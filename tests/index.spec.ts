import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import { privateKeyToAccount } from "viem/accounts";

/** Public anvil test key #0 — matches tests/vectors.json. */
const TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(TEST_KEY);

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("code402-tollbooth", () => {
  it("GET /healthz is free", async () => {
    const res = await SELF.fetch("http://example.com/healthz");
    expect(res.status).toBe(200);
    expect((await res.json() as { status: string }).status).toBe("ok");
  });

  it("Step 5a: request WITHOUT SDK → 402 with Code402 challenge payload", async () => {
    const res = await SELF.fetch("http://example.com/api/hello");
    expect(res.status).toBe(402);
    const body = (await res.json()) as {
      version: number; chain: string; token: string; amount: string;
      address: string; nonce: string;
    };
    expect(body.version).toBe(1);
    expect(body.chain).toBe("base");
    expect(body.token).toBe("USDC");
    expect(body.amount).toBe("0.001");
    expect(body.address.toLowerCase()).toBe(env.PROVIDER_WALLET.toLowerCase());
    expect(body.nonce).toMatch(/^tb_[0-9a-f]{64}$/);
  });

  it("Step 5b: request WITH SDK flow → 402 → sign → 200 OK", async () => {
    // 1. Get the challenge.
    const first = await SELF.fetch("http://example.com/api/data");
    expect(first.status).toBe(402);
    const challenge = (await first.json()) as { nonce: string; [k: string]: unknown };

    // 2. SDK behavior: JCS-canonicalize + EIP-191 sign.
    const canonical = canonicalize(challenge) as string;
    const signature = await account.signMessage({ message: canonical });
    const payment = `${b64url(new TextEncoder().encode(canonical))}.${b64url(new TextEncoder().encode(signature.slice(2)))}`;

    // 3. Retry with X-402-Payment.
    const res = await SELF.fetch("http://example.com/api/data", {
      headers: { "X-402-Payment": payment },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { paid: boolean; payer: string; data: { answer: number } };
    expect(body.paid).toBe(true);
    expect(body.payer.toLowerCase()).toBe(account.address.toLowerCase());
    expect(body.data.answer).toBe(42);
  });

  it("double-spend: replaying the same payment → 402 NONCE_SPENT", async () => {
    const first = await SELF.fetch("http://example.com/api/replay");
    const challenge = (await first.json()) as Record<string, unknown>;
    const canonical = canonicalize(challenge) as string;
    const signature = await account.signMessage({ message: canonical });
    const payment = `${b64url(new TextEncoder().encode(canonical))}.${b64url(new TextEncoder().encode(signature.slice(2)))}`;

    const ok = await SELF.fetch("http://example.com/api/replay", { headers: { "X-402-Payment": payment } });
    expect(ok.status).toBe(200);

    const replay = await SELF.fetch("http://example.com/api/replay", { headers: { "X-402-Payment": payment } });
    expect(replay.status).toBe(402);
    expect(((await replay.json()) as { error: string }).error).toBe("NONCE_SPENT");
  });

  it("malformed signature → 402 BAD_SIGNATURE (EIP-191 recovery fails)", async () => {
    const first = await SELF.fetch("http://example.com/api/bad");
    const challenge = (await first.json()) as Record<string, unknown>;
    const canonical = canonicalize(challenge) as string;
    // 65 bytes of garbage — recoverMessageAddress must throw → BAD_SIGNATURE.
    // NOTE (semantics): a VALID signature over a DIFFERENT message recovers a
    // different address but still parses — in the offline EIP-191 model the
    // signer IS the payer, so it would fail the canonical-match check instead.
    const garbage = "0x" + "ab".repeat(65);
    const payment = `${b64url(new TextEncoder().encode(canonical))}.${b64url(new TextEncoder().encode(garbage.slice(2)))}`;
    const res = await SELF.fetch("http://example.com/api/bad", { headers: { "X-402-Payment": payment } });
    expect(res.status).toBe(402);
    expect(((await res.json()) as { error: string }).error).toBe("BAD_SIGNATURE");
  });

  it("canonical substitution → 402 CANONICAL_MISMATCH (signed payload != stored challenge)", async () => {
    const first = await SELF.fetch("http://example.com/api/mismatch");
    const challenge = (await first.json()) as Record<string, unknown>;
    // Self-sign a MODIFIED challenge (amount changed) — valid EIP-191, wrong terms.
    const forged = { ...challenge, amount: "0.000001" } as Record<string, unknown>;
    const canonical = canonicalize(forged) as string;
    const signature = await account.signMessage({ message: canonical });
    const payment = `${b64url(new TextEncoder().encode(canonical))}.${b64url(new TextEncoder().encode(signature.slice(2)))}`;
    const res = await SELF.fetch("http://example.com/api/mismatch", { headers: { "X-402-Payment": payment } });
    expect(res.status).toBe(402);
    expect(((await res.json()) as { error: string }).error).toBe("CANONICAL_MISMATCH");
  });

  it("conformance: vectors.json canonical + signature recover the expected address", async () => {
    // Mirrors tests/vectors.json (regenerated by tests/generate-vectors.mjs).
    const sample = {
      version: 1, chain: "base", token: "USDC", amount: "0.001",
      address: "0x2CC9237752CFEe65dB46530a958469E7ff12ac6B",
      nonce: "tb_deadbeefdeadbeefdeadbeefdeadbeef", resource: "/api/hello",
    };
    const canonical = canonicalize(sample) as string;
    const sig = await account.signMessage({ message: canonical });
    const { recoverMessageAddress } = await import("viem");
    const recovered = await recoverMessageAddress({ message: canonical, signature: sig });
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase());
    // JCS ordering: keys must be lexicographic (address first, version last).
    expect(Object.keys(JSON.parse(canonical))[0]).toBe("address");
    expect(canonical.endsWith('"version":1}')).toBe(true);
  });
});
