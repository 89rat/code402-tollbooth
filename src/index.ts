/**
 * Code402 Tollbooth — 402 interceptor worker.
 *
 * Implements the Code402 standard (https://code402.dev/) with the
 * vendor-neutral EIP-191 offline verification model from the x402-foundation
 * GitHub threads:
 *   - 402 challenges carry a JCS (RFC 8785) canonicalized JSON payload
 *   - the buyer signs that exact canonical string with EIP-191 (personal_sign)
 *   - the edge verifies the signature locally with viem — zero origin
 *     roundtrips, no external verification APIs, target < 10ms
 *   - a Durable Object spends each nonce exactly once (double-spend proof)
 *
 * Payment state (challenge → pending payment) is parked in KV with a 60s TTL.
 */
import canonicalize from "canonicalize";
import { recoverMessageAddress } from "viem";
import { NonceGuard } from "./nonce";

export { NonceGuard };

export interface Env {
  PAYMENT_STATE: KVNamespace;
  NONCE_GUARD: DurableObjectNamespace;
  PROVIDER_WALLET: string;
  CHAIN: string;
  TOKEN: string;
  AMOUNT: string;
}

/** The Code402 402-challenge payload shape (JCS-canonicalized before hashing/signing). */
interface Challenge {
  version: 1;
  chain: string;
  token: string;
  amount: string;
  address: string;
  nonce: string;
  /** Resource the payment unlocks (anti-replay binding to this request). */
  resource: string;
}

const TTL_SECONDS = 60;

/** EIP-191 personal_sign prefix handling is done by viem's recoverMessageAddress. */
async function verifyEIP191(
  canonical: string,
  signature: `0x${string}`,
): Promise<`0x${string}` | null> {
  try {
    return await recoverMessageAddress({ message: canonical, signature });
  } catch {
    return null;
  }
}

async function issueChallenge(env: Env, resource: string): Promise<Response> {
  // 1. Generate a unique nonce via the Durable Object (single writer).
  const stub = env.NONCE_GUARD.get(env.NONCE_GUARD.idFromName("global"));
  const { nonce } = (await (await stub.fetch("http://nonce/issue")).json()) as { nonce: string };

  // 2. Build the Code402 challenge payload.
  const challenge: Challenge = {
    version: 1,
    chain: env.CHAIN,
    token: env.TOKEN,
    amount: env.AMOUNT,
    address: env.PROVIDER_WALLET,
    nonce,
    resource,
  };
  const canonical = canonicalize(challenge) as string;

  // 3. Park pending-payment state in KV, TTL 60s (challenge expiry).
  await env.PAYMENT_STATE.put(`chal:${nonce}`, JSON.stringify({ canonical, resource }), {
    expirationTtl: TTL_SECONDS,
  });

  // 4. 402 Payment Required with the Code402 JSON payload.
  return new Response(JSON.stringify(challenge), {
    status: 402,
    headers: { "content-type": "application/json", "x-payment-canonical": canonical },
  });
}

async function verifyPayment(env: Env, req: Request, resource: string): Promise<Response> {
  const header = req.headers.get("X-402-Payment");
  if (!header) return issueChallenge(env, resource);

  // X-402-Payment: base64url(canonical JSON) . base64url(EIP-191 signature)
  const [canonB64, sigB64] = header.split(".");
  if (!canonB64 || !sigB64) return issueChallenge(env, resource);

  let canonical: string;
  let signature: `0x${string}`;
  try {
    canonical = atob(canonB64.replace(/-/g, "+").replace(/_/g, "/"));
    signature = `0x${atob(sigB64.replace(/-/g, "+").replace(/_/g, "/"))}`;
    if (!signature.startsWith("0x") || signature.length < 130) throw new Error("bad sig");
  } catch {
    return new Response(JSON.stringify({ error: "MALFORMED_PAYMENT" }), {
      status: 402,
      headers: { "content-type": "application/json" },
    });
  }

  // Offline EIP-191 verification — local viem, no external calls.
  const payer = await verifyEIP191(canonical, signature);
  if (!payer) {
    return new Response(JSON.stringify({ error: "BAD_SIGNATURE" }), {
      status: 402,
      headers: { "content-type": "application/json" },
    });
  }

  // The canonical payload must match a live (unexpired) challenge for this resource.
  let parsed: Challenge;
  try {
    parsed = JSON.parse(canonical) as Challenge;
  } catch {
    return issueChallenge(env, resource);
  }
  const stored = await env.PAYMENT_STATE.get(`chal:${parsed.nonce}`, "json") as
    | { canonical: string; resource: string }
    | null;
  if (!stored) {
    return new Response(JSON.stringify({ error: "CHALLENGE_EXPIRED_OR_UNKNOWN" }), {
      status: 402,
      headers: { "content-type": "application/json" },
    });
  }
  if (stored.canonical !== canonical || stored.resource !== resource) {
    return new Response(JSON.stringify({ error: "CANONICAL_MISMATCH" }), {
      status: 402,
      headers: { "content-type": "application/json" },
    });
  }

  // Atomically spend the nonce — exactly one 200 per challenge.
  const stub = env.NONCE_GUARD.get(env.NONCE_GUARD.idFromName("global"));
  const spendRes = await stub.fetch("http://nonce/spend", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: parsed.nonce }),
  });
  const spent = (await spendRes.json()) as { ok: boolean; reason?: string };
  if (!spent.ok) {
    return new Response(JSON.stringify({ error: "NONCE_" + (spent.reason ?? "REJECTED") }), {
      status: 402,
      headers: { "content-type": "application/json" },
    });
  }
  // NOTE: pending state is NOT deleted here — the 60s TTL cleans it up, and
  // the Durable Object nonce spend is THE single double-spend gate. A replay
  // must fail with NONCE_SPENT (not an expired-challenge error) so buyers get
  // a precise, machine-actionable reason.

  // Forward to origin API (demo origin inlined; swap for originUrl fetch in prod).
  return new Response(
    JSON.stringify({
      data: { resource, answer: 42 },
      paid: true,
      payer,
      amount: parsed.amount,
      token: parsed.token,
      chain: parsed.chain,
      nonce: parsed.nonce,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/healthz") {
      return Response.json({ status: "ok", service: "code402-tollbooth" });
    }
    // Tollbooth gate: everything under /api/* requires Code402 payment.
    if (url.pathname.startsWith("/api/")) {
      return verifyPayment(env, req, url.pathname);
    }
    return new Response("not found", { status: 404 });
  },
};
