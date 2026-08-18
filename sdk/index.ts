/**
 * Code402 Tollbooth client SDK — "The Invisible Wallet".
 *
 * Wraps the standard fetch API. Initialize with a Web3 private key (or session
 * key); when any fetch receives a 402 Code402 challenge, the SDK:
 *   1. parses the JSON payload,
 *   2. canonicalizes it with JCS (RFC 8785),
 *   3. signs the exact canonical string with EIP-191 (personal_sign),
 *   4. retries the original request with X-402-Payment attached,
 *   5. returns the final 200 OK data to the caller.
 *
 * The caller never sees a payment happen.
 */
import canonicalize from "canonicalize";
import { privateKeyToAccount } from "viem/accounts";

/** base64url (RFC 4648 §5) — matches the wire format the Tollbooth expects. */
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function strBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export interface Challenge {
  version: 1;
  chain: string;
  token: string;
  amount: string;
  address: string;
  nonce: string;
  resource?: string;
}

export class TollboothClient {
  private account: ReturnType<typeof privateKeyToAccount>;

  constructor(privateKey: `0x${string}`) {
    this.account = privateKeyToAccount(privateKey);
  }

  get address(): string {
    return this.account.address;
  }

  /** Sign the JCS-canonicalized challenge payload via EIP-191. */
  async signChallenge(challenge: Challenge): Promise<string> {
    const canonical = canonicalize(challenge) as string;
    const signature = await this.account.signMessage({ message: canonical }); // EIP-191
    return `${b64url(strBytes(canonical))}.${b64url(strBytes(signature.slice(2)))}`;
  }

  /** Drop-in fetch: transparently pays any Code402 402 challenge. */
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const first = await fetch(input, init);
    if (first.status !== 402) return first;

    const challenge = (await first.json().catch(() => null)) as Challenge | null;
    if (!challenge || challenge.version !== 1) return first;

    const payment = await this.signChallenge(challenge);
    const headers = new Headers(init?.headers);
    headers.set("X-402-Payment", payment);
    return fetch(input, { ...init, headers });
  }

  /** Convenience: fetch + parse JSON, throws on non-200 after payment. */
  async fetchJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
    const res = await this.fetch(input, init);
    if (!res.ok) throw new Error(`tollbooth: ${res.status} ${await res.text()}`);
    return res.json() as Promise<T>;
  }
}

export default TollboothClient;
