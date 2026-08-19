/**
 * NonceGuard — global nonce management Durable Object (Code402 Tollbooth).
 *
 * Single-writer semantics: every nonce issue and every nonce spend serializes
 * through one DO instance ("global"), which structurally prevents the
 * double-spending race condition where two concurrent requests both observe
 * the same nonce as unspent.
 */

export class NonceGuard implements DurableObject {
  constructor(
    private readonly state: DurableObjectState,
    private readonly _env: unknown,
  ) {}

  /** Issue a fresh, globally-unique challenge nonce. */
  async issue(): Promise<{ nonce: string }> {
    // 256 bits of entropy from the DO's own RNG — collision probability ~0.
    const bytes = new Uint8Array(32); // 256-bit per x402 nonce convention (verified vs spec)
    crypto.getRandomValues(bytes);
    const nonce = "tb_" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    return { nonce };
  }

  /**
   * Atomically spend a nonce: returns { ok: true } exactly once per nonce.
   * A second call with the same nonce returns { ok: false, reason: "SPENT" }.
   */
  async spend(nonce: string): Promise<{ ok: boolean; reason?: string }> {
    if (typeof nonce !== "string" || nonce.length < 8) {
      return { ok: false, reason: "INVALID_NONCE" };
    }
    const existing = await this.state.storage.get(`nonce:${nonce}`);
    if (existing !== undefined) return { ok: false, reason: "SPENT" };
    // Nonces stay spent forever (double-spend protection outlives any TTL).
    await this.state.storage.put(`nonce:${nonce}`, Date.now());
    return { ok: true };
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === "/spend") {
      const { nonce } = (await req.json<{ nonce?: string }>().catch(() => ({}))) as { nonce?: string };
      return Response.json(await this.spend(String(nonce ?? "")));
    }
    if (req.method === "GET" && url.pathname === "/issue") {
      return Response.json(await this.issue());
    }
    return new Response("not found", { status: 404 });
  }
}
