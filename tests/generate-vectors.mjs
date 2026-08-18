/**
 * Conformance vector generator — proves the Tollbooth matches the Code402
 * open standard's EIP-191 + JCS (RFC 8785) offline-verification model.
 *
 * Uses the WELL-KNOWN anvil/foundry test key #0 (zero funds, public in every
 * test suite). Never use a real key here.
 *
 *   node tests/generate-vectors.mjs  →  tests/vectors.json
 */
import canonicalize from "canonicalize";
import { privateKeyToAccount } from "viem/accounts";
import { writeFileSync } from "node:fs";

// Well-known deterministic test key (anvil account #0). Public by convention.
const TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const account = privateKeyToAccount(TEST_PRIVATE_KEY);

const sampleChallenge = {
  version: 1,
  chain: "base",
  token: "USDC",
  amount: "0.001",
  address: "0x2CC9237752CFEe65dB46530a958469E7ff12ac6B",
  nonce: "tb_deadbeefdeadbeefdeadbeefdeadbeef",
  resource: "/api/hello",
};

const canonical = canonicalize(sampleChallenge);
const signature = await account.signMessage({ message: canonical });

const vectors = {
  $schema: "code402-conformance/1",
  description:
    "Code402 Tollbooth conformance vectors: JCS canonicalization (RFC 8785) + EIP-191 offline signature. Test key is the public anvil #0 key (zero funds).",
  privateKey_testOnly: TEST_PRIVATE_KEY,
  vectors: [
    {
      name: "basic-402-challenge",
      challenge: sampleChallenge,
      canonicalJcs: canonical,
      signatureEip191: signature,
      expectedRecoveredAddress: account.address,
      notes:
        "Verify: canonicalize(challenge) === canonicalJcs; recoverMessageAddress({message: canonicalJcs, signature}) === expectedRecoveredAddress.",
    },
  ],
};

writeFileSync(new URL("./vectors.json", import.meta.url), JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote tests/vectors.json");
console.log("  canonical:", canonical);
console.log("  signer:   ", account.address);
