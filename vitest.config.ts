import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          PROVIDER_WALLET: "0x2CC9237752CFEe65dB46530a958469E7ff12ac6B",
          CHAIN: "base",
          TOKEN: "USDC",
          AMOUNT: "0.001",
        },
      },
    }),
  ],
});
