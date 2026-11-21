/**
 * Explicit maintenance runner for stored LLM credentials (P1-T02).
 *
 *   pnpm llm:keys:migrate   # legacy plaintext -> versioned envelope (idempotent)
 *   pnpm llm:keys:rotate    # re-encrypt old key versions under the active KEK
 *
 * Prints aggregate counts only — never a key, envelope, or row id. Requires the
 * same env as the app (the root scripts load `.env` via dotenv).
 */

import { prisma } from "@paper-viewer/db";
import { migrateLegacyLlmApiKeys, rotateLlmApiKeys } from "../lib/llm-key-store";

async function main(): Promise<void> {
  const command = process.argv[2] ?? "migrate";
  if (command === "migrate") {
    const summary = await migrateLegacyLlmApiKeys(prisma);
    console.log(`llm key migration: ${JSON.stringify(summary)}`);
    return;
  }
  if (command === "rotate") {
    const summary = await rotateLlmApiKeys(prisma);
    console.log(`llm key rotation: ${JSON.stringify(summary)}`);
    return;
  }
  console.error("Usage: migrate-llm-keys [migrate|rotate]");
  process.exitCode = 1;
}

main()
  .catch((error: unknown) => {
    // Encryption errors are generic by design; do not print objects or stacks
    // that might carry configuration, and never echo the failing key.
    console.error("LLM key maintenance failed:", error instanceof Error ? error.message : "unknown error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
