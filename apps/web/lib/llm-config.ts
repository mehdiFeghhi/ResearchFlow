import { prisma } from "@paper-viewer/db";
import { getEnv } from "@/lib/env";
import { assertLlmDestination, readStoredApiKey } from "@/lib/llm-key-store";

export type LlmRuntimeConfig = { baseUrl: string; model: string; apiKey: string };

/** The DB configuration wins, with env as the fallback; if neither has a key, throw an explicit error. */
export async function resolveLlmConfig(workspaceId: string): Promise<LlmRuntimeConfig> {
  const row = await prisma.llmConfig.findUnique({ where: { workspaceId } });
  if (row) {
    // A stored key may only be used for the destination it was saved with.
    // A changed baseUrl (or an unbound legacy row) fails closed here, before
    // decryption, so no key can be sent to a destination that was never
    // approved for it.
    assertLlmDestination(row, row.baseUrl);
    // Decryption happens only here, on the server, in memory. A bad envelope or
    // missing KEK throws (fail closed) instead of leaking a key or silently
    // falling back to another configuration.
    const apiKey = readStoredApiKey(row);
    return { baseUrl: row.baseUrl, model: row.model, apiKey };
  }

  const env = getEnv();
  if (!env.LLM_API_KEY) {
    throw new Error("LLM not configured: set it in Settings → LLM or via env");
  }
  return { baseUrl: env.LLM_BASE_URL, model: env.LLM_MODEL, apiKey: env.LLM_API_KEY };
}
