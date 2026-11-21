import { prisma } from "@paper-viewer/db";
import { getEnv } from "@/lib/env";
import { readStoredApiKey } from "@/lib/llm-key-store";

export type LlmRuntimeConfig = { baseUrl: string; model: string; apiKey: string };

/** The DB configuration wins, with env as the fallback; if neither has a key, throw an explicit error. */
export async function resolveLlmConfig(workspaceId: string): Promise<LlmRuntimeConfig> {
  const row = await prisma.llmConfig.findUnique({ where: { workspaceId } });
  if (row) {
    // Decryption happens only here, on the server, in memory. A bad envelope or
    // missing KEK throws (fail closed) instead of leaking a key or silently
    // falling back to another configuration.
    const apiKey = readStoredApiKey({ apiKey: row.apiKey, apiKeyEnvelope: row.apiKeyEnvelope });
    return { baseUrl: row.baseUrl, model: row.model, apiKey };
  }

  const env = getEnv();
  if (!env.LLM_API_KEY) {
    throw new Error("LLM not configured: set it in Settings → LLM or via env");
  }
  return { baseUrl: env.LLM_BASE_URL, model: env.LLM_MODEL, apiKey: env.LLM_API_KEY };
}
