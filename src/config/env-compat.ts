// The product was renamed from governAI to ZenAi4 on 16 October 2026.
// Import this first in every entry point: each ZENAI4_* variable that is not set
// falls back to its old GOVERNAI_* name, so existing .env files keep working.
for (const [key, value] of Object.entries(process.env)) {
  if (!key.startsWith("GOVERNAI_") || value === undefined) continue;
  const renamed = "ZENAI4_" + key.slice("GOVERNAI_".length);
  if (process.env[renamed] === undefined) process.env[renamed] = value;
}
export {};
