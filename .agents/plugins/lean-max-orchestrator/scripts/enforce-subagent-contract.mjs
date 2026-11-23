#!/usr/bin/env node
/**
 * Lean Main / Max Sub-Agents — PreToolUse Hook for `invoke_subagent`
 *
 * Ensures every delegated code/research/worker sub-agent automatically receives
 * the asymmetric contract when the parent agent omits it:
 *   1. Work at 100% maximum depth inside your own isolated context (no token rationing).
 *   2. Return an ultra-compact structured report (<= 18 lines, zero raw dumps)
 *      so the main agent consumes minimal tokens.
 *
 * Skips specialized subagent types (e.g. `browser`, `image-generator`) and
 * never blocks tool execution on error.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PLUGIN_ROOT = path.resolve(__dirname, "..");

const DEFAULT_CONFIG = {
  maxConcurrentSubagents: 20,
  maxReportLines: 18,
  excludedSubagentTypes: ["browser", "image-generator"],
  contractMarker: "[MAX-DEPTH/LEAN-REPORT]",
  enforceOnInvokeSubagent: true,
};

export function loadConfig(configPath = path.join(PLUGIN_ROOT, "config.json")) {
  try {
    if (fs.existsSync(configPath)) {
      const parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        excludedSubagentTypes: Array.isArray(parsed.excludedSubagentTypes)
          ? parsed.excludedSubagentTypes
          : DEFAULT_CONFIG.excludedSubagentTypes,
      };
    }
  } catch {
    // Fall back silently so hooks never break tool calls.
  }
  return DEFAULT_CONFIG;
}

export function buildContractSuffix(config = DEFAULT_CONFIG) {
  const marker = config.contractMarker || DEFAULT_CONFIG.contractMarker;
  const maxLines = Number(config.maxReportLines) || 18;
  return [
    "",
    `${marker} Directives obligatoires du sous-agent :`,
    "- TRAVAIL INTERNE (100% MAX) : n'économise JAMAIS tes propres tokens ; lis les fichiers complets nécessaires, vérifie dépendances/cas limites et lance builds/tests jusqu'à certitude absolue.",
    `- RAPPORT FINAL ULTRA-COMPACT (<= ${maxLines} lignes) : ne colle ni fichiers complets ni logs bruts. Renvoie strictement : STATUS (DONE|PARTIAL|BLOCKED), FILES (chemin:lignes), SUMMARY (2-4 puces denses), VERIFIED (commande -> PASS/FAIL), BLOCKERS.`,
  ].join("\n");
}

export function evaluatePreToolUse(payload, config = loadConfig()) {
  if (!config.enforceOnInvokeSubagent) {
    return { decision: "allow" };
  }

  const toolCall = payload?.toolCall;
  if (!toolCall || toolCall.name !== "invoke_subagent") {
    return { decision: "allow" };
  }

  const args = toolCall.args;
  if (!args || typeof args !== "object") {
    return { decision: "allow" };
  }

  const typeName = String(args.TypeName || "").trim().toLowerCase();
  const excluded = (config.excludedSubagentTypes || []).map((t) =>
    String(t).trim().toLowerCase()
  );
  if (excluded.includes(typeName)) {
    return { decision: "allow" };
  }

  const prompt = typeof args.Prompt === "string" ? args.Prompt : "";
  if (!prompt.trim()) {
    return { decision: "allow" };
  }

  const marker = config.contractMarker || DEFAULT_CONFIG.contractMarker;
  if (prompt.includes(marker)) {
    return { decision: "allow" };
  }

  return {
    decision: "allow",
    overwrite: {
      Prompt: `${prompt.trimEnd()}\n${buildContractSuffix(config)}`,
    },
  };
}

async function readStdinText() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function main() {
  try {
    const raw = await readStdinText();
    const payload = raw ? JSON.parse(raw) : {};
    const out = evaluatePreToolUse(payload, loadConfig());
    process.stdout.write(`${JSON.stringify(out)}\n`);
  } catch {
    process.stdout.write('{"decision":"allow"}\n');
  }
}

const isDirectRun =
  process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isDirectRun) {
  main();
}
