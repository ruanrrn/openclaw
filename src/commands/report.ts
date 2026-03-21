import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { resolveOpenClawAgentDir } from "../agents/agent-paths.js";
import { ensureAuthProfileStore } from "../agents/auth-profiles.js";
import { buildModelAliasIndex, resolveModelRefFromString } from "../agents/model-selection.js";
import { resolveCommandSecretRefsViaGateway } from "../cli/command-secret-gateway.js";
import { getStatusCommandSecretTargetIds } from "../cli/command-secret-targets.js";
import { promptYesNo } from "../cli/prompt.js";
import { readBestEffortConfig } from "../config/config.js";
import { resolveAgentModelPrimaryValue } from "../config/model-input.js";
import type { OpenClawConfig } from "../config/types.js";
import { buildGatewayConnectionDetails } from "../gateway/call.js";
import { callGateway } from "../gateway/call.js";
import { resolveGatewayProbeAuthSafe } from "../gateway/probe-auth.js";
import { probeGateway } from "../gateway/probe.js";
import { buildChannelSummary } from "../infra/channel-summary.js";
import { collectChannelStatusIssues } from "../infra/channels-status-issues.js";
import {
  PROXY_ENV_KEYS,
  hasEnvHttpProxyConfigured,
  resolveEnvHttpProxyUrl,
} from "../infra/net/proxy-env.js";
import { resolveOsSummary } from "../infra/os-summary.js";
import { runExec } from "../process/exec.js";
import type { RuntimeEnv } from "../runtime.js";
import { VERSION } from "../version.js";
import { resolveProviderAuthOverview } from "./models/list.auth-overview.js";
import { runAuthProbes } from "./models/list.probe.js";
import { DEFAULT_PROVIDER } from "./models/shared.js";
import { buildChannelsTable } from "./status-all/channels.js";
import { redactSecrets } from "./status-all/format.js";
import { getStatusSummary } from "./status.js";

export type ReportKind = "bug" | "feature" | "security";
export type ReportOutputFormat = "human" | "json" | "markdown";
export type BugProbeMode = "general" | "model" | "channel" | "gateway" | "none";

type SharedReportOptions = {
  title?: string;
  summary?: string;
  json?: boolean;
  markdown?: boolean;
  output?: string;
  submit?: boolean;
  yes?: boolean;
  nonInteractive?: boolean;
};

export type BugReportOptions = SharedReportOptions & {
  repro?: string;
  expected?: string;
  actual?: string;
  impact?: string;
  previousVersion?: string;
  evidence?: string;
  additionalInformation?: string;
  context?: string;
  probe?: BugProbeMode;
};

export type FeatureReportOptions = SharedReportOptions & {
  problem?: string;
  solution?: string;
  impact?: string;
  alternatives?: string;
  evidence?: string;
  additionalInformation?: string;
  context?: string;
  probe?: BugProbeMode;
};

export type SecurityReportOptions = SharedReportOptions & {
  severity?: string;
  impact?: string;
  component?: string;
  reproduction?: string;
  demonstratedImpact?: string;
  environment?: string;
  remediation?: string;
};

export type ReportOptionsByKind = {
  bug: BugReportOptions;
  feature: FeatureReportOptions;
  security: SecurityReportOptions;
};

type ReportContext = {
  config: OpenClawConfig;
  secretDiagnostics: string[];
  version: string;
  os: string;
  modelRef: string | null;
  providerPath: string | null;
  degradedReasons: string[];
};

export type ReportEvidenceDetail = {
  source:
    | "gateway"
    | "model"
    | "channel"
    | "environment"
    | "secretDiagnostics"
    | "proxy"
    | "recentErrors"
    | "runtime";
  classification?: "fact" | "inference" | "diagnostic_failure";
  label: string;
  value: string;
  sensitive: boolean;
  includedInPublicBody: boolean;
};

export type ReportSubmissionResult = {
  created: boolean;
  url?: string;
  dryRun: boolean;
  blockedReason?: string;
};

export type ReportPayload = {
  kind: ReportKind;
  title: string;
  body: string;
  labels: string[];
  evidence: string[];
  evidenceDetails: ReportEvidenceDetail[];
  redactionsApplied: string[];
  missingFields: string[];
  submissionEligible: boolean;
  submission: ReportSubmissionResult;
};

const PUBLIC_REPO = "openclaw/openclaw";
const REPORT_GENERATED_NOTE = "_Generated via `openclaw report`._";

function normalizeEscapedMultilineText(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\r\n/g, "\n");
}

function sanitizeWhitespace(value: string | undefined): string | undefined {
  const trimmed = normalizeEscapedMultilineText(value)?.trim();
  return trimmed ? trimmed : undefined;
}

function clampTitle(value: string): string {
  const trimmed = value.trim();
  return trimmed.length <= 140 ? trimmed : `${trimmed.slice(0, 137).trimEnd()}...`;
}

function detectRedactions(text: string): string[] {
  const rules: Array<{ label: string; re: RegExp }> = [
    { label: "token", re: /\b(?:Bearer\s+\S+|sk-[A-Za-z0-9]{10,})\b/i },
    { label: "email", re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
    { label: "phone", re: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b/ },
    { label: "user-handle", re: /(^|\s)@[A-Za-z0-9_][A-Za-z0-9_.-]{1,}/ },
    { label: "user-path", re: /\/Users\/[^/\s]+|\/home\/[^/\s]+/ },
  ];
  return rules.filter((entry) => entry.re.test(text)).map((entry) => entry.label);
}

export function sanitizeReportText(value: string | undefined): {
  text: string;
  redactionsApplied: string[];
} {
  if (!value) {
    return { text: "", redactionsApplied: [] };
  }
  const normalized = normalizeEscapedMultilineText(value) ?? "";
  const redactions = detectRedactions(normalized);
  let text = redactSecrets(normalized);
  text = text.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[email-redacted]");
  text = text.replace(/\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b/g, "[phone-redacted]");
  text = text.replace(/\/Users\/[^/\s]+/g, "/Users/user");
  text = text.replace(/\/home\/[^/\s]+/g, "/home/user");
  text = text.replace(/(^|\s)@[A-Za-z0-9_][A-Za-z0-9_.-]{1,}/g, "$1[user-redacted]");
  return { text, redactionsApplied: redactions };
}

function sanitizeMany(values: Array<string | undefined>): {
  values: string[];
  redactionsApplied: string[];
} {
  const redactions = new Set<string>();
  const sanitized = values
    .map((entry) => {
      const result = sanitizeReportText(entry);
      for (const label of result.redactionsApplied) {
        redactions.add(label);
      }
      return result.text.trim();
    })
    .filter((entry) => entry.length > 0);
  return { values: sanitized, redactionsApplied: [...redactions] };
}

function renderSection(title: string, value?: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    return "";
  }
  return `## ${title}\n\n${trimmed}`;
}

function appendGeneratedNote(sections: string[]): string {
  const body = sections.filter(Boolean).join("\n\n");
  return body ? `${body}\n\n${REPORT_GENERATED_NOTE}` : REPORT_GENERATED_NOTE;
}

function normalizeAdditionalInformation(value?: string, context?: string): string | undefined {
  const parts = [sanitizeWhitespace(value), sanitizeWhitespace(context)].filter(
    (entry): entry is string => Boolean(entry),
  );
  if (parts.length === 0) {
    return undefined;
  }
  return parts.join("\n\n");
}

function collectMissingFields(kind: ReportKind, opts: ReportOptionsByKind[ReportKind]): string[] {
  const summary = sanitizeWhitespace(opts.summary);
  switch (kind) {
    case "bug":
      return [
        !summary ? "Summary" : null,
        !sanitizeWhitespace((opts as BugReportOptions).repro) ? "Steps to reproduce" : null,
        !sanitizeWhitespace((opts as BugReportOptions).expected) ? "Expected behavior" : null,
        !sanitizeWhitespace((opts as BugReportOptions).actual) ? "Actual behavior" : null,
        !sanitizeWhitespace((opts as BugReportOptions).impact) ? "Impact" : null,
      ].filter((entry): entry is string => Boolean(entry));
    case "feature":
      return [
        !summary ? "Summary" : null,
        !sanitizeWhitespace((opts as FeatureReportOptions).problem) ? "Problem to solve" : null,
        !sanitizeWhitespace((opts as FeatureReportOptions).solution) ? "Proposed solution" : null,
        !sanitizeWhitespace((opts as FeatureReportOptions).impact) ? "Impact" : null,
      ].filter((entry): entry is string => Boolean(entry));
    case "security":
      return [
        !sanitizeWhitespace(opts.title) ? "Title" : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).severity)
          ? "Severity assessment"
          : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).impact) ? "Impact" : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).component)
          ? "Affected component"
          : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).reproduction)
          ? "Technical reproduction"
          : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).demonstratedImpact)
          ? "Demonstrated impact"
          : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).environment) ? "Environment" : null,
        !sanitizeWhitespace((opts as SecurityReportOptions).remediation)
          ? "Remediation advice"
          : null,
      ].filter((entry): entry is string => Boolean(entry));
  }
}

function resolveLabels(kind: ReportKind): string[] {
  if (kind === "bug") {
    return ["bug"];
  }
  if (kind === "feature") {
    return ["enhancement"];
  }
  return [];
}

function resolveTitle(kind: ReportKind, opts: ReportOptionsByKind[ReportKind]): string {
  const raw =
    sanitizeWhitespace(opts.title) ?? sanitizeWhitespace(opts.summary) ?? `${kind} report`;
  const prefix = kind === "bug" ? "[Bug]: " : kind === "feature" ? "[Feature]: " : "";
  return clampTitle(sanitizeReportText(`${prefix}${raw}`).text);
}

function resolveModelContext(cfg: OpenClawConfig): {
  modelRef: string | null;
  providerPath: string | null;
} {
  const primary = resolveAgentModelPrimaryValue(cfg.agents?.defaults?.model);
  if (primary?.includes("/")) {
    return { modelRef: primary, providerPath: primary };
  }
  if (primary) {
    const providerIds = Object.keys(cfg.models?.providers ?? {});
    const provider = providerIds[0] ?? null;
    return {
      modelRef: provider ? `${provider}/${primary}` : primary,
      providerPath: provider ? `openclaw -> ${provider}` : null,
    };
  }
  const providerIds = Object.keys(cfg.models?.providers ?? {});
  const provider = providerIds[0];
  const providerModels = provider ? (cfg.models?.providers?.[provider]?.models ?? []) : [];
  const firstModel = providerModels[0]?.id;
  if (provider && firstModel) {
    return {
      modelRef: `${provider}/${firstModel}`,
      providerPath: `openclaw -> ${provider}`,
    };
  }
  return { modelRef: null, providerPath: null };
}

async function collectReportContext(commandName: string): Promise<ReportContext> {
  const degradedReasons: string[] = [];
  let sourceConfig = {} as OpenClawConfig;
  try {
    sourceConfig = await readBestEffortConfig();
  } catch (error) {
    degradedReasons.push(`config load degraded: ${String(error)}`);
  }
  let resolvedConfig = sourceConfig;
  let diagnostics: string[] = [];
  try {
    const resolved = await resolveCommandSecretRefsViaGateway({
      config: sourceConfig,
      commandName,
      targetIds: getStatusCommandSecretTargetIds(),
      mode: "read_only_status",
    });
    resolvedConfig = resolved.resolvedConfig;
    diagnostics = resolved.diagnostics;
  } catch (error) {
    degradedReasons.push(`secret resolution degraded: ${String(error)}`);
  }
  const model = resolveModelContext(resolvedConfig ?? ({} as OpenClawConfig));
  return {
    config: resolvedConfig,
    secretDiagnostics: diagnostics,
    version: VERSION,
    os: resolveOsSummary().label,
    modelRef: model.modelRef,
    providerPath: model.providerPath,
    degradedReasons,
  };
}

function addEvidence(
  bucket: ReportEvidenceDetail[],
  detail: Omit<ReportEvidenceDetail, "value"> & { value?: string | null },
) {
  const value = detail.value?.trim();
  if (!value) {
    return;
  }
  const sanitized = sanitizeReportText(value);
  bucket.push({
    ...detail,
    value: sanitized.text,
  });
}

function collectSecretDiagnosticEvidence(ctx: ReportContext): ReportEvidenceDetail[] {
  const details: ReportEvidenceDetail[] = [];
  for (const entry of ctx.secretDiagnostics.slice(0, 3)) {
    addEvidence(details, {
      source: "secretDiagnostics",
      label: "Secret diagnostics",
      value: entry,
      sensitive: true,
      classification: "diagnostic_failure",
      includedInPublicBody: false,
    });
  }
  for (const entry of ctx.degradedReasons.slice(0, 3)) {
    addEvidence(details, {
      source: "secretDiagnostics",
      label: "Degraded diagnostics",
      value: entry,
      sensitive: false,
      classification: "diagnostic_failure",
      includedInPublicBody: false,
    });
  }
  return details;
}

function resolveProxyPreviewValue(value: string): string {
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return value.length > 80 ? `${value.slice(0, 77)}...` : value;
  }
}

function collectProxyEvidence(): ReportEvidenceDetail[] {
  const details: ReportEvidenceDetail[] = [];
  const configuredKeys = PROXY_ENV_KEYS.filter((key) => {
    const value = process.env[key];
    return typeof value === "string" && value.trim().length > 0;
  });
  addEvidence(details, {
    source: "proxy",
    label: "Proxy env",
    value:
      configuredKeys.length > 0
        ? configuredKeys.join(", ")
        : "no HTTP(S) proxy env vars configured",
    sensitive: false,
    classification: "fact",
    includedInPublicBody: configuredKeys.length > 0,
  });
  const effectiveHttpsProxy = resolveEnvHttpProxyUrl("https");
  addEvidence(details, {
    source: "proxy",
    label: "Effective HTTPS proxy",
    value: effectiveHttpsProxy ? resolveProxyPreviewValue(effectiveHttpsProxy) : "none",
    sensitive: false,
    classification: "inference",
    includedInPublicBody: Boolean(effectiveHttpsProxy),
  });
  const noProxy = process.env.no_proxy?.trim() || process.env.NO_PROXY?.trim();
  if (noProxy) {
    const entries = noProxy
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .slice(0, 3);
    addEvidence(details, {
      source: "proxy",
      label: "NO_PROXY",
      value: entries.join(", "),
      sensitive: false,
      classification: "fact",
      includedInPublicBody: false,
    });
  }
  addEvidence(details, {
    source: "proxy",
    label: "Undici env proxy path",
    value: hasEnvHttpProxyConfigured("https")
      ? "HTTPS requests should use EnvHttpProxyAgent"
      : "EnvHttpProxyAgent not configured for HTTPS",
    sensitive: false,
    classification: "inference",
    includedInPublicBody: false,
  });
  return details;
}

function collectRecentErrorEvidenceFromLines(
  source: ReportEvidenceDetail["source"],
  label: string,
  lines: string[],
  includedInPublicBody = true,
): ReportEvidenceDetail[] {
  const details: ReportEvidenceDetail[] = [];
  const errorLine = lines.find((line) => /error|failed|timeout|unreachable/i.test(line));
  if (!errorLine) {
    return details;
  }
  addEvidence(details, {
    source,
    label,
    value: errorLine,
    sensitive: false,
    classification: "diagnostic_failure",
    includedInPublicBody,
  });
  return details;
}

async function collectEnvironmentEvidence(
  ctx: ReportContext,
  kind: ReportKind,
): Promise<ReportEvidenceDetail[]> {
  const details: ReportEvidenceDetail[] = [];
  addEvidence(details, {
    source: "environment",
    label: "Runtime",
    value: `OpenClaw ${ctx.version} on ${ctx.os}`,
    sensitive: false,
    classification: "fact",
    includedInPublicBody: kind !== "security",
  });
  try {
    const summary = await getStatusSummary({
      includeSensitive: false,
      config: ctx.config,
      sourceConfig: ctx.config,
    });
    addEvidence(details, {
      source: "environment",
      label: "Default session model",
      value:
        summary.sessions.defaults.model && summary.sessions.defaults.contextTokens != null
          ? `${summary.sessions.defaults.model} · context ${summary.sessions.defaults.contextTokens}`
          : (summary.sessions.defaults.model ?? ctx.modelRef ?? "unknown"),
      sensitive: false,
      classification: "inference",
      includedInPublicBody: false,
    });
    addEvidence(details, {
      source: "environment",
      label: "Configured channels overview",
      value:
        summary.channelSummary.length > 0
          ? summary.channelSummary.slice(0, 2).join(" | ")
          : "no channel summary available",
      sensitive: false,
      classification: "inference",
      includedInPublicBody: false,
    });
    details.push(
      ...collectRecentErrorEvidenceFromLines(
        "recentErrors",
        "Recent runtime signal",
        summary.channelSummary,
      ),
    );
  } catch (error) {
    addEvidence(details, {
      source: "environment",
      label: "Environment summary",
      value: `status summary unavailable (${String(error)})`,
      sensitive: false,
      classification: "diagnostic_failure",
      includedInPublicBody: true,
    });
  }
  return details;
}

async function collectGatewayEvidence(ctx: ReportContext): Promise<ReportEvidenceDetail[]> {
  const details: ReportEvidenceDetail[] = [];
  try {
    const connection = buildGatewayConnectionDetails({ config: ctx.config });
    const authResolution = resolveGatewayProbeAuthSafe({
      cfg: ctx.config,
      mode: ctx.config.gateway?.mode === "remote" ? "remote" : "local",
    });
    const auth = authResolution.auth;
    addEvidence(details, {
      source: "gateway",
      label: "Gateway target",
      value: connection.message,
      sensitive: false,
      classification: "fact",
      includedInPublicBody: true,
    });
    addEvidence(details, {
      source: "gateway",
      label: "Gateway auth mode",
      value: auth.token
        ? auth.password
          ? "token+password"
          : "token"
        : auth.password
          ? "password"
          : "none",
      sensitive: false,
      classification: "inference",
      includedInPublicBody: false,
    });
    if (authResolution.warning) {
      addEvidence(details, {
        source: "secretDiagnostics",
        label: "Gateway auth warning",
        value: authResolution.warning,
        sensitive: false,
        classification: "diagnostic_failure",
        includedInPublicBody: false,
      });
    }
    try {
      const probe = await probeGateway({
        url: connection.url,
        auth,
        timeoutMs: 5000,
      });
      addEvidence(details, {
        source: "gateway",
        label: "Gateway probe",
        value: probe.ok
          ? `reachable (${Math.round(probe.connectLatencyMs ?? 0)}ms)`
          : `unreachable (${probe.error ?? "unknown error"})`,
        sensitive: false,
        classification: probe.ok ? "fact" : "diagnostic_failure",
        includedInPublicBody: true,
      });
      if (probe.ok) {
        try {
          const health = await callGateway({
            config: ctx.config,
            method: "health",
            timeoutMs: 5000,
          });
          addEvidence(details, {
            source: "gateway",
            label: "Gateway health",
            value:
              typeof health.ok === "boolean"
                ? health.ok
                  ? "ok"
                  : "not ok"
                : `keys: ${Object.keys(health).slice(0, 4).join(", ") || "none"}`,
            sensitive: false,
            classification: "fact",
            includedInPublicBody: true,
          });
        } catch (error) {
          addEvidence(details, {
            source: "gateway",
            label: "Gateway health",
            value: `health call unavailable (${String(error)})`,
            sensitive: false,
            classification: "diagnostic_failure",
            includedInPublicBody: true,
          });
        }
      }
    } catch (error) {
      addEvidence(details, {
        source: "gateway",
        label: "Gateway probe",
        value: `probe failed (${String(error)})`,
        sensitive: false,
        classification: "diagnostic_failure",
        includedInPublicBody: true,
      });
    }
  } catch (error) {
    addEvidence(details, {
      source: "gateway",
      label: "Gateway diagnostics",
      value: `gateway inspection unavailable (${String(error)})`,
      sensitive: false,
      classification: "diagnostic_failure",
      includedInPublicBody: true,
    });
  }
  details.push(...collectProxyEvidence());
  return details;
}

function buildModelCandidates(ctx: ReportContext): string[] {
  const aliasIndex = buildModelAliasIndex({
    cfg: ctx.config,
    defaultProvider: DEFAULT_PROVIDER,
  });
  const configured = [
    ctx.modelRef,
    resolveAgentModelPrimaryValue(ctx.config.agents?.defaults?.model),
  ].filter((value): value is string => Boolean(value));
  return configured
    .map(
      (raw) =>
        resolveModelRefFromString({
          raw,
          defaultProvider: DEFAULT_PROVIDER,
          aliasIndex,
        })?.ref,
    )
    .filter((ref): ref is NonNullable<typeof ref> => Boolean(ref))
    .map((ref) => `${ref.provider}/${ref.model}`);
}

async function collectModelEvidence(ctx: ReportContext): Promise<ReportEvidenceDetail[]> {
  const details: ReportEvidenceDetail[] = [];
  const providerId = ctx.modelRef?.split("/")[0]?.trim() || null;
  const effectiveHttpsProxy = resolveEnvHttpProxyUrl("https");
  addEvidence(details, {
    source: "model",
    label: "Model path",
    value: ctx.modelRef ?? "unknown",
    sensitive: false,
    classification: "fact",
    includedInPublicBody: true,
  });
  addEvidence(details, {
    source: "model",
    label: "Provider path",
    value: ctx.providerPath ?? "unknown",
    sensitive: false,
    classification: "inference",
    includedInPublicBody: true,
  });
  if (!providerId) {
    return details;
  }
  try {
    const agentDir = resolveOpenClawAgentDir();
    const store = ensureAuthProfileStore(agentDir);
    const overview = resolveProviderAuthOverview({
      provider: providerId,
      cfg: ctx.config,
      store,
      modelsPath: path.join(agentDir, "models.json"),
    });
    addEvidence(details, {
      source: "model",
      label: "Provider auth",
      value: `${overview.effective.kind}: ${overview.effective.detail}`,
      sensitive: false,
      classification: "inference",
      includedInPublicBody: true,
    });
    addEvidence(details, {
      source: "model",
      label: "Provider profiles",
      value: `${overview.profiles.count} configured profile(s)`,
      sensitive: false,
      classification: "fact",
      includedInPublicBody: false,
    });
    const configuredCount = Array.isArray(ctx.config.models?.providers?.[providerId]?.models)
      ? (ctx.config.models?.providers?.[providerId]?.models?.length ?? 0)
      : 0;
    addEvidence(details, {
      source: "model",
      label: "Configured provider models",
      value: `${configuredCount}`,
      sensitive: false,
      classification: "fact",
      includedInPublicBody: false,
    });
    const probeSummary = await runAuthProbes({
      cfg: ctx.config,
      providers: [providerId],
      modelCandidates: buildModelCandidates(ctx),
      options: {
        provider: providerId,
        timeoutMs: 5000,
        concurrency: 1,
        maxTokens: 8,
      },
    });
    const firstResult = probeSummary.results[0];
    const proxySummary = effectiveHttpsProxy
      ? `via env proxy ${resolveProxyPreviewValue(effectiveHttpsProxy)}`
      : "with no env proxy configured";
    addEvidence(details, {
      source: "model",
      label: "Model probe",
      value: firstResult
        ? `${firstResult.status} ${proxySummary}${firstResult.latencyMs != null ? ` (${firstResult.latencyMs}ms)` : ""}`
        : "no probe targets",
      sensitive: false,
      classification: firstResult && firstResult.status === "ok" ? "fact" : "diagnostic_failure",
      includedInPublicBody: true,
    });
    if (firstResult?.error) {
      addEvidence(details, {
        source: "recentErrors",
        label: "Recent model-call error",
        value: firstResult.error,
        sensitive: false,
        classification: "diagnostic_failure",
        includedInPublicBody: true,
      });
    }
  } catch (error) {
    addEvidence(details, {
      source: "model",
      label: "Provider auth",
      value: `provider auth overview unavailable (${String(error)})`,
      sensitive: false,
      classification: "diagnostic_failure",
      includedInPublicBody: true,
    });
  }
  return details;
}

async function collectChannelEvidence(ctx: ReportContext): Promise<ReportEvidenceDetail[]> {
  const details: ReportEvidenceDetail[] = [];
  try {
    const table = await buildChannelsTable(ctx.config, {
      showSecrets: false,
      sourceConfig: ctx.config,
    });
    const enabledRows = table.rows.filter((row) => row.enabled);
    addEvidence(details, {
      source: "channel",
      label: "Configured channels",
      value:
        enabledRows.length > 0
          ? enabledRows
              .slice(0, 3)
              .map((row) => `${row.label}:${row.state}`)
              .join(", ")
          : "none detected",
      sensitive: false,
      classification: "fact",
      includedInPublicBody: true,
    });
    const warnRow = enabledRows.find((row) => row.state === "warn" || row.state === "setup");
    if (warnRow) {
      addEvidence(details, {
        source: "channel",
        label: "Top channel issue",
        value: `${warnRow.label}: ${warnRow.detail}`,
        sensitive: false,
        classification: "diagnostic_failure",
        includedInPublicBody: true,
      });
    }
    const summaryLines = await buildChannelSummary(ctx.config, {
      colorize: false,
      includeAllowFrom: false,
      sourceConfig: ctx.config,
    });
    addEvidence(details, {
      source: "channel",
      label: "Channel summary",
      value: summaryLines.slice(0, 2).join(" | "),
      sensitive: false,
      classification: "inference",
      includedInPublicBody: false,
    });
    details.push(
      ...collectRecentErrorEvidenceFromLines("recentErrors", "Recent channel error", summaryLines),
    );
    try {
      const payload = await callGateway({
        config: ctx.config,
        method: "channels.status",
        params: { probe: false, timeoutMs: 5000 },
        timeoutMs: 5000,
      });
      const issues = collectChannelStatusIssues(payload);
      if (issues.length > 0) {
        addEvidence(details, {
          source: "channel",
          label: "Gateway-reported channel issue",
          value: issues[0]?.message ?? "channel issue detected",
          sensitive: false,
          classification: "diagnostic_failure",
          includedInPublicBody: true,
        });
      }
      const accountsByChannel = payload.channelAccounts as Record<string, unknown> | undefined;
      if (accountsByChannel) {
        const recentError = Object.values(accountsByChannel)
          .flatMap((value) => (Array.isArray(value) ? value : []))
          .find(
            (account) =>
              typeof (account as { lastError?: unknown }).lastError === "string" &&
              Boolean((account as { lastError?: string }).lastError?.trim()),
          ) as { lastError?: string } | undefined;
        if (recentError?.lastError) {
          addEvidence(details, {
            source: "recentErrors",
            label: "Recent channel runtime error",
            value: recentError.lastError,
            sensitive: false,
            classification: "diagnostic_failure",
            includedInPublicBody: true,
          });
        }
      }
    } catch (error) {
      addEvidence(details, {
        source: "channel",
        label: "Channel status",
        value: `gateway channel status unavailable (${String(error)})`,
        sensitive: false,
        classification: "diagnostic_failure",
        includedInPublicBody: true,
      });
    }
  } catch (error) {
    addEvidence(details, {
      source: "channel",
      label: "Channel diagnostics",
      value: `channel diagnostics unavailable (${String(error)})`,
      sensitive: false,
      classification: "diagnostic_failure",
      includedInPublicBody: true,
    });
  }
  return details;
}

async function collectEvidenceDetails(
  kind: ReportKind,
  mode: BugProbeMode,
  ctx: ReportContext,
  opts: ReportOptionsByKind[ReportKind],
): Promise<{ details: ReportEvidenceDetail[]; redactionsApplied: string[] }> {
  const details: ReportEvidenceDetail[] = [];
  const manualEvidence = sanitizeMany(["evidence" in opts ? opts.evidence : undefined]);
  for (const entry of manualEvidence.values) {
    addEvidence(details, {
      source: "environment",
      label: "Manual evidence",
      value: entry,
      sensitive: false,
      includedInPublicBody: true,
    });
  }
  details.push(...collectSecretDiagnosticEvidence(ctx));
  if (kind === "security" || mode === "none") {
    return {
      details,
      redactionsApplied: [...new Set(manualEvidence.redactionsApplied)],
    };
  }
  if (mode === "general") {
    details.push(...(await collectEnvironmentEvidence(ctx, kind)));
    details.push(...(await collectGatewayEvidence(ctx)));
    details.push(...(await collectModelEvidence(ctx)));
    details.push(...(await collectChannelEvidence(ctx)));
  } else if (mode === "gateway") {
    details.push(...(await collectGatewayEvidence(ctx)));
  } else if (mode === "model") {
    details.push(...(await collectModelEvidence(ctx)));
  } else if (mode === "channel") {
    details.push(...(await collectChannelEvidence(ctx)));
  }
  const redactions = new Set<string>(manualEvidence.redactionsApplied);
  for (const detail of details) {
    for (const label of detectRedactions(detail.value)) {
      redactions.add(label);
    }
  }
  return { details, redactionsApplied: [...redactions] };
}

function renderEvidenceLines(details: ReportEvidenceDetail[]): string[] {
  return details
    .filter((detail) => detail.includedInPublicBody)
    .toSorted((a, b) => {
      const score = (detail: ReportEvidenceDetail) => {
        if (detail.source === "recentErrors") {
          return 0;
        }
        if (detail.classification === "diagnostic_failure") {
          return 1;
        }
        if (detail.source === "proxy") {
          return 2;
        }
        if (
          detail.source === "gateway" ||
          detail.source === "model" ||
          detail.source === "channel"
        ) {
          return 3;
        }
        return 4;
      };
      return score(a) - score(b);
    })
    .slice(0, 5)
    .map((detail) => `- ${detail.label}: ${detail.value}`);
}

function buildEnvironmentSection(ctx: ReportContext, extra?: string): string {
  const lines = [
    `- OpenClaw version: ${ctx.version}`,
    `- Operating system: ${ctx.os}`,
    ctx.modelRef ? `- Model: ${ctx.modelRef}` : null,
    ctx.providerPath ? `- Provider / routing chain: ${ctx.providerPath}` : null,
    extra ? `- Additional environment: ${extra}` : null,
  ].filter((entry): entry is string => Boolean(entry));
  return lines.join("\n");
}

async function buildBody(
  kind: ReportKind,
  opts: ReportOptionsByKind[ReportKind],
  ctx: ReportContext,
): Promise<{
  body: string;
  evidence: string[];
  evidenceDetails: ReportEvidenceDetail[];
  redactionsApplied: string[];
}> {
  const probeMode = kind === "security" ? "none" : ((opts as BugReportOptions).probe ?? "general");
  const evidenceResult = await collectEvidenceDetails(kind, probeMode, ctx, opts);
  const evidence = renderEvidenceLines(evidenceResult.details);

  const summary = sanitizeReportText(opts.summary).text;
  if (kind === "bug") {
    const bug = opts as BugReportOptions;
    const additionalInformation = normalizeAdditionalInformation(
      bug.additionalInformation,
      bug.context,
    );
    const sections = [
      renderSection("Summary", summary),
      renderSection("Steps to reproduce", sanitizeReportText(bug.repro).text),
      renderSection("Expected behavior", sanitizeReportText(bug.expected).text),
      renderSection("Actual behavior", sanitizeReportText(bug.actual).text),
      renderSection("Environment", buildEnvironmentSection(ctx)),
      renderSection("Impact", sanitizeReportText(bug.impact).text),
      renderSection("Previous version", sanitizeReportText(bug.previousVersion).text),
      renderSection("Evidence", evidence.join("\n")),
      renderSection("Additional information", sanitizeReportText(additionalInformation).text),
    ].filter(Boolean);
    return {
      body: appendGeneratedNote(sections),
      evidence,
      evidenceDetails: evidenceResult.details,
      redactionsApplied: evidenceResult.redactionsApplied,
    };
  }
  if (kind === "feature") {
    const feature = opts as FeatureReportOptions;
    const additionalInformation = normalizeAdditionalInformation(
      feature.additionalInformation,
      feature.context,
    );
    const sections = [
      renderSection("Summary", summary),
      renderSection("Problem to solve", sanitizeReportText(feature.problem).text),
      renderSection("Proposed solution", sanitizeReportText(feature.solution).text),
      renderSection("Impact", sanitizeReportText(feature.impact).text),
      renderSection("Alternatives considered", sanitizeReportText(feature.alternatives).text),
      renderSection("Evidence", evidence.join("\n")),
      renderSection("Additional information", sanitizeReportText(additionalInformation).text),
    ].filter(Boolean);
    return {
      body: appendGeneratedNote(sections),
      evidence,
      evidenceDetails: evidenceResult.details,
      redactionsApplied: evidenceResult.redactionsApplied,
    };
  }

  const security = opts as SecurityReportOptions;
  const sections = [
    renderSection("Title", sanitizeReportText(opts.title).text),
    renderSection("Severity assessment", sanitizeReportText(security.severity).text),
    renderSection("Impact", sanitizeReportText(security.impact).text),
    renderSection("Affected component", sanitizeReportText(security.component).text),
    renderSection("Technical reproduction", sanitizeReportText(security.reproduction).text),
    renderSection("Demonstrated impact", sanitizeReportText(security.demonstratedImpact).text),
    renderSection(
      "Environment",
      sanitizeReportText(security.environment).text ||
        buildEnvironmentSection(ctx, security.environment),
    ),
    renderSection("Remediation advice", sanitizeReportText(security.remediation).text),
  ].filter(Boolean);
  return {
    body: appendGeneratedNote(sections),
    evidence: [],
    evidenceDetails: evidenceResult.details,
    redactionsApplied: evidenceResult.redactionsApplied,
  };
}

export async function buildReportPayload<K extends ReportKind>(params: {
  kind: K;
  options: ReportOptionsByKind[K];
  commandName?: string;
}): Promise<ReportPayload> {
  const ctx = await collectReportContext(params.commandName ?? `report ${params.kind}`);
  const missingFields = collectMissingFields(params.kind, params.options);
  const title = resolveTitle(params.kind, params.options);
  const bodyResult = await buildBody(params.kind, params.options, ctx);
  const payload: ReportPayload = {
    kind: params.kind,
    title,
    body: bodyResult.body,
    labels: resolveLabels(params.kind),
    evidence: bodyResult.evidence,
    evidenceDetails: bodyResult.evidenceDetails,
    redactionsApplied: bodyResult.redactionsApplied,
    missingFields,
    submissionEligible: params.kind !== "security" && missingFields.length === 0,
    submission: {
      created: false,
      dryRun: !params.options.submit,
      blockedReason:
        params.kind === "security" && params.options.submit
          ? "security reports must be filed privately"
          : missingFields.length > 0
            ? `missing required fields: ${missingFields.join(", ")}`
            : undefined,
    },
  };
  return payload;
}

function resolveOutputFormat(opts: SharedReportOptions): ReportOutputFormat {
  if (opts.json && opts.markdown) {
    throw new Error("Choose only one output format: --json or --markdown.");
  }
  if (opts.json) {
    return "json";
  }
  if (opts.markdown) {
    return "markdown";
  }
  return "human";
}

async function writeReportOutput(outputPath: string, body: string): Promise<void> {
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, body, "utf8");
}

function renderHumanPreview(payload: ReportPayload): string {
  const lines = [
    "Report status: Ready",
    `- Kind: ${payload.kind}`,
    `- Title: ${payload.title}`,
    payload.labels.length > 0 ? `- Labels: ${payload.labels.join(", ")}` : null,
    `- Submission eligible: ${payload.submissionEligible ? "yes" : "no"}`,
    payload.missingFields.length > 0 ? `- Missing: ${payload.missingFields.join(", ")}` : null,
    payload.redactionsApplied.length > 0
      ? `- Redactions: ${payload.redactionsApplied.join(", ")}`
      : null,
    "",
    payload.body,
  ].filter((entry): entry is string => Boolean(entry));
  return lines.join("\n");
}

export async function submitPublicReportIssue(params: {
  payload: ReportPayload;
  yes?: boolean;
  nonInteractive?: boolean;
  runtime: RuntimeEnv;
}): Promise<ReportSubmissionResult> {
  if (params.payload.kind === "security") {
    return {
      created: false,
      dryRun: false,
      blockedReason: "security reports must be sent privately to security@openclaw.ai",
    };
  }
  if (!params.payload.submissionEligible) {
    return {
      created: false,
      dryRun: false,
      blockedReason:
        params.payload.submission.blockedReason ?? "report is not ready for submission",
    };
  }

  if (!params.nonInteractive && !params.yes) {
    if (!process.stdin.isTTY) {
      return {
        created: false,
        dryRun: false,
        blockedReason: "interactive confirmation required; rerun with --yes or in a TTY",
      };
    }
    const confirmed = await promptYesNo("Create this GitHub issue now?");
    if (!confirmed) {
      return {
        created: false,
        dryRun: false,
        blockedReason: "submission cancelled",
      };
    }
  }

  if (params.nonInteractive && !params.yes) {
    return {
      created: false,
      dryRun: false,
      blockedReason: "non-interactive submission requires --yes",
    };
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-report-"));
  const bodyFile = path.join(tmpDir, "issue.md");
  try {
    await fs.writeFile(bodyFile, params.payload.body, "utf8");
    const args = [
      "issue",
      "create",
      "--repo",
      PUBLIC_REPO,
      "--title",
      params.payload.title,
      "--body-file",
      bodyFile,
      ...params.payload.labels.flatMap((label) => ["--label", label]),
    ];
    try {
      const { stdout } = await runExec("gh", args, { timeoutMs: 15_000, maxBuffer: 100_000 });
      const url = stdout
        .trim()
        .split(/\s+/)
        .find((entry) => entry.startsWith("http"));
      return {
        created: true,
        url,
        dryRun: false,
      };
    } catch (error) {
      return {
        created: false,
        dryRun: false,
        blockedReason: `gh issue create failed: ${String(error)}`,
      };
    }
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

export async function reportCommand<K extends ReportKind>(params: {
  kind: K;
  options: ReportOptionsByKind[K];
  runtime: RuntimeEnv;
}): Promise<ReportPayload> {
  const originalSuppressConfigWarnings = process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS;
  process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS = "1";
  try {
    const format = resolveOutputFormat(params.options);
    const payload = await buildReportPayload({
      kind: params.kind,
      options: params.options,
      commandName: `report ${params.kind}`,
    });

    if (params.options.submit) {
      payload.submission = await submitPublicReportIssue({
        payload,
        yes: params.options.yes,
        nonInteractive: params.options.nonInteractive,
        runtime: params.runtime,
      });
    }

    if (params.options.output) {
      await writeReportOutput(params.options.output, payload.body);
    }

    if (format === "json") {
      params.runtime.log(JSON.stringify(payload, null, 2));
    } else if (format === "markdown") {
      params.runtime.log(payload.body);
    } else {
      params.runtime.log(renderHumanPreview(payload));
      if (payload.kind === "security") {
        params.runtime.log("");
        params.runtime.log("Private route: send this report to security@openclaw.ai");
      } else if (params.options.submit && payload.submission.created && payload.submission.url) {
        params.runtime.log("");
        params.runtime.log(`Created: ${payload.submission.url}`);
      } else if (params.options.submit && payload.submission.blockedReason) {
        params.runtime.log("");
        params.runtime.log(`Submission blocked: ${payload.submission.blockedReason}`);
      }
    }

    return payload;
  } finally {
    if (originalSuppressConfigWarnings === undefined) {
      delete process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS;
    } else {
      process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS = originalSuppressConfigWarnings;
    }
  }
}
