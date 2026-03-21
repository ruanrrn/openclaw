import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const readBestEffortConfig = vi.fn();
const resolveCommandSecretRefsViaGateway = vi.fn();
const probeGateway = vi.fn();
const buildGatewayConnectionDetails = vi.fn();
const callGateway = vi.fn();
const resolveGatewayProbeAuthSafe = vi.fn();
const promptYesNo = vi.fn();
const runExec = vi.fn();
const getStatusSummary = vi.fn();
const buildChannelsTable = vi.fn();
const buildChannelSummary = vi.fn();
const collectChannelStatusIssues = vi.fn();
const resolveOpenClawAgentDir = vi.fn();
const ensureAuthProfileStore = vi.fn();
const resolveProviderAuthOverview = vi.fn();
const runAuthProbes = vi.fn();

vi.mock("../config/config.js", () => ({
  readBestEffortConfig,
}));

vi.mock("../cli/command-secret-gateway.js", () => ({
  resolveCommandSecretRefsViaGateway,
}));

vi.mock("../cli/command-secret-targets.js", () => ({
  getStatusCommandSecretTargetIds: () => ["gateway.auth.token"],
}));

vi.mock("../gateway/probe.js", () => ({
  probeGateway,
}));

vi.mock("../gateway/probe-auth.js", () => ({
  resolveGatewayProbeAuthSafe,
}));

vi.mock("../gateway/call.js", () => ({
  buildGatewayConnectionDetails,
  callGateway,
}));

vi.mock("../cli/prompt.js", () => ({
  promptYesNo,
}));

vi.mock("../process/exec.js", () => ({
  runExec,
}));

vi.mock("./status.js", () => ({
  getStatusSummary,
}));

vi.mock("./status-all/channels.js", () => ({
  buildChannelsTable,
}));

vi.mock("../infra/channel-summary.js", () => ({
  buildChannelSummary,
}));

vi.mock("../infra/channels-status-issues.js", () => ({
  collectChannelStatusIssues,
}));

vi.mock("../agents/agent-paths.js", () => ({
  resolveOpenClawAgentDir,
}));

vi.mock("../agents/auth-profiles.js", () => ({
  ensureAuthProfileStore,
}));

vi.mock("./models/list.auth-overview.js", () => ({
  resolveProviderAuthOverview,
}));

vi.mock("./models/list.probe.js", () => ({
  runAuthProbes,
}));

const runtime = {
  log: vi.fn(),
  error: vi.fn(),
  exit: vi.fn(),
};

describe("reportCommand", () => {
  let buildReportPayload: typeof import("./report.js").buildReportPayload;
  let reportCommand: typeof import("./report.js").reportCommand;
  let originalIsTTY: boolean | undefined;

  beforeEach(async () => {
    vi.resetModules();
    ({ buildReportPayload, reportCommand } = await import("./report.js"));
    runtime.log.mockReset();
    runtime.error.mockReset();
    runtime.exit.mockReset();
    const cfg = {
      gateway: { mode: "local" },
      channels: { telegram: { enabled: true } },
      models: { providers: { anthropic: { models: [{ id: "claude-sonnet-4.5" }] } } },
      agents: { defaults: { model: "anthropic/claude-sonnet-4.5" } },
    };
    readBestEffortConfig.mockResolvedValue(cfg);
    resolveCommandSecretRefsViaGateway.mockResolvedValue({
      resolvedConfig: cfg,
      diagnostics: ["token=abc123", "path=/Users/private-user/project"],
    });
    buildGatewayConnectionDetails.mockReturnValue({
      url: "ws://127.0.0.1:9090",
      message: "gateway local",
    });
    callGateway.mockResolvedValue({ ok: true, channelAccounts: {} });
    resolveGatewayProbeAuthSafe.mockReturnValue({ auth: {} });
    probeGateway.mockResolvedValue({
      ok: true,
      connectLatencyMs: 42,
    });
    getStatusSummary.mockResolvedValue({
      channelSummary: ["telegram ok", "discord off"],
      queuedSystemEvents: [],
      runtimeVersion: "2026.3.20",
      heartbeat: { defaultAgentId: "main", agents: [] },
      sessions: {
        paths: [],
        count: 0,
        defaults: { model: "anthropic/claude-sonnet-4.5", contextTokens: 200000 },
        recent: [],
        byAgent: [],
      },
    });
    buildChannelsTable.mockResolvedValue({
      rows: [{ id: "telegram", label: "Telegram", enabled: true, state: "ok", detail: "linked" }],
      details: [],
    });
    buildChannelSummary.mockResolvedValue(["telegram linked", "discord disabled"]);
    collectChannelStatusIssues.mockReturnValue([]);
    resolveOpenClawAgentDir.mockReturnValue("/tmp/openclaw-agent");
    ensureAuthProfileStore.mockReturnValue({ profiles: {} });
    resolveProviderAuthOverview.mockReturnValue({
      effective: { kind: "env", detail: "sk-***" },
      profiles: { count: 1 },
    });
    runAuthProbes.mockResolvedValue({
      totalTargets: 1,
      durationMs: 120,
      results: [
        {
          provider: "anthropic",
          model: "claude-sonnet-4.5",
          label: "default",
          source: "env",
          status: "timeout",
          error: "proxy timeout via mitmproxy",
          latencyMs: 1200,
        },
      ],
    });
    promptYesNo.mockResolvedValue(true);
    runExec.mockResolvedValue({
      stdout: "https://github.com/openclaw/openclaw/issues/999\n",
      stderr: "",
    });
    originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: true,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: originalIsTTY,
    });
  });

  it("reports missing bug fields and sanitizes sensitive content", async () => {
    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Gateway timeout for user@example.com",
        repro: "Run from /Users/private-user/project",
      },
    });

    expect(payload.missingFields).toEqual(["Expected behavior", "Actual behavior", "Impact"]);
    expect(payload.title).toBe("[Bug]: Gateway timeout for [email-redacted]");
    expect(payload.body).toContain("[email-redacted]");
    expect(payload.body).toContain("/Users/user/project");
    expect(payload.body).not.toContain("abc123");
    expect(payload.body).toContain("_Generated via `openclaw report`._");
    expect(payload.submissionEligible).toBe(false);
  });

  it("renders literal escaped newline sequences as real line breaks in report sections", async () => {
    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway\\n2. Send request\\n3. Observe failure",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
      },
    });

    expect(payload.body).toContain("1. Start gateway\n2. Send request\n3. Observe failure");
    expect(payload.body).not.toContain("\\n2. Send request");
  });

  it("writes markdown output that matches the generated body", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-report-test-"));
    const outputPath = path.join(tmpDir, "bug.md");

    const payload = await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway\n2. Send request",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        markdown: true,
        output: outputPath,
      },
      runtime,
    });

    const written = await fs.readFile(outputPath, "utf8");
    expect(runtime.log).toHaveBeenCalledWith(payload.body);
    expect(written).toBe(payload.body);
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("suppresses config warning logging while building a report and restores the env", async () => {
    process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS = "0";
    readBestEffortConfig.mockImplementation(async () => {
      expect(process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS).toBe("1");
      return {
        gateway: { mode: "local" },
        models: { providers: { anthropic: { models: [{ id: "claude-sonnet-4.5" }] } } },
        agents: { defaults: { model: "anthropic/claude-sonnet-4.5" } },
      };
    });

    await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway\n2. Send request",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
      },
      runtime,
    });

    expect(process.env.OPENCLAW_SUPPRESS_CONFIG_WARNINGS).toBe("0");
  });

  it("collects gateway evidence for gateway probe mode", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://proxy.local:8080");

    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        probe: "gateway",
      },
    });

    expect(payload.evidenceDetails.some((detail) => detail.source === "gateway")).toBe(true);
    expect(payload.evidence).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Gateway target"),
        expect.stringContaining("Gateway probe"),
        expect.stringContaining("Effective HTTPS proxy"),
      ]),
    );
    expect(payload.body).toContain("## Evidence");
    expect(payload.body).toContain("Gateway probe");
  });

  it("collects model evidence for model probe mode", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://proxy.local:8080");

    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Provider auth mismatch",
        repro: "1. Run model list",
        expected: "Provider is ready",
        actual: "Auth mismatch",
        impact: "Blocks completions",
        probe: "model",
      },
    });

    expect(resolveProviderAuthOverview).toHaveBeenCalled();
    expect(runAuthProbes).toHaveBeenCalled();
    expect(payload.evidenceDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "model", label: "Model path" }),
        expect.objectContaining({ source: "model", label: "Provider auth" }),
        expect.objectContaining({ source: "model", label: "Model probe" }),
        expect.objectContaining({ source: "recentErrors", label: "Recent model-call error" }),
      ]),
    );
    expect(payload.body).toContain("Provider auth");
    expect(payload.body).toContain("Recent model-call error");
    expect(payload.body).toContain("Model probe: timeout via env proxy http://proxy.local:8080");
  });

  it("collects channel evidence for channel probe mode", async () => {
    collectChannelStatusIssues.mockReturnValue([{ message: "Telegram account needs relink" }]);

    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Telegram send failed",
        repro: "1. Send a message",
        expected: "Message sends",
        actual: "Delivery fails",
        impact: "Breaks channel delivery",
        probe: "channel",
      },
    });

    expect(payload.evidenceDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "channel", label: "Configured channels" }),
        expect.objectContaining({
          source: "channel",
          label: "Gateway-reported channel issue",
        }),
      ]),
    );
    expect(payload.body).toContain("Telegram account needs relink");
  });

  it("bounds public evidence while preserving richer details for general feature probes", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://proxy.local:8080");
    vi.stubEnv("NO_PROXY", "localhost,127.0.0.1");
    const payload = await buildReportPayload({
      kind: "feature",
      options: {
        summary: "Need better retry visibility",
        problem: "Retries are opaque",
        solution: "Show retry state in UI",
        impact: "Reduces debugging time",
        evidence: "User report from user@example.com",
        probe: "general",
      },
    });

    expect(payload.evidence.length).toBeLessThanOrEqual(5);
    expect(payload.evidenceDetails.length).toBeGreaterThan(payload.evidence.length);
    expect(payload.body).toContain("## Evidence");
    expect(payload.body).not.toContain("Secret diagnostics");
    expect(payload.body).not.toContain("Degraded diagnostics");
    expect(payload.body).not.toContain("token=abc123");
    expect(payload.evidenceDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "proxy", label: "Proxy env" }),
        expect.objectContaining({ source: "proxy", label: "Effective HTTPS proxy" }),
      ]),
    );
  });

  it("renders previous version when provided", async () => {
    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Regression after update",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        previousVersion: "2026.3.14",
      },
    });

    expect(payload.body).toContain("## Previous version");
    expect(payload.body).toContain("2026.3.14");
  });

  it("renders additional information with the new heading for bug reports", async () => {
    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        additionalInformation:
          "Worked last week for user@example.com from /Users/private-user/project",
      },
    });

    expect(payload.body).toContain("## Additional information");
    expect(payload.body).not.toContain("## Additional context");
    expect(payload.body).toContain("[email-redacted]");
    expect(payload.body).toContain("/Users/user/project");
  });

  it("merges additional information and context for feature reports", async () => {
    const payload = await buildReportPayload({
      kind: "feature",
      options: {
        summary: "Need better retry visibility",
        problem: "Retries are opaque",
        solution: "Show retry state in UI",
        impact: "Reduces debugging time",
        additionalInformation: "Users noticed this after the last rollout.",
        context: "Might be related to proxy retries.",
      },
    });

    expect(payload.body).toContain("## Additional information");
    expect(payload.body).toContain("Users noticed this after the last rollout.");
    expect(payload.body).toContain("Might be related to proxy retries.");
  });

  it("submits a public bug report in non-interactive mode with --yes", async () => {
    const payload = await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        submit: true,
        yes: true,
        nonInteractive: true,
        json: true,
      },
      runtime,
    });

    expect(runExec).toHaveBeenCalledWith(
      "gh",
      expect.arrayContaining(["issue", "create", "--repo", "openclaw/openclaw"]),
      expect.any(Object),
    );
    expect(payload.submission.created).toBe(true);
    expect(payload.submission.url).toBe("https://github.com/openclaw/openclaw/issues/999");
  });

  it("prints the created issue url in human output after successful submission", async () => {
    await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        submit: true,
        yes: true,
        nonInteractive: true,
      },
      runtime,
    });

    expect(runtime.log).toHaveBeenCalledWith("Created: https://github.com/openclaw/openclaw/issues/999");
  });

  it("keeps draft generation working when config and secret resolution degrade", async () => {
    readBestEffortConfig.mockRejectedValueOnce(new Error("config missing"));
    resolveCommandSecretRefsViaGateway.mockRejectedValueOnce(new Error("secret refs unavailable"));

    const payload = await buildReportPayload({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        probe: "general",
      },
    });

    expect(payload.submissionEligible).toBe(true);
    expect(payload.evidenceDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          source: "secretDiagnostics",
          label: "Degraded diagnostics",
          includedInPublicBody: false,
        }),
      ]),
    );
    expect(payload.body).not.toContain("config load degraded");
  });

  it("blocks public submission for security reports", async () => {
    const payload = await reportCommand({
      kind: "security",
      options: {
        title: "Token leak",
        severity: "high",
        impact: "Credential reuse risk",
        component: "Gateway auth",
        reproduction: "Trigger auth flow",
        demonstratedImpact: "Token exposed in logs",
        environment: "macOS",
        remediation: "Mask token before logging",
        submit: true,
        json: true,
      },
      runtime,
    });

    expect(runExec).not.toHaveBeenCalled();
    expect(payload.submission.created).toBe(false);
    expect(payload.submission.blockedReason).toContain("security reports");
  });

  it("requires confirmation for interactive bug submission", async () => {
    promptYesNo.mockResolvedValue(false);

    const payload = await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        submit: true,
      },
      runtime,
    });

    expect(promptYesNo).toHaveBeenCalled();
    expect(runExec).not.toHaveBeenCalled();
    expect(payload.submission.blockedReason).toBe("submission cancelled");
  });

  it("returns a structured blocked submission when gh create fails", async () => {
    runExec.mockRejectedValue(new Error("gh auth login required"));

    const payload = await reportCommand({
      kind: "bug",
      options: {
        summary: "Gateway timeout",
        repro: "1. Start gateway",
        expected: "Model responds",
        actual: "Timeout",
        impact: "Blocks requests",
        submit: true,
        yes: true,
        nonInteractive: true,
      },
      runtime,
    });

    expect(payload.submission.created).toBe(false);
    expect(payload.submission.blockedReason).toContain("gh issue create failed");
    expect(payload.submission.blockedReason).toContain("gh auth login required");
    expect(runtime.log).toHaveBeenCalledWith(expect.stringContaining("Report status: Ready"));
    expect(runtime.log).toHaveBeenCalledWith(
      expect.stringContaining("Submission blocked: gh issue create failed"),
    );
  });
});
