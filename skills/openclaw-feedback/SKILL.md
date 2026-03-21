---
name: openclaw-feedback
description: Invoke when the user starts complaining about a bug, broken behavior, regression, product issue, feature request, or private security problem in `openclaw/openclaw`. Route them into the right `openclaw report` flow.
user-invocable: true
metadata:
  {
    "openclaw":
      {
        "emoji": "🐙",
        "requires": { "bins": ["gh"] },
        "install":
          [
            {
              "id": "brew",
              "kind": "brew",
              "formula": "gh",
              "bins": ["gh"],
              "label": "Install GitHub CLI (brew)",
            },
          ],
      },
  }
---

# OpenClaw Feedback

Use this skill only for `openclaw/openclaw`.

## Goal

- Route the user into the correct `openclaw report` flow with minimal extra questions.
- Treat `openclaw report` as the only authoritative path for drafting, previewing, diagnostics, redaction, and submission results.

## Do

- Tell the user you are using the `openclaw-feedback` skill.
- In that opening, explain that getting enough context matters because stronger context produces a more accurate, actionable GitHub issue and avoids weak or misleading filings.
- In that opening, give the user a clear way to decline or cancel issue filing if they do not want to proceed.
- Decide `bug`, `feature`, or `private security report`.
- Ask only for missing required fields, with at most 1-3 short questions.
- Derive as much as possible from the conversation, the active diagnosis session, and the generated report draft before asking the user anything.
- Treat `openclaw report bug|feature|security` as the source of truth for drafting, redaction, diagnostics, previewing, and submission behavior.
- If you are unsure about flags or subcommand shape, run `openclaw report --help` before invoking the report flow.
- Tell the user report generation can take a moment when diagnostics or probes are included.
- Relay the generated draft or blocked result from `openclaw report` directly.
- Show the full sanitized draft before asking to submit.
- Ask permission in plain English before adding `--submit`.
- Only after approval, use `--submit` for public bug or feature issues.
- If submission succeeds, include the created GitHub issue URL in the final reply to the user.

## Do Not

- Never create the issue before user approval.
- Never file against any repo other than `openclaw/openclaw`.
- Never maintain a separate manual issue-writing path when `openclaw report` is available.
- Never publish a security report as a public issue.
- Never fall back to manual filing if `openclaw report` or `gh` is unavailable.
- Never ask the user for fields the conversation, diagnostics, or report output already make clear.
- Never read report metadata such as labels, submission eligibility, or redactions back to the user unless it is directly useful to the decision.

## If X Then Y

- If the request is a vulnerability, leaked credential, or private security report: use `openclaw report security`; do not create a public issue.
- If the request is clearly a broken behavior or regression: use `openclaw report bug`.
- If the request is clearly asking for a new capability or improvement: use `openclaw report feature`.
- If the type is unclear: ask one short question to decide bug vs feature.
- If the user already gave enough detail: skip extra questions.
- If summary, likely title, environment, diagnosis clues, repro outline, or impact can be derived from the conversation or active diagnosis work: do not ask for them again.
- If diagnostics would materially improve the report: use `--probe general|gateway|model|channel` on the `openclaw report` command instead of assembling standalone diagnostics yourself.
- If the issue is still too weak after a short recovery attempt: return `NOT_ENOUGH_INFO`.
- If unsafe content cannot be safely redacted without losing the technical meaning: return `BLOCKED_UNSAFE_CONTENT`.
- If `openclaw report` or `gh` is unavailable: return `BLOCKED_MISSING_TOOL`.

## Workflow

1. Say: `I’m using the openclaw-feedback skill to prepare an OpenClaw GitHub issue. I want to gather enough context to make the issue accurate and useful for maintainers without over-questioning you. Report generation can take a moment if I include diagnostics or probes. If you do not want to file an issue, just tell me and I’ll stop.`
2. Decide `bug`, `feature`, or `private security report`.
3. Derive as much as possible from the conversation and current diagnosis context before asking anything.
4. Ask only for missing required user facts:
   - bug: summary, steps to reproduce, expected behavior, actual behavior, impact
     optional regression context: previous version -> `--previous-version`
   - feature: summary, problem to solve, proposed solution, impact
   - security: title, severity, impact, affected component, technical reproduction, demonstrated impact, environment, remediation advice
     If a field can be inferred with high confidence from the conversation or diagnosis session, infer it instead of asking.
5. Choose the matching command:
   - `openclaw report bug`
   - `openclaw report feature`
   - `openclaw report security`
6. If targeted diagnostics are useful, add one probe mode:
   - `--probe general`
   - `--probe gateway`
   - `--probe model`
   - `--probe channel`
     Choose `--probe gateway` for proxy, gateway, or timeout/network failures.
     Choose `--probe model` for provider auth, model-call, or dispatcher/proxy-path issues.
     Choose `--probe channel` for channel integrations or account-specific failures.
7. Run `openclaw report <kind> ...` and trust its output as authoritative.
8. Show the full sanitized draft or blocked result without reformatting it into a separate skill-owned state machine.
9. When showing the draft, emphasize the user-visible problem and the proposed report body, not internal metadata like labels or submission headers.
10. After showing the draft, ask in plain English: `If this draft looks right, I can submit it to GitHub now.`
11. Do not mention CLI flags like `--submit` in the user-facing approval question.
12. Only if the user clearly approves, rerun or continue with `--submit` for public bug or feature issues.
13. If the issue is created successfully, include the created GitHub URL in the final reply.
14. For security, keep the report private and route the user to `security@openclaw.ai`.

## Common Commands

- Help: `openclaw report --help`
- Bug draft: `openclaw report bug`
- Feature draft: `openclaw report feature`
- Security private report draft: `openclaw report security`
- Public issue submission after approval: add `--submit`

## Flag Mapping

- summary -> `--summary`
- repro -> `--repro`
- expected -> `--expected`
- actual -> `--actual`
- impact -> `--impact`
- previous version -> `--previous-version`
- additional information -> `--additional-information`
- feature problem -> `--problem`
- feature solution -> `--solution`

Use `--additional-information` for details that do not fit neatly into `--repro`, `--expected`, `--actual`, or `--evidence`, including:

- useful loose context
- regression clues
- timelines
- unusual observations
- operator hypotheses worth preserving

Prefer deriving these from the conversation when they are already clear instead of asking the user to restate them.

When passing multiline text into the CLI as a single quoted argument, encode line breaks as literal `\n` so `openclaw report` can render them back as real line breaks in the final issue body.

## Private Security Reports

If the request is a security issue:

- use `openclaw report security` as the source of truth for the private report draft
- do not create a public GitHub issue
- do not include exploit details in chat unless needed to route the report
- ask only for missing required private-report fields
- briefly summarize the category, affected area, and impact in private-report-safe terms only
- tell the user to report it privately to `security@openclaw.ai`

## PII And Secret Redaction

- Let `openclaw report` handle redaction by default.
- If you must quote or summarize content before invoking it, redact tokens, passwords, emails, phone numbers, private-person handles, home-directory names, and unnecessary local file paths.

## Permission Preview

Let `openclaw report` define the preview, readiness, blocked-submission, and created-output wording.

Do not restate or simulate `READY_TO_CREATE`, `SUBMISSION_BLOCKED`, or other CLI output formats inside this skill.

If the user has not clearly approved filing after seeing the full draft, stop before adding `--submit`.

## Notes

- `openclaw report` is the authoritative path for title/body formatting, bounded diagnostics, redaction, degraded diagnostics handling, submission gating, and `gh` failure behavior.
- Keep this skill focused on orchestration, not manual issue authoring.
- Do not invent extra workflow, output schema, or issue-body rules beyond what `openclaw report` already implements.

## Examples

### Example: bug with gateway diagnostics

User says: `OpenClaw times out behind mitmproxy.`

Assistant says:

```text
I’m using the openclaw-feedback skill to prepare an OpenClaw GitHub issue. I want to gather enough context to make the issue accurate and useful for maintainers without over-questioning you. Report generation can take a moment if I include diagnostics or probes.
If you do not want to file an issue, just tell me and I’ll stop.

I need a few bug-report details: what steps reproduce it, what you expected, what actually happened, and the impact.
```

If those fields are not already clear from the diagnosis session, ask for them. Otherwise infer them and run:

```bash
openclaw report bug --summary "Gateway times out behind mitmproxy" --repro "1. Start gateway\n2. Send request\n3. Observe timeout" --expected "..." --actual "..." --impact "..." --probe gateway
```

Then show the draft itself, not internal report metadata. Only add `--submit` after explicit approval.

After showing the draft, ask:

```text
If this draft looks right, I can submit it to GitHub now.
```

If submission succeeds, include the created issue URL in the final reply.

### Example: regression bug with loose extra context

User says: `This worked last week, but after updating it started timing out.`

Assistant says:

```text
I’m using the openclaw-feedback skill to prepare an OpenClaw GitHub issue. I want to gather enough context to make the issue accurate and useful for maintainers without over-questioning you. Report generation can take a moment if I include diagnostics or probes.
If you do not want to file an issue, just tell me and I’ll stop.

I need the repro steps, expected behavior, actual behavior, and impact. I can also include the previous version and any extra observations that do not fit neatly into the main bug fields.
```

If the missing facts are not already clear from the conversation or diagnosis session, ask for them. Otherwise infer them and run:

```bash
openclaw report bug --summary "Regression after update" --repro "1. Start gateway\n2. Send request\n3. Observe failure" --expected "..." --actual "..." --impact "..." --previous-version "2026.3.14" --additional-information "Worked last week; now every call times out behind the same proxy setup." --probe model
```

Then show the draft and ask:

```text
If this draft looks right, I can submit it to GitHub now.
```

If submission succeeds, include the created issue URL in the final reply.

### Example: feature request

User says: `Please add a way to export a report draft without submitting it.`

If the user already gave enough detail, derive the report directly and run:

```bash
openclaw report feature --summary "Export report drafts without submission" --problem "Operators want a clean draft artifact without creating a GitHub issue" --solution "Allow report generation and file output without submit" --impact "Safer scripted issue authoring"
```

Then show the draft and ask:

```text
If this draft looks right, I can submit it to GitHub now.
```

If submission succeeds, include the created issue URL in the final reply.

### Example: private security report

User says: `I found a token leak in logs.`

Assistant says:

```text
I’m using the openclaw-feedback skill to route this into the private OpenClaw security-report flow. I want to gather enough context to make the report accurate and actionable while keeping it private.
If you do not want to file a report, just tell me and I’ll stop.
```

Then gather only missing private-report fields and run:

```bash
openclaw report security --title "Token leak in logs" --severity high --impact "..." --component "..." --reproduction "..." --demonstrated-impact "..." --environment "..." --remediation "..."
```

Do not create a public issue.
