# Policy-as-Code Agent

A small CI agent that reads Terraform and Kubernetes manifests in a pull
request, finds policy violations with deterministic checks, and asks Claude to
explain each finding in plain English with a concrete fix.

The point is to replace cryptic policy output ("`Resource AWSC0007 -
denied`") with something a developer can actually act on without pinging the
security team.

## How it works

![Architecture diagram]

The rule layer is deterministic on purpose — it's fast, free, and reliable.
The LLM layer only runs on confirmed findings, so cost stays bounded by the
number of violations, not the size of the repo. The LLM never decides whether
something is a violation; it only explains the ones the rule engine already
found, which keeps the trust boundary clean and the agent resistant to
prompt-injection from manifest content.

## Quick start

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

# Scan the examples
python policy_agent.py examples/

# Scan without LLM explanations (fast, free)
python policy_agent.py --no-llm examples/

# Produce a markdown report for a PR comment
python policy_agent.py --format markdown examples/ -o report.md
```

Exit code is non-zero when violations meet `--fail-on` (default: `high`), so
the agent can gate CI without extra plumbing.

## Built-in policies

| ID                  | Target | What it catches                                  |
|---------------------|--------|--------------------------------------------------|
| `TF-S3-001`         | TF     | S3 bucket with `public-read` / `public-read-write` ACL |
| `TF-SG-001`         | TF     | Security group exposing SSH/RDP/DB ports to `0.0.0.0/0` |
| `TF-RDS-001`        | TF     | RDS instance without storage encryption          |
| `TF-IAM-001`        | TF     | IAM policy with `"Action": "*"`                  |
| `K8S-HOST-*`        | K8s    | `hostNetwork`, `hostPID`, `hostIPC` enabled      |
| `K8S-VOL-HOSTPATH`  | K8s    | `hostPath` volume mounted into a pod             |
| `K8S-SEC-PRIV`      | K8s    | Container running `privileged: true`             |
| `K8S-SEC-ESC`       | K8s    | `allowPrivilegeEscalation: true`                 |
| `K8S-SEC-ROOT`      | K8s    | Container running as UID 0                       |
| `K8S-IMG-TAG`       | K8s    | Image using `:latest` or no tag                  |
| `K8S-RES-LIMITS`    | K8s    | Container missing `resources.limits`             |

Adding a new policy is one function in `policy_agent.py` — add a check in
`check_terraform` or `check_kubernetes` and append a `Violation`.

## GitHub Action

`.github/workflows/policy-check.yml` runs the agent on every PR that changes
`.tf`, `.yaml`, or `.yml` files. It diffs against the base branch, scans only
the changed files, and posts a sticky comment on the PR. Add
`ANTHROPIC_API_KEY` to your repository secrets and you're done.

## What's intentionally missing (and how I'd add it)

This is an MVP. A few things you'd want before relying on it:

- **More policies.** The set above is enough to demo the value; a real
  deployment needs ~30–50 rules covering the cloud services you actually use.
  Consider importing CIS Benchmark mappings or wrapping Checkov / tfsec / Trivy
  to get a large rule set for free and using this agent's LLM layer purely as a
  translator over their output.
- **`--diff-only` mode.** Right now the agent scans whole files. For PR use, it
  should only flag violations on lines that the PR actually touched, so people
  don't get blamed for pre-existing issues. The GitHub Action passes only
  changed files, which is close enough for most cases.
- **Suppression / waivers.** A `# policy-agent:ignore=TF-S3-001 reason="logs
  bucket is intentionally public"` comment that the parser respects.
- **Prompt-injection hardening.** The LLM sees manifest content. A malicious
  PR could embed instructions in a comment field. Mitigate by (a) keeping the
  LLM role purely explanatory — it never decides whether something is a
  violation — and (b) stripping comments from the excerpt before sending.
- **Caching.** Findings with identical `(policy_id, raw_finding)` get
  identical explanations; cache by hash of those fields to cut API spend in
  half on repos with repeated patterns.
