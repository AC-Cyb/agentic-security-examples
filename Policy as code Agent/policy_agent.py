#!/usr/bin/env python3
"""
Policy-as-Code Agent
====================
Scans Terraform (.tf) and Kubernetes (.yaml/.yml) manifests for policy
violations, then uses Claude to translate each finding into a plain-English
explanation with a concrete fix.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python policy_agent.py path/to/file_or_dir [...]
    python policy_agent.py --format markdown path/  # for PR comments
    python policy_agent.py --no-llm path/           # skip explanations (fast)

Exit code is non-zero when violations are found, so it can gate CI.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

import yaml

try:
    import hcl2  # pip install python-hcl2
except ImportError:
    hcl2 = None

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class Violation:
    file: str
    resource: str            # e.g. "aws_s3_bucket.logs" or "Deployment/api"
    policy_id: str           # e.g. "TF-S3-001"
    title: str               # short human-readable title
    severity: str            # one of SEVERITIES
    raw_finding: str         # technical detail, fed to the LLM
    excerpt: str = ""        # snippet of the manifest, for LLM context
    explanation: str = ""    # filled in by the LLM
    fix: str = ""            # filled in by the LLM

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Terraform policies
# ---------------------------------------------------------------------------
# Each checker takes (file_path, parsed_hcl) and yields Violations.
# hcl2 wraps most scalar values in single-element lists; _unwrap normalises.

def _unwrap(v: Any) -> Any:
    while isinstance(v, list) and len(v) == 1:
        v = v[0]
    # python-hcl2 v4+ wraps string values in escaped quotes: '"public-read"'
    if isinstance(v, str) and len(v) >= 2 and v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return v


def _strip_quotes(s: str) -> str:
    """hcl2 v4 wraps dict keys in escaped quotes too — strip them."""
    if isinstance(s, str) and len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _iter_resources(parsed: dict) -> Iterable[tuple[str, str, dict]]:
    """Yield (resource_type, name, config) tuples from a parsed .tf file."""
    for block in parsed.get("resource", []):
        for rtype, instances in block.items():
            rtype_clean = _strip_quotes(rtype)
            for name, cfg in instances.items():
                yield rtype_clean, _strip_quotes(name), _unwrap(cfg) or {}


def check_terraform(path: str, parsed: dict, source: str) -> list[Violation]:
    out: list[Violation] = []

    for rtype, name, cfg in _iter_resources(parsed):
        resource_id = f"{rtype}.{name}"
        excerpt = _excerpt_for(source, rtype, name)

        # --- S3: public ACL --------------------------------------------------
        if rtype == "aws_s3_bucket":
            acl = _unwrap(cfg.get("acl"))
            if acl in ("public-read", "public-read-write"):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="TF-S3-001",
                    title="S3 bucket with public ACL",
                    severity="high",
                    raw_finding=f"acl is '{acl}', allowing anonymous read access.",
                    excerpt=excerpt,
                ))

        # --- Security group: open ingress on sensitive ports -----------------
        if rtype == "aws_security_group":
            ingress = cfg.get("ingress", [])
            if not isinstance(ingress, list):
                ingress = [ingress]
            sensitive = {22: "SSH", 3389: "RDP", 3306: "MySQL",
                         5432: "Postgres", 6379: "Redis", 27017: "MongoDB"}
            for rule in ingress:
                rule = _unwrap(rule)
                cidrs = _unwrap(rule.get("cidr_blocks", []))
                if not isinstance(cidrs, list):
                    cidrs = [cidrs]
                fp = _unwrap(rule.get("from_port"))
                if "0.0.0.0/0" in cidrs and fp in sensitive:
                    out.append(Violation(
                        file=path, resource=resource_id,
                        policy_id="TF-SG-001",
                        title=f"{sensitive[fp]} port open to the internet",
                        severity="critical",
                        raw_finding=f"ingress allows 0.0.0.0/0 on port {fp} ({sensitive[fp]}).",
                        excerpt=excerpt,
                    ))

        # --- RDS: unencrypted storage ---------------------------------------
        if rtype == "aws_db_instance":
            encrypted = _unwrap(cfg.get("storage_encrypted"))
            if not encrypted:
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="TF-RDS-001",
                    title="RDS instance without storage encryption",
                    severity="high",
                    raw_finding="storage_encrypted is false or unset.",
                    excerpt=excerpt,
                ))

        # --- IAM: wildcard Action -------------------------------------------
        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            doc = _unwrap(cfg.get("policy"))
            # hcl2 may return either a rendered JSON string ("Action": "*")
            # or the raw HCL expression (Action = "*") if jsonencode is used.
            if isinstance(doc, str) and re.search(
                    r'Action\s*[:=]\s*\\?"\*\\?"', doc):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="TF-IAM-001",
                    title="IAM policy with wildcard Action",
                    severity="high",
                    raw_finding="The policy document grants Action: \"*\" — full access to the service.",
                    excerpt=excerpt,
                ))

    return out


def _excerpt_for(source: str, rtype: str, name: str, ctx: int = 12) -> str:
    """Pull the resource block out of the original .tf source for LLM context."""
    lines = source.splitlines()
    pattern = re.compile(rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(name)}"')
    for i, line in enumerate(lines):
        if pattern.search(line):
            return "\n".join(lines[i:i + ctx])
    return ""


# ---------------------------------------------------------------------------
# Kubernetes policies
# ---------------------------------------------------------------------------

K8S_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _pod_spec(doc: dict) -> dict | None:
    """Return the PodSpec inside a workload manifest, regardless of kind."""
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec") or {}
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        return ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    if kind == "CronJob":
        return (((doc.get("spec") or {})
                 .get("jobTemplate") or {})
                .get("spec") or {}).get("template", {}).get("spec") or {}
    return None


def check_kubernetes(path: str, docs: list[dict]) -> list[Violation]:
    out: list[Violation] = []

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind not in K8S_WORKLOAD_KINDS:
            continue
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        resource_id = f"{kind}/{name}"
        excerpt = yaml.safe_dump(doc, sort_keys=False).strip()

        pod = _pod_spec(doc)
        if pod is None:
            continue

        # --- hostNetwork / hostPID / hostIPC ---------------------------------
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(flag):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id=f"K8S-HOST-{flag.upper()}",
                    title=f"Pod uses {flag}",
                    severity="high",
                    raw_finding=f"{flag} is true — the pod shares the host's namespace.",
                    excerpt=excerpt,
                ))

        # --- hostPath volumes ------------------------------------------------
        for vol in pod.get("volumes") or []:
            if "hostPath" in (vol or {}):
                hp = vol["hostPath"].get("path", "?")
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-VOL-HOSTPATH",
                    title="Pod mounts a hostPath volume",
                    severity="high",
                    raw_finding=f"Volume '{vol.get('name')}' mounts host path '{hp}'.",
                    excerpt=excerpt,
                ))

        # --- Container-level checks -----------------------------------------
        containers = (pod.get("containers") or []) + (pod.get("initContainers") or [])
        for c in containers:
            cname = c.get("name", "?")
            sc = c.get("securityContext") or {}

            if sc.get("privileged") is True:
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-SEC-PRIV",
                    title=f"Container '{cname}' runs privileged",
                    severity="critical",
                    raw_finding=f"securityContext.privileged=true on container '{cname}'.",
                    excerpt=excerpt,
                ))

            if sc.get("allowPrivilegeEscalation") is True:
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-SEC-ESC",
                    title=f"Container '{cname}' allows privilege escalation",
                    severity="high",
                    raw_finding=f"allowPrivilegeEscalation=true on container '{cname}'.",
                    excerpt=excerpt,
                ))

            if sc.get("runAsUser") == 0 or (sc.get("runAsNonRoot") is False):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-SEC-ROOT",
                    title=f"Container '{cname}' runs as root",
                    severity="medium",
                    raw_finding=f"Container '{cname}' explicitly runs as UID 0 / runAsNonRoot=false.",
                    excerpt=excerpt,
                ))

            image = c.get("image", "")
            if image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-IMG-TAG",
                    title=f"Container '{cname}' uses :latest or no tag",
                    severity="low",
                    raw_finding=f"Image '{image}' is not pinned to an immutable tag/digest.",
                    excerpt=excerpt,
                ))

            res = c.get("resources") or {}
            if not res.get("limits"):
                out.append(Violation(
                    file=path, resource=resource_id,
                    policy_id="K8S-RES-LIMITS",
                    title=f"Container '{cname}' has no resource limits",
                    severity="medium",
                    raw_finding=f"Container '{cname}' is missing resources.limits.",
                    excerpt=excerpt,
                ))

    return out


# ---------------------------------------------------------------------------
# File discovery & dispatch
# ---------------------------------------------------------------------------

def scan_path(target: Path) -> list[Violation]:
    if target.is_file():
        return scan_file(target)

    violations: list[Violation] = []
    for p in target.rglob("*"):
        if p.is_file():
            violations.extend(scan_file(p))
    return violations


def scan_file(path: Path) -> list[Violation]:
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    if suffix == ".tf":
        if hcl2 is None:
            print("WARN: python-hcl2 not installed; skipping Terraform files.",
                  file=sys.stderr)
            return []
        try:
            parsed = hcl2.loads(text)
        except Exception as e:
            print(f"WARN: failed to parse {path}: {e}", file=sys.stderr)
            return []
        return check_terraform(str(path), parsed, text)

    if suffix in (".yaml", ".yml"):
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as e:
            print(f"WARN: failed to parse {path}: {e}", file=sys.stderr)
            return []
        # heuristic: only treat as k8s if at least one doc has apiVersion + kind
        if not any(isinstance(d, dict) and "apiVersion" in d and "kind" in d
                   for d in docs):
            return []
        return check_kubernetes(str(path), docs)

    return []


# ---------------------------------------------------------------------------
# LLM explanation layer
# ---------------------------------------------------------------------------

EXPLAINER_PROMPT = """You are a senior security engineer reviewing an infrastructure-as-code pull request. A policy check flagged the violation below. Your job is to explain it to the developer who wrote the PR — assume they are smart but not a security specialist.

POLICY: {title} ({policy_id})
SEVERITY: {severity}
FILE: {file}
RESOURCE: {resource}
TECHNICAL FINDING: {raw_finding}

MANIFEST EXCERPT:
```
{excerpt}
```

Respond with EXACTLY two sections, each 2-4 sentences:

WHY IT MATTERS:
Explain the real-world risk in plain English. What could an attacker actually do? Avoid jargon and acronyms when possible; when you must use a term (IMDS, RCE, etc.), define it briefly. Don't moralise or restate the policy name.

HOW TO FIX:
A concrete, specific fix for this resource. If a short code snippet would help, include it in a fenced block. Don't suggest tangential hardening — just fix what was flagged."""


def explain_violations(violations: list[Violation],
                       model: str = "claude-sonnet-4-5") -> None:
    """Mutates violations in place, filling in `explanation` and `fix`."""
    if not violations:
        return
    if Anthropic is None:
        print("WARN: anthropic SDK not installed; skipping explanations.",
              file=sys.stderr)
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("WARN: ANTHROPIC_API_KEY not set; skipping explanations.",
              file=sys.stderr)
        return

    client = Anthropic()
    for v in violations:
        prompt = EXPLAINER_PROMPT.format(**v.to_dict())
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(b.text for b in resp.content if b.type == "text")
            v.explanation, v.fix = _split_sections(text)
        except Exception as e:
            print(f"WARN: explanation failed for {v.policy_id}: {e}",
                  file=sys.stderr)


def _split_sections(text: str) -> tuple[str, str]:
    """Pull WHY IT MATTERS / HOW TO FIX sections out of the model response."""
    why_match = re.search(r"WHY IT MATTERS:\s*(.+?)(?=HOW TO FIX:|$)",
                          text, re.S | re.I)
    fix_match = re.search(r"HOW TO FIX:\s*(.+)", text, re.S | re.I)
    why = why_match.group(1).strip() if why_match else text.strip()
    fix = fix_match.group(1).strip() if fix_match else ""
    return why, fix


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}


def render_markdown(violations: list[Violation]) -> str:
    if not violations:
        return "## ✅ Policy check passed\n\nNo policy violations found in this change.\n"

    violations = sorted(violations, key=lambda v: SEV_RANK[v.severity])
    counts = {s: sum(1 for v in violations if v.severity == s) for s in SEVERITIES}

    lines = ["## 🛡️ Policy check found issues", ""]
    summary = " · ".join(f"{SEV_EMOJI[s]} {counts[s]} {s}"
                         for s in reversed(SEVERITIES) if counts[s])
    lines += [summary, ""]

    for v in violations:
        lines.append(f"### {SEV_EMOJI[v.severity]} {v.title}")
        lines.append(f"**`{v.resource}`** in `{v.file}` · "
                     f"policy `{v.policy_id}` · severity **{v.severity}**")
        lines.append("")
        if v.explanation:
            lines.append("**Why it matters**")
            lines.append(v.explanation)
            lines.append("")
        if v.fix:
            lines.append("**How to fix**")
            lines.append(v.fix)
            lines.append("")
        if not v.explanation and not v.fix:
            lines.append(f"_Technical detail:_ {v.raw_finding}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def render_text(violations: list[Violation]) -> str:
    if not violations:
        return "OK: no policy violations found.\n"
    out = []
    for v in sorted(violations, key=lambda v: SEV_RANK[v.severity]):
        out.append(f"[{v.severity.upper():8}] {v.policy_id}  {v.resource}  ({v.file})")
        out.append(f"           {v.title}")
        if v.explanation:
            out.append(f"           → {v.explanation.splitlines()[0]}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("paths", nargs="+", help="Files or directories to scan")
    p.add_argument("--format", choices=("text", "markdown", "json"),
                   default="text")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip the LLM explanation step")
    p.add_argument("--model", default="claude-sonnet-4-5",
                   help="Anthropic model to use for explanations")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   help="Minimum severity that causes a non-zero exit code")
    p.add_argument("-o", "--output", help="Write report to file instead of stdout")
    args = p.parse_args(argv)

    violations: list[Violation] = []
    for raw in args.paths:
        violations.extend(scan_path(Path(raw)))

    if not args.no_llm:
        explain_violations(violations, model=args.model)

    if args.format == "markdown":
        report = render_markdown(violations)
    elif args.format == "json":
        report = json.dumps([v.to_dict() for v in violations], indent=2)
    else:
        report = render_text(violations)

    if args.output:
        Path(args.output).write_text(report)
    else:
        sys.stdout.write(report)

    threshold = SEV_RANK[args.fail_on]
    if any(SEV_RANK[v.severity] >= threshold for v in violations):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
