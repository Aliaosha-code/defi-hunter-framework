#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
REGISTRY = TARGETS / "registry.csv"
SKILL_HOME = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills"
ORCH_SKILL = SKILL_HOME / "defi-audit-orchestrator"

CANDIDATE_STATES = {
    "suspected",
    "plausible but unproven",
    "test written",
    "tested failed/security relevant",
    "tested no impact",
    "confirmed with PoC",
    "false positive",
    "informational",
    "blocked",
}

ACTIVE_STATE_ORDER = {
    "tested failed/security relevant": 0,
    "test written": 1,
    "plausible but unproven": 2,
    "suspected": 3,
}

CANDIDATE_FIELDS = [
    "id",
    "state",
    "priority",
    "title",
    "code_path",
    "pattern",
    "trust_class",
    "source_expr",
    "sink_path",
    "property",
    "impact",
    "proof_gate",
    "false_positive_filters",
    "harness",
    "validation_plan",
    "autopilot_next_action",
    "next_action",
    "evidence",
]

FINDING_FIELDS = [
    "id",
    "status",
    "severity",
    "affected",
    "poc_command",
    "report_path",
    "log_path",
    "summary",
]

FAMILY_CANDIDATE_WEIGHTS = {
    "perps-async-orders": {
        "oracle-composition-signed-cast": 8,
        "signed-oracle-to-unsigned-cast": 10,
        "oracle-freshness-surface": 12,
        "full-balance-after-external-call": 18,
        "untrusted-erc4626-value-conversion": 22,
        "trusted-erc4626-oracle-dependency": 24,
        "preview-action-pair": 28,
        "bounded-maturity-loop": 35,
        "admin-parameter-domain": 50,
    },
    "lending-vault": {
        "oracle-composition-signed-cast": 8,
        "signed-oracle-to-unsigned-cast": 10,
        "untrusted-erc4626-value-conversion": 12,
        "trusted-erc4626-oracle-dependency": 16,
        "oracle-freshness-surface": 15,
        "preview-action-pair": 22,
        "bounded-maturity-loop": 24,
        "full-balance-after-external-call": 30,
        "admin-parameter-domain": 50,
    },
    "modular-lending": {
        "oracle-composition-signed-cast": 8,
        "signed-oracle-to-unsigned-cast": 10,
        "untrusted-erc4626-value-conversion": 12,
        "trusted-erc4626-oracle-dependency": 16,
        "oracle-freshness-surface": 14,
        "full-balance-after-external-call": 18,
        "bounded-maturity-loop": 22,
        "preview-action-pair": 26,
        "admin-parameter-domain": 50,
    },
    "fixed-maturity-yield": {
        "bounded-maturity-loop": 10,
        "oracle-composition-signed-cast": 11,
        "signed-oracle-to-unsigned-cast": 12,
        "untrusted-erc4626-value-conversion": 14,
        "trusted-erc4626-oracle-dependency": 17,
        "oracle-freshness-surface": 18,
        "preview-action-pair": 20,
        "full-balance-after-external-call": 22,
        "admin-parameter-domain": 50,
    },
    "vault-erc4626": {
        "untrusted-erc4626-value-conversion": 10,
        "trusted-erc4626-oracle-dependency": 13,
        "preview-action-pair": 12,
        "oracle-composition-signed-cast": 14,
        "signed-oracle-to-unsigned-cast": 16,
        "oracle-freshness-surface": 18,
        "full-balance-after-external-call": 24,
        "bounded-maturity-loop": 35,
        "admin-parameter-domain": 50,
    },
    "solana-clmm": {
        "oracle-freshness-surface": 20,
        "full-balance-after-external-call": 25,
        "signed-oracle-to-unsigned-cast": 30,
        "preview-action-pair": 35,
        "bounded-maturity-loop": 45,
        "admin-parameter-domain": 50,
    },
}

REQUIRED_TARGET_FILES = [
    "audit-state.md",
    "scope.md",
    "protocol-map.md",
    "attack-lines.md",
    "candidates.tsv",
    "findings.tsv",
    "evidence-index.jsonl",
    "lessons.jsonl",
    "skill-evolution.md",
    "notes/commands.md",
    "notes/repo-commits.md",
]

TARGET_PHASES = [
    "env_not_ready",
    "baseline_ready",
    "protocol_mapped",
    "candidate_queue_ready",
    "poc_validation_active",
    "confirmed_or_exhausted",
]

DISCOVERY_SKIP_DIRS = {
    ".git",
    ".github",
    ".codex-audit",
    ".nx",
    ".yarn",
    ".vscode",
    "__pycache__",
    "artifacts",
    "build",
    "cache",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "typechain-types",
    "abi_typescript",
    "broadcast",
    "deployments",
    "flattened",
    "lib",
    "dependencies",
    "dependency",
    "vendor",
    "vendors",
    "third_party",
    "third-party",
}

SOURCE_EXTENSIONS = {".sol", ".rs", ".ts", ".js", ".vy", ".move", ".cairo"}

FAMILY_RULES = [
    (
        "modular-lending",
        92,
        ["controller", "collateral", "liquidation", "vault kit", "deferred check", "cross-vault", "account status"],
        "deferred checks, cross-vault collateral, oracle route composition, liquidation boundaries",
    ),
    (
        "perps-async-orders",
        88,
        ["perp", "perpetual", "synthetics", "funding", "orderhandler", "async order", "position impact", "open interest"],
        "async order state machines, funding, pool-value accounting, cancellation/freeze paths",
    ),
    (
        "fixed-maturity-yield",
        86,
        ["maturity", "expiry", "principal token", "yield token", "fixed rate", "term", "rollover", "checkpoint"],
        "maturity horizons, PT/YT accounting, reward drift, checkpoint timing",
    ),
    (
        "lending-vault",
        82,
        ["borrow", "repay", "irm", "ltv", "bad debt", "debt", "collateral", "liquidation"],
        "collateral/debt conservation, liquidation, interest indexes, oracle solvency",
    ),
    (
        "vault-erc4626",
        78,
        ["erc4626", "vault", "share", "deposit", "redeem", "withdraw", "strategy", "nav"],
        "share accounting, first deposit, donation, withdrawal queues, strategy valuation",
    ),
    (
        "oracle-router",
        74,
        ["oracle", "chainlink", "twap", "pricefeed", "router", "fallback", "sequencer"],
        "oracle freshness, decimals, signedness, fallback composition, route trust boundaries",
    ),
    (
        "solana-clmm",
        90,
        ["clmm", "anchor", "litesvm", "pinocchio", "token-2022", "tick", "tick array", "position bundle"],
        "account validation, token extensions, tick math, transfer hooks, quote boundaries",
    ),
    (
        "amm-router",
        70,
        ["amm", "swap", "router", "pool", "liquidity", "market", "curve", "balanceof"],
        "router residue, AMM invariants, callbacks, fee accounting, balance-delta checks",
    ),
    (
        "staking-rewards",
        58,
        ["stake", "staking", "reward", "stream", "claim", "epoch", "emission"],
        "reward index drift, claim/exit ordering, paused exits, dust accumulation",
    ),
    (
        "core-connector",
        55,
        ["connector", "multicall", "permit", "registry", "access", "auth", "proxy"],
        "authorization, batching, integration trust boundaries, account status finality",
    ),
]

PATTERN_META = {
    "oracle-composition-signed-cast": {
        "priority": 1,
        "title": "Composed oracle sub-feed signed answer cast before validation",
        "property": "Signed oracle components must be validated before unsigned composition math.",
        "next": "Use negative sub-feed mocks, then prove whether the composed positive answer reaches accountLiquidity, borrow, liquidation, or share math.",
    },
    "signed-oracle-to-unsigned-cast": {
        "priority": 1,
        "title": "Signed oracle answer can reach unsigned value path",
        "property": "Oracle answers must be validated before pricing, solvency, liquidation, or share math.",
        "next": "Wire a negative or invalid mock answer into the consuming path and prove revert or impact.",
    },
    "bounded-maturity-loop": {
        "priority": 1,
        "title": "Maturity or checkpoint horizon may exclude reachable value",
        "property": "A new entrant must not capture value that should have been accrued before entry.",
        "next": "Compare checkpoint-before-enter against enter-before-checkpoint with identical final state.",
    },
    "untrusted-erc4626-value-conversion": {
        "priority": 2,
        "title": "Untrusted ERC4626 conversion used as value source",
        "property": "ERC4626 receipt/share conversion must be registry-bound or otherwise proven trusted before value use.",
        "next": "Trace the ERC4626 receiver source first; only use a fake vault PoC if a factory/config/user path accepts that receiver.",
    },
    "trusted-erc4626-oracle-dependency": {
        "priority": 3,
        "title": "Trusted ERC4626 dependency contributes to oracle value",
        "property": "Fixed ERC4626 dependency conversion must not create unsafe oracle/risk states under in-scope dependency behavior.",
        "next": "Prove the dependency can enter a bad conversion state in scope, then trace the adapter output into oracle, borrow, liquidation, or solvency logic.",
    },
    "full-balance-after-external-call": {
        "priority": 2,
        "title": "Router residue may be attributed as fresh output",
        "property": "Pre-existing balances must not satisfy minOut or receiver accounting.",
        "next": "Inject residue before the route and assert receiver/protected-user accounting is unchanged.",
    },
    "oracle-freshness-surface": {
        "priority": 3,
        "title": "Oracle freshness surface needs consuming-path classification",
        "property": "Stale, zero, negative, and reverting oracle states must be handled at core consumers.",
        "next": "Classify the feed as core risk, share, swap, reward, preview, or unused, then test boundaries.",
    },
    "preview-action-pair": {
        "priority": 4,
        "title": "Preview/action pair needs rounding consistency check",
        "property": "Preview and action outputs must agree in the security-relevant rounding direction.",
        "next": "Compare preview and state-changing calls under dust, donation, fee, and first-deposit states.",
    },
    "admin-parameter-domain": {
        "priority": 5,
        "title": "Admin parameter domain review",
        "property": "Admin parameters must be bounded when user funds can be affected.",
        "next": "Demote unless role bypass, missing cap, missing timelock, or direct fund impact is shown.",
    },
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(value: str) -> str:
    lowered = value.strip().lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", lowered).strip("-")
    return slug or "target"


def target_dir(name: str) -> Path:
    return TARGETS / slugify(name)


def sparse(path: Path) -> bool:
    if not path.exists():
        return True
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if len(text) < 80:
        return True
    hints = [
        "TBD",
        "fill in",
        "replace",
        "unknown",
        "scanner hit only",
        "no PoC yet",
    ]
    return any(hint.lower() in text.lower() for hint in hints)


def write_if_missing(path: Path, text: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def append_jsonl(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        handle.write("\n")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"parse_error": True, "raw": line})
    return rows


def read_tsv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        rows: list[dict[str, str]] = []
        for row in csv.DictReader(handle, delimiter="\t"):
            if None in row or any(value is None for value in row.values()):
                continue
            normalized = {str(key): "" if value is None else str(value) for key, value in row.items()}
            if not normalized.get("id") and "id" in normalized:
                continue
            if path.name == "candidates.tsv" and not normalized.get("state"):
                continue
            rows.append(normalized)
        return rows


def write_tsv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=path.parent, delete=False) as handle:
        tmp = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "" if row.get(key) is None else str(row.get(key, "")) for key in fieldnames})
    tmp.replace(path)


@contextmanager
def file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def registry_rows() -> list[dict[str, str]]:
    if not REGISTRY.exists():
        return []
    with REGISTRY.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def save_registry(rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "name",
        "family",
        "repo_path",
        "authorization",
        "phase",
        "priority",
        "status",
        "next_action",
        "notes",
    ]
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRY.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def upsert_registry(row: dict[str, str]) -> None:
    rows = registry_rows()
    updated = False
    for index, existing in enumerate(rows):
        if existing.get("name") == row["name"]:
            merged = dict(existing)
            merged.update({key: value for key, value in row.items() if value})
            rows[index] = merged
            updated = True
            break
    if not updated:
        rows.append(row)
    save_registry(rows)


def repo_for_target(name: str) -> str:
    audit_state = target_dir(name) / "audit-state.md"
    if audit_state.exists():
        for line in audit_state.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("- Repo path:"):
                return line.split(":", 1)[1].strip()
    for row in registry_rows():
        if row.get("name") == slugify(name):
            return row.get("repo_path", "")
    return ""


def phase_for_target(name: str) -> str:
    audit_state = target_dir(name) / "audit-state.md"
    if audit_state.exists():
        for line in audit_state.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("- Phase:"):
                value = line.split(":", 1)[1].strip()
                return value or "env_not_ready"
    for row in registry_rows():
        if row.get("name") == slugify(name):
            return row.get("phase", "") or "env_not_ready"
    return "env_not_ready"


def set_target_phase(name: str, phase: str, next_action_text: str = "") -> None:
    slug = slugify(name)
    if phase not in TARGET_PHASES:
        raise ValueError(f"unknown phase: {phase}")
    out = target_dir(slug)
    state = out / "audit-state.md"
    if state.exists():
        lines = state.read_text(encoding="utf-8", errors="ignore").splitlines()
        updated_lines: list[str] = []
        saw_phase = False
        saw_next = False
        for line in lines:
            if line.startswith("- Phase:"):
                updated_lines.append(f"- Phase: {phase}")
                saw_phase = True
            elif next_action_text and line.startswith("- Current next action:"):
                updated_lines.append(f"- Current next action: {next_action_text}")
                saw_next = True
            else:
                updated_lines.append(line)
        if not saw_phase:
            updated_lines.append(f"- Phase: {phase}")
        if next_action_text and not saw_next:
            updated_lines.append(f"- Current next action: {next_action_text}")
        state.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    set_registry_field(slug, phase=phase, next_action=next_action_text)


def set_registry_field(name: str, **fields: str) -> None:
    rows = registry_rows()
    slug = slugify(name)
    found = False
    for row in rows:
        if row.get("name") == slug:
            row.update(fields)
            found = True
            break
    if not found:
        base = {
            "name": slug,
            "family": "",
            "repo_path": "",
            "authorization": "",
            "phase": fields.get("phase", "env_not_ready"),
            "priority": "",
            "status": "active",
            "next_action": fields.get("next_action", ""),
            "notes": "",
        }
        base.update(fields)
        rows.append(base)
    save_registry(rows)


def detect_toolchain(repo: Path) -> list[str]:
    commands: list[str] = []
    if (repo / "foundry.toml").exists():
        commands.extend(["forge build", "forge test"])
    if (repo / "hardhat.config.ts").exists() or (repo / "hardhat.config.js").exists():
        if (repo / "pnpm-lock.yaml").exists():
            commands.append("pnpm test")
        elif (repo / "yarn.lock").exists():
            commands.append("yarn test")
        else:
            commands.append("npm test")
    if (repo / "Anchor.toml").exists():
        commands.append("anchor test")
    if (repo / "Cargo.toml").exists():
        commands.append("cargo test")
    if not commands:
        commands.append("inspect repository toolchain and run the smallest build/test command")
    return commands


def agent_prompt_text(name: str, repo_path: str) -> str:
    safe_name = slugify(name)
    out = target_dir(safe_name)
    return f"""# Subagent Prompts - {safe_name}

Use only authorized/local defensive review. Keep PoCs local: unit tests,
invariants, fuzz harnesses, or read-only fork simulations. Do not provide live
fund movement or third-party exploitation instructions.

The framework and existing prompts are starting points, not limits. If the
current workflow misses a protocol-specific risk, propose or create local
framework, script, template, harness, scanner, or skill-evolution updates.

Repo/path: {repo_path or "TBD"}
Target workspace: {out}

Every final subagent output must include:

- role
- files_reviewed
- candidate_ids
- evidence_refs
- confidence
- next_validation
- false_positive_filters
- changed_files
- framework_or_skill_evolution_needed
- creative_hypotheses

## Scope Mapper

Confirm authorization, repo, commit, in-scope files/contracts, out-of-scope
areas, test command, and obvious exclusions.

Output to: `{out / "scope.md"}` and `{out / "notes/repo-commits.md"}`

## Value-Flow Auditor

Follow funds across deposit, mint, borrow, swap, oracle update, fee accrual,
liquidation, claim, redeem, withdraw, pause, cancel, and emergency paths.

Output to: `{out / "protocol-map.md"}` and `{out / "attack-lines.md"}`

## Accounting Auditor

Inspect share, LP, debt, reward, fee, interest, rounding, decimal, donation,
first-deposit, and dust logic.

Output candidates to: `{out / "candidates.tsv"}`

## Oracle And Economic Auditor

Inspect oracle adapters, TWAPs, stale/fallback behavior, quote direction,
liquidation thresholds, sequencer assumptions, and economic reachability.

Output candidates to: `{out / "candidates.tsv"}`

## Invariant Designer

Turn protocol properties into Foundry, Echidna, Medusa, Proptest, Anchor, or
LiteSVM invariants using the repo's existing test style.

Output plans to: `{out / "poc"}`

## Validator

Convert top candidates into minimal local PoCs or disprove them. A confirmed
finding requires a reproducible command and saved evidence.

Output to: `{out / "findings.tsv"}`, `{out / "findings"}`, and `{out / "logs"}`

## Skill Evolution Reviewer

Record which workflow elements helped, failed, or should become reusable. If a
new script, prompt, harness, invariant template, scanner rule, or skill update
is useful, describe the exact change and how it should be validated.

Output to: `{out / "skill-evolution.md"}`

## Novelty Hunter

Use CREATIVE_DISCOVERY.md. Generate protocol-specific hypotheses that are not
direct copies of common checklists. Focus on protocol promises, weird but legal
states, order perturbations, unit-boundary mismatches, honest-but-surprising
dependencies, and negative-space checks.

Output to: `{out / "creative-hypotheses.md"}` and candidate proposals.

## Adversarial Reviewer

Attack the audit plan itself. Look for skipped files, prematurely dismissed
scanner hits, weak false-positive assumptions, untested config extremes,
unmodeled dependencies, and missing invariants.

Output to: `{out / "attack-lines.md"}` and `{out / "skill-evolution.md"}`
"""


def init_target(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    repo_path = args.repo or ""
    repo = Path(repo_path).expanduser().resolve() if repo_path else Path("")
    out = target_dir(name)
    for rel in ["findings", "poc", "logs", "notes", "agents", "invariants", "scans", "reports"]:
        (out / rel).mkdir(parents=True, exist_ok=True)

    commands = detect_toolchain(repo) if repo_path and repo.exists() else ["TBD: inspect repository toolchain"]

    write_if_missing(
        out / "README.md",
        f"""# {name}

Local audit workspace for `{name}`.

Completion target: confirmed vulnerability with local PoC.

Use:

```bash
python3 {ROOT / "scripts/auditctl.py"} status {name}
python3 {ROOT / "scripts/auditctl.py"} next {name}
python3 {ROOT / "scripts/auditctl.py"} agents {name}
```
""",
    )
    write_if_missing(
        out / "audit-state.md",
        f"""# Audit State

- Project: {name}
- Repo path: {repo_path or "TBD"}
- Family: {args.family or "TBD"}
- Authorization: {args.authorization or "TBD"}
- Phase: env_not_ready
- Status: active
- Priority: {args.priority}
- Created: {now()}
- Completion target: confirmed vulnerability with local PoC
- Current next action: establish scope, authorization, repo commit, and baseline command

## Phase State Machine

- env_not_ready: toolchain and baseline command not proven yet
- baseline_ready: smallest reliable build/test command is known
- protocol_mapped: value flow, assets, roles, oracle, and accounting map exists
- candidate_queue_ready: candidates are ranked and ready for validation
- poc_validation_active: at least one candidate is being converted into a local PoC
- confirmed_or_exhausted: confirmed finding exists or the target is explicitly paused/exhausted
""",
    )
    write_if_missing(
        out / "scope.md",
        f"""# Scope

- Authorization statement: {args.authorization or "TBD"}
- Project owner/authorized reviewer: TBD
- Repo/path: {repo_path or "TBD"}
- Commit: TBD
- In-scope contracts/modules: TBD
- Out-of-scope areas: TBD
- Allowed PoC environment: local tests, fuzz/invariant harnesses, or read-only fork simulation
- Disallowed actions: live exploitation, real fund movement, public disclosure before clearance
""",
    )
    write_if_missing(
        out / "protocol-map.md",
        """# Protocol Map

## Runtime And Toolchain

- Chain/runtime: TBD
- Test framework: TBD

## Assets And Accounting Units

- Assets: TBD
- Shares/LP/debt/reward units: TBD

## Value Flows

- Deposit/mint:
- Swap/borrow:
- Oracle update:
- Fee/reward accrual:
- Liquidation/settlement:
- Withdraw/redeem:
- Admin/emergency:

## Trust Boundaries

- External calls:
- Oracles:
- Routers:
- Hooks/callbacks:
- Privileged roles:
""",
    )
    write_if_missing(
        out / "attack-lines.md",
        """# Attack Lines

Rank only a few high-signal lines at a time. Scanner hits are not findings.

| Rank | State | Attack line | Property | Why now | Validation plan | Next action |
|---:|---|---|---|---|---|---|
""",
    )
    write_tsv(out / "candidates.tsv", CANDIDATE_FIELDS, read_tsv(out / "candidates.tsv"))
    write_tsv(out / "findings.tsv", FINDING_FIELDS, read_tsv(out / "findings.tsv"))
    write_if_missing(out / "evidence-index.jsonl", "")
    write_if_missing(out / "lessons.jsonl", "")
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "target_initialized",
            "target": name,
            "repo_path": repo_path or "",
            "phase": "env_not_ready",
            "authorization": args.authorization or "",
            "conclusion": "workspace initialized; not evidence of vulnerability",
        },
    )
    write_if_missing(
        out / "hypotheses.md",
        """# Hypotheses

Use this file for longer-form reasoning. Keep machine-readable state in
`candidates.tsv`.
""",
    )
    write_if_missing(
        out / "skill-evolution.md",
        """# Skill Evolution

Record lessons that should become reusable framework, skill, script, template,
or false-positive filter changes.

| Date | Lesson | Proposed change | Applied? |
|---|---|---|---|
""",
    )
    write_if_missing(
        out / "notes/commands.md",
        "# Commands\n\nRecord exact commands and key output here.\n\n" + "\n".join(f"- `{cmd}`" for cmd in commands) + "\n",
    )
    write_if_missing(
        out / "notes/repo-commits.md",
        """# Repository Commits

| Repo | Remote | Commit | Scope note |
|---|---|---|---|
""",
    )
    (out / "agents/agent-prompts.md").write_text(agent_prompt_text(name, repo_path), encoding="utf-8")

    upsert_registry(
        {
            "name": name,
            "family": args.family or "",
            "repo_path": repo_path,
            "authorization": args.authorization or "",
            "phase": "env_not_ready",
            "priority": str(args.priority),
            "status": "active",
            "next_action": "establish scope and baseline",
            "notes": args.notes or "",
        }
    )
    print(f"Initialized target: {out}")
    return 0


def is_repo_like(path: Path) -> bool:
    markers = [
        ".git",
        "foundry.toml",
        "hardhat.config.ts",
        "hardhat.config.js",
        "Anchor.toml",
        "Cargo.toml",
        "package.json",
        "brownie-config.yaml",
        "ape-config.yaml",
    ]
    return any((path / marker).exists() for marker in markers)


def iter_repo_candidates(root: Path, max_depth: int) -> list[Path]:
    root = root.resolve()
    repos: list[Path] = []
    seen: set[Path] = set()

    def walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if path.name in DISCOVERY_SKIP_DIRS and path != root:
            return
        if is_repo_like(path):
            resolved = path.resolve()
            if resolved not in seen:
                repos.append(path)
                seen.add(resolved)
            if path != root:
                return
        try:
            children = sorted(child for child in path.iterdir() if child.is_dir())
        except OSError:
            return
        for child in children:
            if child.name in DISCOVERY_SKIP_DIRS:
                continue
            walk(child, depth + 1)

    walk(root, 0)
    return repos


def count_source_files(repo: Path, limit: int = 5000) -> tuple[int, int, str]:
    source_count = 0
    test_dirs = 0
    sample_parts: list[str] = [repo.name.lower()]
    for path in repo.rglob("*"):
        if any(part in DISCOVERY_SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir() and path.name in {"test", "tests", "spec", "integration"}:
            test_dirs += 1
            continue
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        source_count += 1
        if source_count <= 80:
            rel = str(path.relative_to(repo)).lower()
            sample_parts.append(rel)
            try:
                sample_parts.append(path.read_text(encoding="utf-8", errors="ignore")[:600].lower())
            except OSError:
                pass
        if source_count >= limit:
            break
    return source_count, test_dirs, "\n".join(sample_parts)


def detect_toolchains(repo: Path) -> list[str]:
    toolchains: list[str] = []
    if (repo / "foundry.toml").exists():
        toolchains.append("foundry")
    if (repo / "hardhat.config.ts").exists() or (repo / "hardhat.config.js").exists():
        toolchains.append("hardhat")
    if (repo / "Anchor.toml").exists():
        toolchains.append("anchor")
    if (repo / "Cargo.toml").exists():
        toolchains.append("rust")
    if (repo / "package.json").exists():
        toolchains.append("node")
    if (repo / "certora").exists():
        toolchains.append("certora")
    return toolchains or ["unknown"]


def classify_family(sample: str) -> tuple[str, int, list[str], str]:
    override = family_override(sample)
    if override:
        return override
    best_family = "generic-defi"
    best_base = 45
    best_hits: list[str] = []
    best_focus = "map value flow, identify accounting units, then run high-signal scanner"
    for family, base, keywords, focus in FAMILY_RULES:
        hits = [keyword for keyword in keywords if keyword_hit(sample, keyword)]
        if not hits:
            continue
        rank = base + min(len(hits), 8) * 2
        if rank > best_base:
            best_family = family
            best_base = rank
            best_hits = hits[:12]
            best_focus = focus
    return best_family, best_base, best_hits, best_focus


def family_override(sample: str) -> tuple[str, int, list[str], str] | None:
    return None


def keyword_hit(sample: str, keyword: str) -> bool:
    lowered = keyword.lower()
    if " " in lowered or "-" in lowered:
        return lowered in sample
    if len(lowered) <= 3:
        return re.search(rf"(?<![a-z0-9]){re.escape(lowered)}(?![a-z0-9])", sample) is not None
    return lowered in sample


def repo_signature(result: DiscoveryResult) -> str:
    return result.name


def dedupe_results(results: list[DiscoveryResult]) -> list[DiscoveryResult]:
    best: dict[str, DiscoveryResult] = {}
    for result in results:
        signature = repo_signature(result)
        current = best.get(signature)
        if current is None or result.score > current.score or result.source_files > current.source_files:
            best[signature] = result
    return list(best.values())


def score_repo(repo: Path) -> DiscoveryResult:
    toolchains = detect_toolchains(repo)
    source_count, test_dirs, sample = count_source_files(repo)
    family, base_score, hits, focus = classify_family(sample)
    score = int(base_score * 0.62)
    if "foundry" in toolchains:
        score += 7
    if "hardhat" in toolchains:
        score += 5
    if "anchor" in toolchains or "rust" in toolchains:
        score += 6
    if test_dirs:
        score += min(test_dirs, 4) * 2
    if source_count >= 20:
        score += 4
    if source_count >= 150:
        score += 3
    if source_count >= 700:
        score += 2
    if "certora" in toolchains:
        score += 2
    if family in {"modular-lending", "perps-async-orders", "fixed-maturity-yield", "lending-vault"}:
        score += 7
    if family == "generic-defi":
        score -= 5
    if "node_modules" in str(repo):
        score -= 20
    reason = []
    reason.append(f"family={family}")
    reason.append(f"toolchains={'+'.join(toolchains)}")
    reason.append(f"source_files={source_count}")
    if hits:
        reason.append("signals=" + ",".join(hits[:8]))
    return DiscoveryResult(
        name=slugify(repo.name),
        path=repo.resolve(),
        family=family,
        score=max(0, min(score, 100)),
        toolchains=toolchains,
        source_files=source_count,
        test_dirs=test_dirs,
        signals=hits,
        next_focus=focus,
        reason="; ".join(reason),
    )


def discovery_csv_path() -> Path:
    return TARGETS / "discovered-targets.csv"


def write_discovery_csv(path: Path, results: list[DiscoveryResult]) -> None:
    fieldnames = [
        "name",
        "score",
        "family",
        "repo_path",
        "toolchains",
        "source_files",
        "test_dirs",
        "signals",
        "next_focus",
        "reason",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "name": result.name,
                    "score": result.score,
                    "family": result.family,
                    "repo_path": str(result.path),
                    "toolchains": "+".join(result.toolchains),
                    "source_files": result.source_files,
                    "test_dirs": result.test_dirs,
                    "signals": ",".join(result.signals),
                    "next_focus": result.next_focus,
                    "reason": result.reason,
                }
            )


def write_discovery_markdown(path: Path, results: list[DiscoveryResult]) -> None:
    lines = [
        "# DeFi Target Discovery",
        "",
        f"Generated: {now()}",
        "",
        "Scores prioritize local runnability, rich value flow, useful test surface, and high-signal audit families. Scanner hits are not vulnerabilities.",
        "",
        "| Rank | Score | Target | Family | Toolchain | Source files | Signals | Next focus |",
        "|---:|---:|---|---|---|---:|---|---|",
    ]
    for rank, result in enumerate(results, start=1):
        signals = ", ".join(result.signals[:6]) or "-"
        lines.append(
            f"| {rank} | {result.score} | {result.name} | {result.family} | "
            f"{'+'.join(result.toolchains)} | {result.source_files} | {signals} | {result.next_focus} |"
        )
    lines.append("")
    lines.append("## Next Use")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 scripts/auditctl.py recommend")
    lines.append("python3 scripts/auditctl.py import-discovered --top 5 --authorization user-owned")
    lines.append("python3 scripts/auditctl.py queue")
    lines.append("```")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def discover(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(f"missing root: {root}", file=sys.stderr)
        return 1
    repos = iter_repo_candidates(root, args.max_depth)
    results = [score_repo(repo) for repo in repos]
    if not args.no_dedupe:
        results = dedupe_results(results)
    if args.min_score:
        results = [result for result in results if result.score >= args.min_score]
    results.sort(key=lambda item: (-item.score, item.name))
    if args.limit:
        results = results[: args.limit]
    csv_path = Path(args.out).expanduser().resolve() if args.out else discovery_csv_path()
    md_path = csv_path.with_suffix(".md")
    write_discovery_csv(csv_path, results)
    write_discovery_markdown(md_path, results)
    print(f"discovered targets: {len(results)}")
    print(f"csv: {csv_path}")
    print(f"map: {md_path}")
    for rank, result in enumerate(results[: args.show], start=1):
        print(f"{rank}. {result.name} score={result.score} family={result.family} repo={result.path}")
    return 0


def read_discovery(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def recommend(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser().resolve() if args.file else discovery_csv_path()
    rows = read_discovery(path)
    if not rows:
        print(f"No discovery file found or file is empty: {path}")
        print(f"Run: python3 {ROOT / 'scripts/auditctl.py'} discover --root .")
        return 0
    rows.sort(key=lambda row: int(row.get("score") or "0"), reverse=True)
    rows = rows[: args.top]
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    print("# Recommended DeFi Targets")
    print("| Rank | Score | Target | Family | Toolchain | Next focus |")
    print("|---:|---:|---|---|---|---|")
    for rank, row in enumerate(rows, start=1):
        print(
            f"| {rank} | {row.get('score')} | {row.get('name')} | {row.get('family')} | "
            f"{row.get('toolchains')} | {row.get('next_focus')} |"
        )
    return 0


def import_discovered(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser().resolve() if args.file else discovery_csv_path()
    rows = read_discovery(path)
    if not rows:
        print(f"No discovery file found or file is empty: {path}", file=sys.stderr)
        return 1
    rows.sort(key=lambda row: int(row.get("score") or "0"), reverse=True)
    imported = 0
    for row in rows[: args.top]:
        name = row.get("name") or ""
        repo_path = row.get("repo_path") or ""
        if not name or not repo_path:
            continue
        init_args = argparse.Namespace(
            name=name,
            repo=repo_path,
            family=row.get("family") or "",
            authorization=args.authorization,
            priority=max(1, min(5, 6 - (int(row.get("score") or "0") // 20))),
            notes=f"discovered score={row.get('score')}; {row.get('reason')}",
        )
        init_target(init_args)
        out = target_dir(name)
        append_jsonl(
            out / "evidence-index.jsonl",
            {
                "time": now(),
                "type": "target_discovered",
                "target": name,
                "repo_path": repo_path,
                "score": row.get("score"),
                "family": row.get("family"),
                "signals": row.get("signals"),
                "conclusion": "target imported for authorized local audit; not vulnerability evidence",
            },
        )
        imported += 1
    print(f"imported targets: {imported}")
    return 0


def family_for_target(name: str) -> str:
    slug = slugify(name)
    for row in registry_rows():
        if row.get("name") == slug:
            return row.get("family") or "generic-defi"
    return "generic-defi"


def pattern_for_candidate(row: dict[str, str]) -> str:
    explicit = str(row.get("pattern") or "").strip().lower()
    if explicit:
        return explicit
    text = " ".join(str(row.get(key) or "") for key in ["id", "title", "validation_plan"]).lower()
    for pattern in PATTERN_META:
        normalized = pattern.replace("-", "_")
        if pattern in text or normalized in text:
            return pattern
    title = str(row.get("title") or "").lower()
    if "signed oracle" in title:
        return "signed-oracle-to-unsigned-cast"
    if "composed oracle" in title or "sub-feed" in title or "composition" in title:
        return "oracle-composition-signed-cast"
    if "maturity" in title or "checkpoint" in title:
        return "bounded-maturity-loop"
    if "erc4626" in title:
        if "trusted" in title or "dependency" in title:
            return "trusted-erc4626-oracle-dependency"
        return "untrusted-erc4626-value-conversion"
    if "router residue" in title or "fresh output" in title:
        return "full-balance-after-external-call"
    if "freshness" in title or "oracle" in title:
        return "oracle-freshness-surface"
    if "preview" in title:
        return "preview-action-pair"
    if "admin" in title:
        return "admin-parameter-domain"
    return "unknown"


def rank_value(row: dict[str, str], family: str) -> int:
    pattern = pattern_for_candidate(row)
    family_weights = FAMILY_CANDIDATE_WEIGHTS.get(family, {})
    value = family_weights.get(pattern, int(row.get("priority") or "9") * 10)
    code_path = row.get("code_path", "").lower()
    evidence = row.get("evidence", "").lower()
    if "/interfaces/" in code_path or code_path.startswith("interfaces/"):
        value += 12
    if "utils/" in code_path or code_path.endswith(".ts:"):
        value += 4
    if "mock" in code_path or "example" in code_path:
        value += 20
    if "oracle" in code_path and family in {"lending-vault", "perps-async-orders", "modular-lending"}:
        value -= 3
    if pattern == "signed-oracle-to-unsigned-cast" and "positive guard confirmed" in evidence:
        value += 35
    if pattern == "oracle-composition-signed-cast" and any(token in code_path for token in ["pricefeeddouble", "pricefeedwrapper", "oracle"]):
        value -= 4
    if pattern == "untrusted-erc4626-value-conversion" and any(
        token in evidence for token in [
            "constructor_bound_or_addressbook_dependency",
            "address-book",
            "address book",
            "immutable trusted",
            "fixed dependency",
        ]
    ):
        value += 28
    if pattern == "trusted-erc4626-oracle-dependency" and any(token in code_path for token in ["oracle", "adapter", "price"]):
        value -= 2
    if "market" in code_path and family in {"fixed-maturity-yield", "perps-async-orders"}:
        value -= 2
    return max(1, value)


def rank_candidates(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    path = out / "candidates.tsv"
    with file_lock(path):
        rows = read_tsv(path)
        if not rows:
            print(f"No candidates found: {path}")
            return 0
        family = args.family or family_for_target(name)
        ranked: list[tuple[int, dict[str, str]]] = []
        for row in rows:
            value = rank_value(row, family)
            row["priority"] = str(max(1, min(5, (value + 9) // 10)))
            row["next_action"] = row.get("next_action") or "inspect consuming path and write local validation test"
            evidence = row.get("evidence", "")
            note = f"ranked for family={family}; rank_value={value}"
            if note not in evidence:
                row["evidence"] = (evidence + " | " + note).strip(" |")
            ranked.append((value, row))
        ranked.sort(key=lambda item: (item[0], item[1].get("id", "")))
        write_tsv(path, CANDIDATE_FIELDS, [row for _, row in ranked])
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "candidate_rerank",
            "target": name,
            "family": family,
            "candidate_count": len(rows),
            "top_candidate": ranked[0][1].get("id") if ranked else "",
            "conclusion": "candidate queue reranked by protocol-family heuristics; not vulnerability evidence",
        },
    )
    top = ranked[0][1]
    print(f"reranked candidates: {len(rows)}")
    print(f"family: {family}")
    print(f"top: {top.get('id')} - {top.get('title')}")
    return 0


def split_code_path(code_path: str) -> tuple[str, int]:
    if ":" not in code_path:
        return code_path, 0
    rel, raw_line = code_path.rsplit(":", 1)
    try:
        return rel, int(raw_line)
    except ValueError:
        return code_path, 0


def text_index_at_line(text: str, line_no: int) -> int:
    if line_no <= 1:
        return 0
    index = 0
    for _ in range(line_no - 1):
        next_index = text.find("\n", index)
        if next_index == -1:
            return len(text)
        index = next_index + 1
    return index


def nearest_contract_name(text: str) -> str:
    match = re.search(r"\bcontract\s+([A-Za-z_]\w*)", text)
    return match.group(1) if match else ""


def in_constructor_context(text: str, line_no: int) -> bool:
    index = text_index_at_line(text, line_no)
    before = text[:index]
    last_constructor = before.rfind("constructor")
    last_function = max(before.rfind("\nfunction "), before.rfind("\n    function "), before.rfind("\n  function "))
    return last_constructor != -1 and last_constructor > last_function


def erc4626_call_from_line(line: str) -> tuple[str, str]:
    match = re.search(
        r"\b(?:IERC4626|ERC4626|IShareToken|IVault)\s*\(\s*([^)]+?)\s*\)\s*\.\s*"
        r"(asset|convertToAssets|convertToShares)\s*\(",
        line,
    )
    if not match:
        return "", ""
    receiver = re.sub(r"\s+", "", match.group(1))
    return receiver, match.group(2)


def receiver_is_fixed_dependency(text: str, receiver: str) -> bool:
    if not receiver:
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_\.]*", receiver):
        return True
    if re.search(rf"\b(?:address\s+)?public\s+immutable\s+{re.escape(receiver)}\b", text):
        return True
    if re.search(rf"\b[A-Z][A-Z0-9_]*\s*=\s*{re.escape(receiver)}\s*;", text):
        return True
    return False


def addressbook_deploy_hint(repo: Path, contract_name: str) -> str:
    if not contract_name:
        return ""
    checked = 0
    for path in repo.rglob("*.sol"):
        if checked > 250:
            break
        if any(part in {".git", "node_modules", "out", "cache", "artifacts", "test", "tests"} for part in path.parts):
            continue
        path_text = str(path.relative_to(repo)).lower()
        if "deploy" not in path_text and "script" not in path_text:
            continue
        checked += 1
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if f"new {contract_name}" in raw and ("AddrKey." in raw or "getAddress(" in raw):
            return f"{path.relative_to(repo)} deploys {contract_name} from address-book/config inputs"
    return ""


def triage_candidate_rule(name: str, row: dict[str, str]) -> dict[str, str]:
    if pattern_for_candidate(row) != "untrusted-erc4626-value-conversion":
        return {}
    repo_raw = repo_for_target(name)
    if not repo_raw:
        return {}
    repo = Path(repo_raw).expanduser().resolve()
    rel, line_no = split_code_path(row.get("code_path", ""))
    source_path = repo / rel
    if not source_path.exists() or line_no <= 0:
        return {}
    try:
        text = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}
    lines = text.splitlines()
    if line_no > len(lines):
        return {}
    snippet = lines[line_no - 1].strip()
    receiver, method = erc4626_call_from_line(snippet)
    if not receiver or not method:
        return {}

    if method == "asset" and in_constructor_context(text, line_no):
        return {
            "candidate_id": row.get("id", ""),
            "state": "false positive",
            "priority": "5",
            "impact": "No direct value-conversion impact: constructor-only ERC4626 asset() metadata initialization.",
            "validation_plan": "Disproved by source review; do not use fake ERC4626 PoC unless a public path accepts attacker-controlled receivers.",
            "next_action": "Do not pursue this untrusted ERC4626 framing.",
            "evidence": (
                f"triage-candidates: {row.get('code_path')} is constructor asset() metadata call; "
                "skip as value-conversion candidate"
            ),
            "reason": "constructor_asset_metadata",
        }

    if method in {"convertToAssets", "convertToShares"} and receiver_is_fixed_dependency(text, receiver):
        contract_name = nearest_contract_name(text)
        deploy_hint = addressbook_deploy_hint(repo, contract_name)
        evidence = (
            f"triage-candidates: {row.get('code_path')} calls {method} on fixed receiver {receiver}; "
            "untrusted fake-vault framing is not proven"
        )
        if deploy_hint:
            evidence += f"; {deploy_hint}"
        return {
            "candidate_id": row.get("id", ""),
            "state": "false positive",
            "priority": "5",
            "impact": "Untrusted ERC4626 receiver framing is disproved; receiver appears fixed/immutable, so only dependency-risk remains.",
            "validation_plan": "Reclassify as trusted ERC4626 dependency only if the fixed dependency can enter a bad state in scope and reaches risk logic.",
            "next_action": "Prefer a trusted-erc4626-oracle-dependency candidate; do not use a fake receiver PoC as proof.",
            "evidence": evidence,
            "reason": "fixed_erc4626_dependency",
            "suggested_pattern": "trusted-erc4626-oracle-dependency",
        }

    return {}


def triage_candidates(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    path = out / "candidates.tsv"
    rows = read_tsv(path)
    suggestions: list[dict[str, str]] = []
    for row in rows:
        if row.get("state") not in {"suspected", "plausible but unproven", "test written", "tested failed/security relevant"}:
            continue
        suggestion = triage_candidate_rule(name, row)
        if suggestion:
            suggestions.append(suggestion)

    if args.json:
        print(json.dumps(suggestions, indent=2, ensure_ascii=False))
    else:
        if not suggestions:
            print("No automatic triage suggestions.")
        else:
            print("# Candidate Triage Suggestions")
            print("| Candidate | Suggested state | Reason | Next |")
            print("|---|---|---|---|")
            for item in suggestions:
                print(
                    f"| {item.get('candidate_id')} | {item.get('state')} | "
                    f"{item.get('reason')} | {item.get('next_action')} |"
                )

    if not args.apply or not suggestions:
        return 0

    by_id = {item["candidate_id"]: item for item in suggestions}
    with file_lock(path):
        rows = read_tsv(path)
        for row in rows:
            item = by_id.get(row.get("id", ""))
            if not item:
                continue
            for field in ["state", "priority", "impact", "validation_plan", "next_action"]:
                if item.get(field):
                    row[field] = item[field]
            existing = row.get("evidence", "")
            row["evidence"] = (existing + " | " + item.get("evidence", "")).strip(" |")
        write_tsv(path, CANDIDATE_FIELDS, rows)

    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "candidate_auto_triage",
            "target": name,
            "candidate_ids": [item.get("candidate_id", "") for item in suggestions],
            "conclusion": "automatic false-positive filters applied; not vulnerability evidence",
        },
    )
    print(f"applied triage suggestions: {len(suggestions)}")
    return 0


@dataclass
class TargetSummary:
    name: str
    path: Path
    missing: list[str]
    candidate_counts: dict[str, int]
    finding_counts: dict[str, int]


@dataclass
class DiscoveryResult:
    name: str
    path: Path
    family: str
    score: int
    toolchains: list[str]
    source_files: int
    test_dirs: int
    signals: list[str]
    next_focus: str
    reason: str


def summarize(name: str) -> TargetSummary:
    out = target_dir(name)
    missing = [rel for rel in REQUIRED_TARGET_FILES if not (out / rel).exists()]
    candidate_counts = {state: 0 for state in CANDIDATE_STATES}
    for row in read_tsv(out / "candidates.tsv"):
        state = row.get("state", "").strip()
        candidate_counts[state] = candidate_counts.get(state, 0) + 1
    finding_counts: dict[str, int] = {}
    for row in read_tsv(out / "findings.tsv"):
        status = row.get("status", "").strip()
        finding_counts[status] = finding_counts.get(status, 0) + 1
    return TargetSummary(name=slugify(name), path=out, missing=missing, candidate_counts=candidate_counts, finding_counts=finding_counts)


def status(args: argparse.Namespace) -> int:
    names = [slugify(args.name)] if args.name else [row["name"] for row in registry_rows() if row.get("name")]
    if not names:
        print("No targets registered. Run: auditctl.py init <name> --repo <path>")
        return 0
    for name in names:
        summary = summarize(name)
        print(f"# {summary.name}")
        print(f"path: {summary.path}")
        if summary.missing:
            print("missing: " + ", ".join(summary.missing))
        else:
            print("missing: none")
        print("candidates:")
        for state in sorted(summary.candidate_counts):
            count = summary.candidate_counts[state]
            if count:
                print(f"- {state}: {count}")
        if not any(summary.candidate_counts.values()):
            print("- none")
        print("findings:")
        if summary.finding_counts:
            for key, value in sorted(summary.finding_counts.items()):
                print(f"- {key or 'blank'}: {value}")
        else:
            print("- none")
        evidence_count = len(read_jsonl(summary.path / "evidence-index.jsonl"))
        lesson_count = len(read_jsonl(summary.path / "lessons.jsonl"))
        print(f"evidence events: {evidence_count}")
        print(f"lessons: {lesson_count}")
        print()
    return 0


def next_action(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}")
        return 1

    confirmed_findings = [
        row for row in read_tsv(out / "findings.tsv")
        if "confirmed" in row.get("status", "").lower()
    ]
    confirmed_candidates = [
        row for row in read_tsv(out / "candidates.tsv")
        if row.get("state") == "confirmed with PoC"
    ]
    if confirmed_findings or confirmed_candidates:
        print("Next action: package confirmed finding immediately.")
        print(f"Command: open {out / 'findings.tsv'} and verify report/log/PoC paths.")
        return 0

    checks = [
        ("scope.md", "fill authorization, repo, commit, in-scope and out-of-scope rules"),
        ("notes/commands.md", "record and run the smallest reliable baseline build/test command"),
        ("protocol-map.md", "map assets, roles, value flows, accounting units, oracles, and trust boundaries"),
        ("creative-hypotheses.md", "generate creative discovery hypotheses before over-focusing on generic scanner hits"),
        ("attack-lines.md", "rank the top 3 attack lines from value flow and scanner hits"),
    ]
    for rel, action in checks:
        if sparse(out / rel):
            print(f"Next action: {action}")
            print(f"Reason: {rel} is missing or still template-like.")
            return 0

    candidates = read_tsv(out / "candidates.tsv")
    active = [
        row for row in candidates
        if row.get("state") in {"plausible but unproven", "suspected"}
    ]
    if active:
        active.sort(key=lambda row: int(row.get("priority") or "9"))
        top = active[0]
        print("Next action: validate highest-priority candidate with a local PoC.")
        print(f"Candidate: {top.get('id')} - {top.get('title')}")
        print(f"Validation plan: {top.get('validation_plan')}")
        print(f"Next: {top.get('next_action')}")
        return 0

    repo = repo_for_target(name)
    if repo:
        print("Next action: run scanner and promote only high-signal hits to suspected candidates.")
        print(f"Command: python3 {ROOT / 'scripts/auditctl.py'} scan {name}")
    else:
        print("Next action: attach a repo path or official in-scope source, then rerun init/status.")
    return 0


def agents(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    repo_path = repo_for_target(name)
    out = target_dir(name) / "agents/agent-prompts.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    text = agent_prompt_text(name, repo_path)
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"\nWrote: {out}")
    return 0


def creative_plan(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}", file=sys.stderr)
        return 1
    repo = repo_for_target(name) or "TBD"
    family = family_for_target(name)
    path = out / "creative-hypotheses.md"
    if path.exists() and not args.force:
        print(f"exists: {path}")
        print("Use --force to rewrite, or edit the existing file.")
        return 0
    lanes = [
        (
            "Protocol-specific promise breaking",
            "Write one unique promise this protocol makes, then design a local invariant that breaks if the promise is false.",
        ),
        (
            "Counterfactual state machine",
            "Construct a weird but legal state: partial init, stale nonzero oracle, dust position, paused/unqueued mix, cancelled residue, or expired maturity with pending value.",
        ),
        (
            "Order perturbation",
            "Take two or three safe operations and reorder them; compare final accounting state.",
        ),
        (
            "Unit-boundary mismatch",
            "Trace token decimals, share/assets, debt/interest, quote/base, signed/unsigned, raw/scaled, tick/liquidity, or epoch/maturity boundaries.",
        ),
        (
            "Honest-but-surprising dependency",
            "Use legal edge behavior from ERC20, ERC4626, oracle, router, callback, Solana account extension, or admin config extremes.",
        ),
        (
            "Negative-space audit",
            "Search for missing bounds, freshness, receiver binding, market binding, callback post-condition, conservation assertion, queue cleanup, or decimal normalization.",
        ),
        (
            "Scanner inversion",
            "Pick a boring scanner hit and inspect nearby cross-contract state, ordering, callback, rounding, queue, maturity, or deployment reachability that the scanner cannot model.",
        ),
    ]
    lines = [
        f"# Creative Hypotheses - {name}",
        "",
        f"- Target: {name}",
        f"- Family: {family}",
        f"- Repo: {repo}",
        f"- Generated: {now()}",
        "",
        "Use this file after baseline mapping. Do not promote any hypothesis to a finding without local evidence.",
        "",
        "## Working Rule",
        "",
        "Most obvious bugs have probably been scanned. Prefer protocol-specific, state-machine, ordering, unit-boundary, dependency, and negative-space hypotheses over generic checklist hits.",
        "",
        "## Hypothesis Table",
        "",
        "| ID | Lane | Hypothesis | Protocol promise challenged | Code path | Weird state or sequence | Why common scanners may miss it | Local test idea | Fastest disproof | Candidate state |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for index, (lane, prompt) in enumerate(lanes, start=1):
        lines.append(
            f"| CREATIVE-{index:03d} | {lane} | {prompt} | TBD | TBD | TBD | TBD | TBD | TBD | suspected |"
        )
    lines.extend(
        [
            "",
            "## Next Commands",
            "",
            "```bash",
            f"python3 scripts/auditctl.py agents {name}",
            f"python3 scripts/auditctl.py ensure-candidate {name} CREATIVE-001 --state suspected --title \"<hypothesis title>\" --validation-plan \"<local test idea>\"",
            f"python3 scripts/auditctl.py evolve {name} --lesson \"Creative discovery found a protocol-specific missing invariant\" --proposed-change \"Add a reusable invariant or scanner rule after validation\"",
            "```",
            "",
            "## Notes",
            "",
            "- Keep creative hypotheses private and local.",
            "- Record false positives with the disproof path.",
            "- Convert the best hypothesis into a minimal local PoC or invariant.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "creative_plan_generated",
            "target": name,
            "family": family,
            "path": str(path),
            "conclusion": "creative discovery worksheet generated; not vulnerability evidence",
        },
    )
    print(f"creative plan: {path}")
    return 0


def run_scanner(repo: Path, out_json: Path, max_per_pattern: int) -> int:
    scanner = ORCH_SKILL / "scripts/scan_high_signal_patterns.py"
    if not scanner.exists():
        print(f"missing scanner: {scanner}", file=sys.stderr)
        return 1
    cmd = [
        sys.executable,
        str(scanner),
        str(repo),
        "--json",
        "--max-per-pattern",
        str(max_per_pattern),
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    (out_json.with_suffix(".stderr.log")).write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode
    out_json.write_text(proc.stdout, encoding="utf-8")
    return 0


def promote_scan_hits(name: str, hits: list[dict[str, object]]) -> int:
    out = target_dir(name)
    path = out / "candidates.tsv"
    rows = read_tsv(path)
    existing_ids = {row.get("id") for row in rows}
    existing_paths = {(row.get("code_path"), row.get("title")) for row in rows}
    added = 0
    counters: dict[str, int] = {}
    for hit in hits:
        pattern = str(hit.get("pattern", ""))
        meta = PATTERN_META.get(pattern)
        if not meta:
            continue
        code_path = f"{hit.get('path')}:{hit.get('line')}"
        title = meta["title"]
        if (code_path, title) in existing_paths:
            continue
        counters[pattern] = counters.get(pattern, 0) + 1
        candidate_id = f"{slugify(name).upper()}-{pattern.upper().replace('-', '_')}-{counters[pattern]:03d}"
        while candidate_id in existing_ids:
            counters[pattern] += 1
            candidate_id = f"{slugify(name).upper()}-{pattern.upper().replace('-', '_')}-{counters[pattern]:03d}"
        evidence_note = f"scanner hit only at {code_path}; snippet={str(hit.get('snippet', ''))[:160]}"
        for key in ["trust_boundary_hint", "erc4626_receiver", "erc4626_method", "addressbook_deploy_hint"]:
            value = str(hit.get(key) or "")
            if value:
                evidence_note += f"; {key}={value}"
        false_filter = str(hit.get("false_positive_filter") or "")
        if false_filter:
            evidence_note += f"; false_positive_filter={false_filter}"
        trust_class = str(hit.get("trust_class") or hit.get("trust_boundary_hint") or "")
        source_expr = str(hit.get("source_expr") or hit.get("erc4626_receiver") or "")
        proof_gate = str(hit.get("proof_gate") or hit.get("gate") or meta["next"])
        autopilot_next = str(hit.get("autopilot_next_action") or meta["next"])
        rows.append(
            {
                "id": candidate_id,
                "state": "suspected",
                "priority": str(meta["priority"]),
                "title": title,
                "code_path": code_path,
                "pattern": pattern,
                "trust_class": trust_class,
                "source_expr": source_expr,
                "sink_path": str(hit.get("value_sink_hint") or ""),
                "property": meta["property"],
                "impact": "TBD after consuming-path validation",
                "proof_gate": proof_gate,
                "false_positive_filters": false_filter,
                "harness": str(hit.get("suggested_harness") or ""),
                "validation_plan": proof_gate,
                "autopilot_next_action": autopilot_next,
                "next_action": autopilot_next,
                "evidence": evidence_note,
            }
        )
        added += 1
    write_tsv(path, CANDIDATE_FIELDS, rows)
    return added


def scan(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    repo_raw = args.repo or repo_for_target(name)
    if not repo_raw:
        print("missing repo path; pass --repo or initialize target with --repo", file=sys.stderr)
        return 1
    repo = Path(repo_raw).expanduser().resolve()
    if not repo.is_dir():
        print(f"missing repo directory: {repo}", file=sys.stderr)
        return 1
    out_json = target_dir(name) / "scans/high-signal.json"
    rc = run_scanner(repo, out_json, args.max_per_pattern)
    if rc != 0:
        return rc
    hits = json.loads(out_json.read_text(encoding="utf-8"))
    added = promote_scan_hits(name, hits)
    append_jsonl(
        target_dir(name) / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "scanner_run",
            "target": name,
            "repo_path": str(repo),
            "command": f"{sys.executable} {ORCH_SKILL / 'scripts/scan_high_signal_patterns.py'} {repo} --json --max-per-pattern {args.max_per_pattern}",
            "exit_code": 0,
            "log_path": str(out_json),
            "hit_count": len(hits),
            "new_suspected_candidates": added,
            "conclusion": "scanner hits promoted only to suspected candidates; not confirmed vulnerabilities",
        },
    )
    if added:
        set_target_phase(name, "candidate_queue_ready", "validate highest-priority suspected candidate locally")
        rank_candidates(argparse.Namespace(name=name, family=""))
    print(f"scan hits: {len(hits)}")
    print(f"new suspected candidates: {added}")
    print(f"json: {out_json}")
    print(f"candidates: {target_dir(name) / 'candidates.tsv'}")
    return 0


def evolve(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}", file=sys.stderr)
        return 1
    path = out / "skill-evolution.md"
    proposal = args.proposed_change or "Add as reusable skill/framework lesson after validation."
    line = f"| {now()} | {args.lesson.strip()} | {proposal.strip()} | no |\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
    patch_dir = out / "skill-patches"
    patch_dir.mkdir(exist_ok=True)
    patch_file = patch_dir / f"{now().replace(':', '-')}-{name}.md"
    patch_file.write_text(
        f"""# Skill Evolution Proposal

- Target: {name}
- Lesson: {args.lesson.strip()}
- Proposed change: {proposal.strip()}
- Suggested destination: {args.skill or "defi-audit-orchestrator / defi-poc-pattern-hunter"}
- Status: proposal only; apply after the lesson is validated across at least one concrete audit path.
""",
        encoding="utf-8",
    )
    lesson_event = {
        "time": now(),
        "target": name,
        "lesson": args.lesson.strip(),
        "proposed_change": proposal.strip(),
        "suggested_skill": args.skill or "defi-audit-orchestrator / defi-poc-pattern-hunter",
        "validation_seen": False,
        "status": "proposal",
    }
    append_jsonl(out / "lessons.jsonl", lesson_event)
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "skill_evolution_lesson",
            "target": name,
            "conclusion": "framework lesson recorded; not vulnerability evidence",
            "lesson": args.lesson.strip(),
        },
    )
    print(f"updated: {path}")
    print(f"proposal: {patch_file}")
    return 0


def log_evidence(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}", file=sys.stderr)
        return 1
    payload = {
        "time": now(),
        "type": args.type,
        "target": name,
        "candidate_id": args.candidate_id or "",
        "command": args.command or "",
        "cwd": args.cwd or "",
        "exit_code": args.exit_code,
        "log_path": args.log_path or "",
        "repo_commit": args.repo_commit or "",
        "conclusion": args.conclusion or "",
    }
    append_jsonl(out / "evidence-index.jsonl", payload)
    print(f"logged evidence: {out / 'evidence-index.jsonl'}")
    return 0


def update_candidate(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    path = out / "candidates.tsv"
    if not path.exists():
        print(f"missing candidates file: {path}", file=sys.stderr)
        return 1
    candidate_id = args.candidate_id.strip()
    state = args.state.strip()
    if state and state not in CANDIDATE_STATES:
        print(f"unknown candidate state: {state}", file=sys.stderr)
        return 1

    with file_lock(path):
        rows = read_tsv(path)
        found = False
        for row in rows:
            if row.get("id") != candidate_id:
                continue
            found = True
            if state:
                row["state"] = state
            if args.priority:
                row["priority"] = str(args.priority)
            arg_map = {
                "title": "title",
                "code_path": "code_path",
                "pattern": "pattern",
                "trust_class": "trust_class",
                "source_expr": "source_expr",
                "sink_path": "sink_path",
                "property": "property",
                "impact": "impact",
                "proof_gate": "proof_gate",
                "false_positive_filters": "false_positive_filters",
                "harness": "harness",
                "validation_plan": "validation_plan",
                "autopilot_next_action": "autopilot_next_action",
                "next_action": "next_action",
            }
            for field, attr in arg_map.items():
                value = getattr(args, attr, "")
                if value:
                    row[field] = value
            if args.evidence:
                existing = row.get("evidence", "")
                row["evidence"] = (existing + " | " + args.evidence).strip(" |")
            break

        if not found:
            if not args.create:
                print(f"candidate not found: {candidate_id}", file=sys.stderr)
                return 1
            if not state:
                state = "suspected"
            row = {
                "id": candidate_id,
                "state": state,
                "priority": str(args.priority or 3),
                "title": args.title or "Manual candidate",
                "code_path": args.code_path or "",
                "pattern": args.pattern or "",
                "trust_class": args.trust_class or "",
                "source_expr": args.source_expr or "",
                "sink_path": args.sink_path or "",
                "property": args.property or "",
                "impact": args.impact or "TBD after consuming-path validation",
                "proof_gate": args.proof_gate or "",
                "false_positive_filters": args.false_positive_filters or "",
                "harness": args.harness or "",
                "validation_plan": args.validation_plan or "write a local validation test",
                "autopilot_next_action": args.autopilot_next_action or "",
                "next_action": args.next_action or "inspect consuming path and write local validation test",
                "evidence": args.evidence or "manual candidate; not vulnerability evidence",
            }
            rows.append(row)

        write_tsv(path, CANDIDATE_FIELDS, rows)
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "candidate_update",
            "target": name,
            "candidate_id": candidate_id,
            "state": state,
            "conclusion": args.evidence or "candidate state updated; validate completion gate separately",
        },
    )
    if state in {"plausible but unproven", "test written", "tested failed/security relevant"}:
        set_target_phase(name, "poc_validation_active", args.next_action or "continue local PoC validation")
    elif state == "confirmed with PoC":
        set_target_phase(name, "confirmed_or_exhausted", "package confirmed finding privately")
    print(f"updated candidate: {candidate_id}")
    print(f"candidates: {path}")
    return 0


def ensure_candidate(args: argparse.Namespace) -> int:
    args.create = True
    return update_candidate(args)


def top_active_candidate(name: str) -> dict[str, str]:
    out = target_dir(name)
    candidates = [
        row for row in read_tsv(out / "candidates.tsv")
        if row.get("state") in {"plausible but unproven", "test written", "tested failed/security relevant", "suspected"}
    ]
    candidates.sort(
        key=lambda row: (
            ACTIVE_STATE_ORDER.get(row.get("state", ""), 9),
            int(row.get("priority") or "9"),
            row.get("id", ""),
        )
    )
    return candidates[0] if candidates else {}


def autopilot_plan(args: argparse.Namespace) -> int:
    names = [slugify(args.name)] if args.name else [row["name"] for row in registry_rows() if row.get("name")]
    if not names:
        print("No targets registered.")
        return 0
    plans: list[dict[str, object]] = []
    for name in names[: args.limit]:
        out = target_dir(name)
        repo = repo_for_target(name)
        phase = phase_for_target(name)
        top = top_active_candidate(name)
        gaps: list[str] = []
        if sparse(out / "scope.md"):
            gaps.append("scope/commit/in-scope fields still need tightening")
        if sparse(out / "notes/commands.md"):
            gaps.append("baseline command record is still template-like")
        if sparse(out / "protocol-map.md"):
            gaps.append("protocol map is still template-like")
        if sparse(out / "creative-hypotheses.md"):
            gaps.append("creative discovery hypotheses are missing or template-like")
        if top:
            next_step = {
                "kind": "validate_candidate",
                "candidate_id": top.get("id", ""),
                "candidate_state": top.get("state", ""),
                "property": top.get("property", ""),
                "validation_plan": top.get("validation_plan", ""),
                "next_action": top.get("next_action", ""),
                "acceptance_gate": "update candidate only with local evidence; confirmed requires complete gate",
            }
        elif sparse(out / "scope.md"):
            next_step = {"kind": "fill_scope", "next_action": "fill scope, authorization, commit, and in-scope modules"}
        elif sparse(out / "notes/commands.md"):
            next_step = {"kind": "baseline", "next_action": "run and record the smallest reliable baseline command"}
        elif sparse(out / "protocol-map.md"):
            next_step = {"kind": "map_protocol", "next_action": "map value flow, assets, roles, oracle, accounting, and trust boundaries"}
        elif sparse(out / "creative-hypotheses.md"):
            next_step = {
                "kind": "creative_discovery",
                "next_action": f"python3 {ROOT / 'scripts/auditctl.py'} creative-plan {name}",
                "acceptance_gate": "at least three protocol-specific hypotheses with local validation or disproof paths",
            }
        elif repo:
            next_step = {"kind": "scan", "next_action": f"python3 {ROOT / 'scripts/auditctl.py'} scan {name}"}
        else:
            next_step = {"kind": "attach_repo", "next_action": "attach repo path before scanning"}
        plans.append(
            {
                "target": name,
                "phase": phase,
                "repo": repo,
                "gaps": gaps,
                "next_step": next_step,
                "completion_rule": "stop only after confirmed with PoC plus reproducible local evidence, or an explicit blocker",
            }
        )
    if args.json:
        print(json.dumps(plans, indent=2, ensure_ascii=False))
        return 0
    print("# Autopilot Plan")
    print()
    print("Completion rule: stop only after `confirmed with PoC` plus reproducible local evidence, or after an explicit blocker is recorded.")
    print()
    for plan in plans:
        print(f"## {plan['target']}")
        print(f"- phase: {plan['phase']}")
        print(f"- repo: {plan['repo'] or 'TBD'}")
        gaps = plan["gaps"]
        if gaps:
            print("- gaps: " + "; ".join(gaps))
        next_step = plan["next_step"]
        top_id = str(next_step.get("candidate_id", ""))
        if top_id:
            print(f"- top candidate: {top_id} ({next_step.get('candidate_state')})")
            print(f"- property: {next_step.get('property')}")
            print(f"- validation: {next_step.get('validation_plan')}")
            print("- command path: write local PoC, run it, then `log-evidence` and `update-candidate`.")
        else:
            print(f"- next: {next_step.get('next_action')}")
        print()
    return 0


def merge_agent(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}", file=sys.stderr)
        return 1
    payload: dict[str, object]
    if args.file:
        raw = Path(args.file).expanduser().read_text(encoding="utf-8", errors="ignore")
    else:
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        print("missing agent output JSON", file=sys.stderr)
        return 1
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"agent output must be JSON: {exc}", file=sys.stderr)
        return 1

    required = [
        "role",
        "files_reviewed",
        "candidate_ids",
        "evidence_refs",
        "confidence",
        "next_validation",
        "false_positive_filters",
        "changed_files",
        "framework_or_skill_evolution_needed",
        "creative_hypotheses",
    ]
    missing = [key for key in required if key not in payload]
    if missing:
        print("agent output missing fields: " + ", ".join(missing), file=sys.stderr)
        return 1

    append_jsonl(
        out / "agents/agent-outputs.jsonl",
        {
            "time": now(),
            "target": name,
            "payload": payload,
        },
    )
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "agent_output_merged",
            "target": name,
            "role": payload.get("role"),
            "candidate_ids": payload.get("candidate_ids"),
            "evidence_refs": payload.get("evidence_refs"),
            "conclusion": "subagent output recorded; candidate states unchanged unless update-candidate is run",
        },
    )
    print(f"merged agent output: {out / 'agents/agent-outputs.jsonl'}")
    return 0


def add_finding(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"Initialize target first: {name}", file=sys.stderr)
        return 1
    rows = read_tsv(out / "findings.tsv")
    found = False
    for row in rows:
        if row.get("id") != args.finding_id:
            continue
        row.update(
            {
                "status": args.status,
                "severity": args.severity,
                "affected": args.affected,
                "poc_command": args.poc_command,
                "report_path": args.report_path,
                "log_path": args.log_path,
                "summary": args.summary,
            }
        )
        found = True
        break
    if not found:
        rows.append(
            {
                "id": args.finding_id,
                "status": args.status,
                "severity": args.severity,
                "affected": args.affected,
                "poc_command": args.poc_command,
                "report_path": args.report_path,
                "log_path": args.log_path,
                "summary": args.summary,
            }
        )
    write_tsv(out / "findings.tsv", FINDING_FIELDS, rows)
    append_jsonl(
        out / "evidence-index.jsonl",
        {
            "time": now(),
            "type": "finding_update",
            "target": name,
            "finding_id": args.finding_id,
            "status": args.status,
            "command": args.poc_command,
            "log_path": args.log_path,
            "conclusion": args.summary,
        },
    )
    if "confirmed" in args.status.lower():
        set_target_phase(name, "confirmed_or_exhausted", "run complete gate and package confirmed finding")
    print(f"updated finding: {args.finding_id}")
    return 0


def event_text(event: dict[str, object]) -> str:
    return " ".join(str(value) for value in event.values()).lower()


def candidate_text(row: dict[str, str]) -> str:
    return " ".join(str(row.get(key) or "") for key in CANDIDATE_FIELDS).lower()


def candidate_evidence_text(row: dict[str, str]) -> str:
    return " ".join(
        str(row.get(key) or "")
        for key in [
            "pattern",
            "trust_class",
            "source_expr",
            "impact",
            "proof_gate",
            "false_positive_filters",
            "evidence",
        ]
    ).lower()


def related_evidence_events(name: str, candidate_id: str) -> list[dict[str, object]]:
    out = target_dir(name)
    return [
        event for event in read_jsonl(out / "evidence-index.jsonl")
        if str(event.get("candidate_id", "")) == candidate_id
    ]


def gate_status(passed: bool, weak: bool = False) -> str:
    if passed:
        return "passed"
    if weak:
        return "weak"
    return "missing"


def positive_local_poc_text(text: str) -> bool:
    positive_terms = [
        "local_poc=true",
        "confirmed local poc",
        "poc passed",
        "poc test passed",
        "invariant failure reproduced",
        "failing test reproduced",
        "forge test passed",
        "local test passed",
        "deterministic crash reproduced",
    ]
    negative_terms = [
        "blocked",
        "missing rpc",
        "env not found",
        "environment variable",
        "no vulnerability evidence",
        "compile succeeded",
        "test blocked",
        "integration_test_blocked",
    ]
    return any(term in text for term in positive_terms) and not any(term in text for term in negative_terms)


def positive_evidence(text: str, positive_terms: list[str], negative_terms: list[str]) -> bool:
    return any(term in text for term in positive_terms) and not any(term in text for term in negative_terms)


def risk_path_proven(text: str) -> bool:
    positive_terms = [
        "risk_path=true",
        "risk path reproduced",
        "risk path confirmed",
        "core risk consumer confirmed",
        "accountliquidity reached",
        "checkborrow reached",
        "checkborrow pass",
        "checkshortfall reached",
        "borrow capacity affected",
        "liquidation path confirmed",
        "solvency consumer confirmed",
        "withdrawal path confirmed",
        "share accounting affected",
    ]
    negative_terms = [
        "risk_path=false",
        "risk path not yet proven",
        "risk path not proven",
        "risk path not confirmed",
        "risk path still unproven",
        "needs risk",
        "prove the behavior",
        "tbd",
    ]
    return positive_evidence(text, positive_terms, negative_terms)


def deployment_reachability_proven(text: str, events: list[dict[str, object]]) -> bool:
    if any(
        str(event.get("type", "")).lower() in {"deployment_reachability", "config_reachability", "scope_reachability"}
        and int(event.get("exit_code") or 0) == 0
        for event in events
    ):
        return True
    positive_terms = [
        "deployment_reachability=true",
        "config_reachability=true",
        "scope_reachability=true",
        "core consumer confirmed",
        "market wiring confirmed",
        "enablemarket reached",
        "setpricefeed reached",
        "adapter wired to risk oracle",
        "deployed config reaches core consumer",
    ]
    negative_terms = [
        "not yet proven",
        "not proven",
        "not confirmed",
        "still unproven",
        "still need",
        "trace deployment",
        "tbd",
    ]
    return positive_evidence(text, positive_terms, negative_terms)


def build_candidate_gates(name: str, row: dict[str, str]) -> dict[str, object]:
    candidate_id = row.get("id", "")
    pattern = pattern_for_candidate(row)
    events = related_evidence_events(name, candidate_id)
    combined = candidate_text(row) + " " + " ".join(event_text(event) for event in events)
    evidence_combined = candidate_evidence_text(row) + " " + " ".join(event_text(event) for event in events)

    local_poc_events = [
        event for event in events
        if str(event.get("type", "")).lower() in {"poc_test", "confirmed_poc", "invariant_failure"}
        and int(event.get("exit_code") or 0) == 0
    ]
    local_poc = bool(local_poc_events) or positive_local_poc_text(evidence_combined)
    risk_path = risk_path_proven(evidence_combined)
    deployment_reachability = deployment_reachability_proven(evidence_combined, events)

    erc4626_receiver_classified = True
    erc4626_note = "not required for this pattern"
    erc4626_trust_boundary_passed = True
    erc4626_dependency_behavior_passed = True
    erc4626_fake_vault_only = False
    if pattern in {"untrusted-erc4626-value-conversion", "trusted-erc4626-oracle-dependency"}:
        user_control_terms = [
            "receiver_user_controlled=true",
            "attacker-controlled erc4626 accepted",
            "user-controlled erc4626 accepted",
            "public path accepts arbitrary erc4626",
            "factory path accepts arbitrary erc4626",
            "config path accepts arbitrary erc4626",
        ]
        trusted_terms = [
            "constructor_bound_or_addressbook_dependency",
            "address-book",
            "address book",
            "fixed address",
            "fixed dependency",
            "immutable trusted",
            "addrkey.",
            "trusted erc4626 dependency",
        ]
        erc4626_fake_vault_only = "fake erc4626" in evidence_combined and not any(term in evidence_combined for term in user_control_terms)
        receiver_user_controlled = any(term in evidence_combined for term in user_control_terms)
        receiver_trusted = any(term in evidence_combined for term in trusted_terms)
        erc4626_receiver_classified = receiver_user_controlled or receiver_trusted
        if receiver_user_controlled:
            erc4626_note = "receiver source proven attacker/user-controlled or arbitrary config-controlled"
        elif receiver_trusted:
            erc4626_note = "receiver appears constructor-bound, immutable, or address-book controlled"
        else:
            erc4626_note = "classify ERC4626 receiver source through constructor, factory, registry, deployment, and market config"

        if pattern == "untrusted-erc4626-value-conversion":
            erc4626_trust_boundary_passed = receiver_user_controlled and not erc4626_fake_vault_only
            erc4626_dependency_behavior_passed = True
        else:
            dependency_terms = [
                "dependency can enter bad state",
                "conversion rate can be manipulated",
                "conversion behavior reproduced",
                "trusted dependency price-risk reproduced",
                "fork shows conversion",
                "local dependency state reproduced",
            ]
            erc4626_trust_boundary_passed = receiver_trusted
            erc4626_dependency_behavior_passed = any(term in evidence_combined for term in dependency_terms)

    external_precondition = True
    external_note = "not required for this pattern"
    if pattern == "oracle-composition-signed-cast":
        external_note = "prove an in-scope sub-feed can return invalid/negative value or admin/feed configuration is in scope"
        positive_terms = [
            "underlying feed can return negative",
            "sub-feed can return negative",
            "oracle can return negative",
            "governance can set unsafe",
            "unsafe adapter is in scope",
            "admin misconfiguration in scope",
        ]
        negative_terms = [
            "still need prove",
            "still no proof",
            "no proof underlying",
            "unproven",
            "needs underlying",
        ]
        external_precondition = any(term in evidence_combined for term in positive_terms) and not any(term in evidence_combined for term in negative_terms)
    elif pattern == "untrusted-erc4626-value-conversion":
        external_note = "prove the ERC4626 receiver is attacker/user-controlled or arbitrary-config controlled; fake vault alone is not enough"
        external_precondition = erc4626_trust_boundary_passed
    elif pattern == "trusted-erc4626-oracle-dependency":
        external_note = "prove the fixed dependency can enter the bad conversion state in scope, not only by replacing it with a fake vault"
        external_precondition = erc4626_dependency_behavior_passed

    findings = read_tsv(target_dir(name) / "findings.tsv")
    finding_row = next((finding for finding in findings if finding.get("id") == candidate_id), {})
    report_packaged = bool(finding_row) and "confirmed" in finding_row.get("status", "").lower()

    gates = [
        {
            "gate": "local_poc",
            "status": gate_status(local_poc),
            "evidence": [str(event.get("command", "")) for event in local_poc_events] or ["candidate/evidence text mentions local PoC"] if local_poc else [],
            "next": "write and run a local unit/invariant/fork PoC",
        },
    ]

    if pattern in {"untrusted-erc4626-value-conversion", "trusted-erc4626-oracle-dependency"}:
        gates.append(
            {
                "gate": "erc4626_receiver_classified",
                "status": gate_status(erc4626_receiver_classified),
                "evidence": erc4626_note if erc4626_receiver_classified else "",
                "next": "classify ERC4626 receiver as user-controlled, registry-bound, constructor-bound, or fixed address-book dependency",
            }
        )
        gates.append(
            {
                "gate": "erc4626_trust_boundary",
                "status": gate_status(erc4626_trust_boundary_passed),
                "evidence": erc4626_note if erc4626_trust_boundary_passed else "",
                "next": (
                    "for untrusted claims, prove a public/factory/config path accepts an attacker-controlled ERC4626; "
                    "for trusted dependency claims, prove the fixed dependency is the deployed receiver"
                ),
            }
        )

    gates.extend(
        [
        {
            "gate": "risk_path",
            "status": gate_status(risk_path, weak=local_poc and not risk_path),
            "evidence": "risk/accounting keywords found in candidate evidence" if risk_path else "",
            "next": "prove the behavior reaches accounting, borrow, liquidation, withdrawal, or solvency checks",
        },
        {
            "gate": "deployment_reachability",
            "status": gate_status(deployment_reachability),
            "evidence": "deployment/config reachability evidence exists" if deployment_reachability else "",
            "next": "trace deployment config or on-chain/fork metadata from adapter to core consumer",
        },
        {
            "gate": "external_precondition_or_scope",
            "status": gate_status(external_precondition),
            "evidence": external_note if external_precondition else "",
            "next": external_note,
        },
        {
            "gate": "report_package",
            "status": gate_status(report_packaged),
            "evidence": finding_row.get("report_path", "") if report_packaged else "",
            "next": "add a confirmed finding row and report only after all proof gates pass",
        },
        ]
    )

    missing = [gate for gate in gates if gate["status"] != "passed"]
    if not local_poc:
        verdict = "suspected"
    elif missing:
        verdict = "plausible but unproven"
    else:
        verdict = "ready for confirmed finding package"
    return {
        "target": name,
        "candidate_id": candidate_id,
        "pattern": pattern,
        "state": row.get("state", ""),
        "verdict": verdict,
        "gates": gates,
    }


def gate_candidate(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    candidates = read_tsv(target_dir(name) / "candidates.tsv")
    if not candidates:
        print(f"No candidates found for {name}", file=sys.stderr)
        return 1
    if args.candidate_id:
        row = next((candidate for candidate in candidates if candidate.get("id") == args.candidate_id), None)
    else:
        row = top_active_candidate(name)
    if not row:
        print("candidate not found", file=sys.stderr)
        return 1
    result = build_candidate_gates(name, row)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"# Candidate Gate - {result['candidate_id']}")
        print(f"target: {result['target']}")
        print(f"pattern: {result['pattern']}")
        print(f"state: {result['state']}")
        print(f"verdict: {result['verdict']}")
        print()
        print("| Gate | Status | Next |")
        print("|---|---|---|")
        for gate in result["gates"]:
            print(f"| {gate['gate']} | {gate['status']} | {gate['next']} |")
    if args.update:
        missing = [gate for gate in result["gates"] if gate["status"] != "passed"]
        next_action_text = missing[0]["next"] if missing else "package confirmed finding and run complete gate"
        update_args = argparse.Namespace(
            name=name,
            candidate_id=result["candidate_id"],
            state="plausible but unproven" if missing else "confirmed with PoC",
            priority=args.priority,
            title="",
            code_path="",
            pattern="",
            trust_class="",
            source_expr="",
            sink_path="",
            property="",
            impact="",
            proof_gate="",
            false_positive_filters="",
            harness="",
            validation_plan="; ".join(gate["next"] for gate in missing) if missing else "",
            autopilot_next_action="",
            next_action=next_action_text,
            evidence=f"gate-candidate verdict={result['verdict']}",
            create=False,
        )
        update_candidate(update_args)
    return 0


def completion_gate(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"missing target: {name}", file=sys.stderr)
        return 1

    reasons: list[str] = []
    confirmed_rows = [
        row for row in read_tsv(out / "findings.tsv")
        if "confirmed" in row.get("status", "").lower()
    ]
    confirmed_candidates = [
        row for row in read_tsv(out / "candidates.tsv")
        if row.get("state") == "confirmed with PoC"
    ]
    if not confirmed_rows and not confirmed_candidates:
        reasons.append("no confirmed finding or candidate")

    for row in confirmed_rows:
        fid = row.get("id") or "unknown"
        for key in ["affected", "poc_command", "report_path", "log_path", "summary"]:
            if not row.get(key) or row.get(key) == "TBD":
                reasons.append(f"{fid}: confirmed finding missing {key}")
        report_path = row.get("report_path", "")
        log_path = row.get("log_path", "")
        for label, raw in [("report_path", report_path), ("log_path", log_path)]:
            if raw and raw != "TBD":
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = out / raw
                if not candidate.exists():
                    reasons.append(f"{fid}: {label} does not exist: {raw}")

    for row in confirmed_candidates:
        cid = row.get("id") or "unknown"
        evidence = row.get("evidence", "")
        if not evidence or "scanner hit only" in evidence or "TBD" in evidence:
            reasons.append(f"{cid}: confirmed candidate lacks concrete evidence")
        if not row.get("impact") or row.get("impact") == "TBD":
            reasons.append(f"{cid}: confirmed candidate missing impact")

    evidence_events = read_jsonl(out / "evidence-index.jsonl")
    confirmed_events = [
        event for event in evidence_events
        if "confirmed" in str(event.get("conclusion", "")).lower()
        or "confirmed" in str(event.get("type", "")).lower()
    ]
    if (confirmed_rows or confirmed_candidates) and not confirmed_events:
        reasons.append("no confirmed event in evidence-index.jsonl")

    if reasons:
        print("not complete")
        for reason in reasons:
            print(f"- {reason}")
        print("Only `confirmed with PoC` plus reproducible local evidence can complete the goal.")
        return 2 if args.strict else 0

    print("complete")
    print("Confirmed local PoC evidence is present and required fields are populated.")
    set_registry_field(name, phase="confirmed_or_exhausted", status="confirmed", next_action="package and disclose confirmed finding privately")
    return 0


def queue(args: argparse.Namespace) -> int:
    rows = registry_rows()
    if not rows:
        print("No registered targets.")
        return 0
    board: list[tuple[int, str, str, str, str, str]] = []
    for row in rows:
        name = row.get("name", "")
        out = target_dir(name)
        candidates = read_tsv(out / "candidates.tsv")
        active = [
            item for item in candidates
            if item.get("state") in {"plausible but unproven", "test written", "tested failed/security relevant", "suspected"}
        ]
        active.sort(
            key=lambda item: (
                ACTIVE_STATE_ORDER.get(item.get("state", ""), 9),
                int(item.get("priority") or "9"),
                item.get("id", ""),
            )
        )
        top = active[0] if active else {}
        priority = int(row.get("priority") or top.get("priority") or "9")
        phase = row.get("phase") or phase_for_target(name)
        next_step = top.get("next_action") or row.get("next_action") or "run auditctl next"
        board.append((priority, name, phase, top.get("id", ""), top.get("title", ""), next_step))
    board.sort(key=lambda item: item[0])
    if args.json:
        print(json.dumps([
            {
                "priority": item[0],
                "name": item[1],
                "phase": item[2],
                "top_candidate": item[3],
                "title": item[4],
                "next_action": item[5],
            }
            for item in board
        ], indent=2, ensure_ascii=False))
        return 0
    print("# Work Queue")
    print("| Priority | Target | Phase | Top candidate | Title | Next action |")
    print("|---:|---|---|---|---|---|")
    for priority, name, phase, cid, title, next_step in board:
        print(f"| {priority} | {name} | {phase} | {cid or '-'} | {title or '-'} | {next_step} |")
    return 0


def check(args: argparse.Namespace) -> int:
    name = slugify(args.name)
    out = target_dir(name)
    if not out.exists():
        print(f"missing target: {name}", file=sys.stderr)
        return 1
    errors: list[str] = []
    warnings: list[str] = []
    for rel in REQUIRED_TARGET_FILES:
        if not (out / rel).exists():
            errors.append(f"missing {rel}")
    for row in read_tsv(out / "candidates.tsv"):
        state = row.get("state", "")
        cid = row.get("id", "unknown")
        if state and state not in CANDIDATE_STATES:
            warnings.append(f"{cid}: unknown candidate state {state}")
        if state == "confirmed with PoC":
            if "TBD" in row.get("evidence", "") or not row.get("evidence"):
                errors.append(f"{cid}: confirmed candidate lacks evidence")
    for row in read_tsv(out / "findings.tsv"):
        status_text = row.get("status", "").lower()
        fid = row.get("id", "unknown")
        if "confirmed" in status_text:
            for key in ["affected", "poc_command", "report_path", "log_path"]:
                if not row.get(key) or row.get(key) == "TBD":
                    errors.append(f"{fid}: confirmed finding missing {key}")
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    for item in warnings:
        print(f"WARN: {item}", file=sys.stderr)
    print(f"check complete: errors={len(errors)} warnings={len(warnings)}")
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DeFi Hunter audit framework controller.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser("discover", help="discover and score local DeFi repositories")
    p_discover.add_argument("--root", default=".")
    p_discover.add_argument("--max-depth", type=int, default=3)
    p_discover.add_argument("--min-score", type=int, default=0)
    p_discover.add_argument("--limit", type=int, default=0)
    p_discover.add_argument("--show", type=int, default=10)
    p_discover.add_argument("--out", default="")
    p_discover.add_argument("--no-dedupe", action="store_true")
    p_discover.set_defaults(func=discover)

    p_recommend = sub.add_parser("recommend", help="show recommended targets from discovery CSV")
    p_recommend.add_argument("--file", default="")
    p_recommend.add_argument("--top", type=int, default=10)
    p_recommend.add_argument("--json", action="store_true")
    p_recommend.set_defaults(func=recommend)

    p_import = sub.add_parser("import-discovered", help="initialize top discovered targets")
    p_import.add_argument("--file", default="")
    p_import.add_argument("--top", type=int, default=5)
    p_import.add_argument("--authorization", default="user-owned")
    p_import.set_defaults(func=import_discovered)

    p_init = sub.add_parser("init", help="initialize or update a target workspace")
    p_init.add_argument("name")
    p_init.add_argument("--repo", default="")
    p_init.add_argument("--family", default="")
    p_init.add_argument("--authorization", default="")
    p_init.add_argument("--priority", type=int, default=3)
    p_init.add_argument("--notes", default="")
    p_init.set_defaults(func=init_target)

    p_status = sub.add_parser("status", help="show target status")
    p_status.add_argument("name", nargs="?")
    p_status.set_defaults(func=status)

    p_next = sub.add_parser("next", help="suggest next action")
    p_next.add_argument("name")
    p_next.set_defaults(func=next_action)

    p_agents = sub.add_parser("agents", help="generate subagent prompts")
    p_agents.add_argument("name")
    p_agents.set_defaults(func=agents)

    p_creative = sub.add_parser("creative-plan", help="generate a creative discovery hypothesis worksheet")
    p_creative.add_argument("name")
    p_creative.add_argument("--force", action="store_true")
    p_creative.set_defaults(func=creative_plan)

    p_scan = sub.add_parser("scan", help="run high-signal scanner and promote suspected candidates")
    p_scan.add_argument("name")
    p_scan.add_argument("--repo", default="")
    p_scan.add_argument("--max-per-pattern", type=int, default=10)
    p_scan.set_defaults(func=scan)

    p_rank = sub.add_parser("rank-candidates", help="rerank candidates by target family")
    p_rank.add_argument("name")
    p_rank.add_argument("--family", default="")
    p_rank.set_defaults(func=rank_candidates)

    p_triage = sub.add_parser("triage-candidates", help="suggest or apply automatic false-positive filters")
    p_triage.add_argument("name")
    p_triage.add_argument("--apply", action="store_true")
    p_triage.add_argument("--json", action="store_true")
    p_triage.set_defaults(func=triage_candidates)

    p_evolve = sub.add_parser("evolve", help="record framework/skill evolution lesson")
    p_evolve.add_argument("name")
    p_evolve.add_argument("--lesson", required=True)
    p_evolve.add_argument("--proposed-change", default="")
    p_evolve.add_argument("--skill", default="")
    p_evolve.set_defaults(func=evolve)

    p_log = sub.add_parser("log-evidence", help="append one evidence-index.jsonl event")
    p_log.add_argument("name")
    p_log.add_argument("--type", default="manual")
    p_log.add_argument("--candidate-id", default="")
    p_log.add_argument("--command", default="")
    p_log.add_argument("--cwd", default="")
    p_log.add_argument("--exit-code", type=int, default=0)
    p_log.add_argument("--log-path", default="")
    p_log.add_argument("--repo-commit", default="")
    p_log.add_argument("--conclusion", default="")
    p_log.set_defaults(func=log_evidence)

    p_update = sub.add_parser("update-candidate", help="update one candidate state or evidence fields")
    p_update.add_argument("name")
    p_update.add_argument("candidate_id")
    p_update.add_argument("--state", default="")
    p_update.add_argument("--priority", type=int, default=0)
    p_update.add_argument("--title", default="")
    p_update.add_argument("--code-path", default="")
    p_update.add_argument("--pattern", default="")
    p_update.add_argument("--trust-class", default="")
    p_update.add_argument("--source-expr", default="")
    p_update.add_argument("--sink-path", default="")
    p_update.add_argument("--property", default="")
    p_update.add_argument("--impact", default="")
    p_update.add_argument("--proof-gate", default="")
    p_update.add_argument("--false-positive-filters", default="")
    p_update.add_argument("--harness", default="")
    p_update.add_argument("--validation-plan", default="")
    p_update.add_argument("--autopilot-next-action", default="")
    p_update.add_argument("--next-action", default="")
    p_update.add_argument("--evidence", default="")
    p_update.add_argument("--create", action="store_true")
    p_update.set_defaults(func=update_candidate)

    p_ensure = sub.add_parser("ensure-candidate", help="create or update one candidate")
    p_ensure.add_argument("name")
    p_ensure.add_argument("candidate_id")
    p_ensure.add_argument("--state", default="suspected")
    p_ensure.add_argument("--priority", type=int, default=3)
    p_ensure.add_argument("--title", default="")
    p_ensure.add_argument("--code-path", default="")
    p_ensure.add_argument("--pattern", default="")
    p_ensure.add_argument("--trust-class", default="")
    p_ensure.add_argument("--source-expr", default="")
    p_ensure.add_argument("--sink-path", default="")
    p_ensure.add_argument("--property", default="")
    p_ensure.add_argument("--impact", default="")
    p_ensure.add_argument("--proof-gate", default="")
    p_ensure.add_argument("--false-positive-filters", default="")
    p_ensure.add_argument("--harness", default="")
    p_ensure.add_argument("--validation-plan", default="")
    p_ensure.add_argument("--autopilot-next-action", default="")
    p_ensure.add_argument("--next-action", default="")
    p_ensure.add_argument("--evidence", default="")
    p_ensure.set_defaults(func=ensure_candidate)

    p_autopilot = sub.add_parser("autopilot-plan", help="emit a machine-readable-ish execution plan from current state")
    p_autopilot.add_argument("name", nargs="?")
    p_autopilot.add_argument("--limit", type=int, default=10)
    p_autopilot.add_argument("--json", action="store_true")
    p_autopilot.set_defaults(func=autopilot_plan)

    p_merge = sub.add_parser("merge-agent", help="record a structured subagent JSON result")
    p_merge.add_argument("name")
    p_merge.add_argument("--file", default="")
    p_merge.set_defaults(func=merge_agent)

    p_finding = sub.add_parser("add-finding", help="add or update a finding row")
    p_finding.add_argument("name")
    p_finding.add_argument("finding_id")
    p_finding.add_argument("--status", default="confirmed with PoC")
    p_finding.add_argument("--severity", default="TBD")
    p_finding.add_argument("--affected", default="TBD")
    p_finding.add_argument("--poc-command", default="TBD")
    p_finding.add_argument("--report-path", default="TBD")
    p_finding.add_argument("--log-path", default="TBD")
    p_finding.add_argument("--summary", default="TBD")
    p_finding.set_defaults(func=add_finding)

    p_gate = sub.add_parser("gate-candidate", help="show proof gates for one candidate before confirmation")
    p_gate.add_argument("name")
    p_gate.add_argument("candidate_id", nargs="?")
    p_gate.add_argument("--json", action="store_true")
    p_gate.add_argument("--update", action="store_true", help="write the gate verdict back into candidates.tsv")
    p_gate.add_argument("--priority", type=int, default=0)
    p_gate.set_defaults(func=gate_candidate)

    p_complete = sub.add_parser("complete", help="run completion gate")
    p_complete.add_argument("name")
    p_complete.add_argument("--strict", action="store_true")
    p_complete.set_defaults(func=completion_gate)

    p_queue = sub.add_parser("queue", help="show cross-target work queue")
    p_queue.add_argument("--json", action="store_true")
    p_queue.set_defaults(func=queue)

    p_check = sub.add_parser("check", help="check evidence gates")
    p_check.add_argument("name")
    p_check.set_defaults(func=check)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
