# DeFi Hunter Framework

This framework is a local-only audit operating system for projects the user
owns, maintains, or is explicitly authorized to review.

It is designed to let Codex keep moving without being trapped inside one fixed
skill checklist:

- `defi-audit-orchestrator`: coordinates target choice, evidence, agents, and
  completion gates.
- `defi-pool-auditor`: maps protocol value flow and audit surfaces.
- `defi-poc-pattern-hunter`: turns recurring DeFi patterns into local PoC
  harnesses and false-positive filters.
- `defi-hunter`: stores the actual state, evidence, candidates, findings, logs,
  and framework evolution notes.

## Completion Standard

The audit goal is not complete when the environment is installed, the repo
builds, a scanner finds a pattern, or a report draft exists.

The only success state for "find a vulnerability" is:

```text
confirmed with PoC
```

That state requires local reproducible evidence:

- a failing local test, invariant failure, fuzz case, deterministic crash, or
  read-only fork simulation;
- an exact command that reproduces the behavior;
- affected code path and commit;
- a scoped impact statement;
- false-positive filters applied.

Everything else stays as `suspected`, `plausible but unproven`,
`informational`, `false positive`, or `blocked`.

## Directory Model

```text
scripts/auditctl.py          # main framework CLI
prompts/                     # reusable startup prompts
targets/registry.csv         # generated local target queue
targets/<target>/
  audit-state.md             # phase and next action
  scope.md                   # authorization and in-scope repos
  protocol-map.md            # assets, roles, value flow, dependencies
  attack-lines.md            # ranked attack routes
  candidates.tsv             # machine-readable candidate state table
  findings.tsv               # machine-readable finding evidence table
  evidence-index.jsonl       # command/evidence event stream
  lessons.jsonl              # replayable skill-evolution queue
  findings/                  # individual finding reports
  poc/                       # local PoC tests and harness notes
  logs/                      # command outputs
  scans/                     # scanner JSON/markdown output
  agents/agent-prompts.md    # subagent role prompts
  skill-evolution.md         # lessons and proposed skill upgrades
```

## Basic Commands

For a new authorized project, start Codex by reading
`AUTHORIZATION.md`, then use the prompt template in
`prompts/authorized-defi-audit.md`, then initialize or attach the target with
the commands below.

Put the authorization statement at the top of the session before running any
project-specific commands. The framework is intended for whitehat audit and
bug-bounty work where the user owns, maintains, develops, or has explicit
authorization to review the target. When scope is unclear, stop at local
defensive review and ask for confirmation.

Discover and rank local DeFi repositories:

```bash
python3 scripts/auditctl.py discover --root .
python3 scripts/auditctl.py recommend --top 10
```

Import the best discovered targets into the audit queue:

```bash
python3 scripts/auditctl.py import-discovered --top 5 --authorization user-owned
```

Initialize a target workspace:

```bash
python3 scripts/auditctl.py init my-target --repo ./my-repo --family lending --authorization user-owned
```

Show status:

```bash
python3 scripts/auditctl.py status my-target
```

Show the cross-target queue:

```bash
python3 scripts/auditctl.py queue
```

Ask the framework what Codex should do next:

```bash
python3 scripts/auditctl.py next my-target
```

Generate subagent prompts:

```bash
python3 scripts/auditctl.py agents my-target
```

Run the high-signal scanner and promote hits into `candidates.tsv` as
`suspected`:

```bash
python3 scripts/auditctl.py scan my-target
```

Rerank candidate priority by target family:

```bash
python3 scripts/auditctl.py rank-candidates my-target
```

Apply automatic false-positive filters or preview what they would change:

```bash
python3 scripts/auditctl.py triage-candidates my-target
python3 scripts/auditctl.py triage-candidates my-target --apply
```

Update a candidate after manual review, a subagent result, or a local test:

```bash
python3 scripts/auditctl.py update-candidate my-target MY-CANDIDATE-001 \
  --state "tested failed/security relevant" \
  --impact "local test shows the risk path is affected; deployment reachability still unproven" \
  --evidence "forge test --match-contract MyPoC -vvv passed" \
  --next-action "trace deployment reachability and scope"
```

Ask for an execution plan that keeps moving even when docs still have gaps:

```bash
python3 scripts/auditctl.py autopilot-plan my-target
```

Check proof gates before calling a candidate confirmed:

```bash
python3 scripts/auditctl.py gate-candidate my-target MY-CANDIDATE-001
python3 scripts/auditctl.py gate-candidate my-target MY-CANDIDATE-001 --json
```

Record structured subagent output without automatically changing state:

```bash
python3 scripts/auditctl.py merge-agent my-target --file agent-output.json
```

Log one evidence event:

```bash
python3 scripts/auditctl.py log-evidence my-target \
  --type poc_test \
  --candidate-id MY-CANDIDATE-001 \
  --command "forge test --match-test test_local_poc -vvv" \
  --cwd ./my-repo \
  --exit-code 1 \
  --log-path logs/MY-CANDIDATE-001.log \
  --conclusion "local test fails; impact still being classified"
```

Run the completion gate:

```bash
python3 scripts/auditctl.py complete my-target
```

Record a reusable lesson:

```bash
python3 scripts/auditctl.py evolve my-target --lesson "Oracle route tests must include stale, zero, negative, and reverting feeds."
```

## Operating Loop

1. Discovery: use `discover` and `recommend` when the target is not fixed.
   Prefer local runnability, rich value-flow complexity, and feasible PoC paths
   over headline bounty size.
2. Scope gate: record authorization, repo, commit, in-scope code, out-of-scope
   clauses, and allowed PoC environment.
3. Baseline: identify toolchain and run the smallest reliable build/test
   command.
4. Protocol map: follow value flow, roles, accounting units, oracles,
   external integrations, and admin controls.
5. Parallel passes: run scope, value-flow, accounting, oracle/economic,
   invariant, validator, and skill-evolution roles.
6. Candidate promotion: scanner hits and code observations start as
   `suspected`; promote only with concrete code evidence and an attack path.
7. Validation: write a local unit test, invariant, fuzz harness, or read-only
   fork simulation.
8. Reporting: package confirmed findings immediately; record false positives
   with the disproof path.
9. Evolution: update `skill-evolution.md` with workflow changes that should be
   added to future skills, scripts, or templates.

## Target Phases

- `env_not_ready`: toolchain and baseline are not proven.
- `baseline_ready`: smallest reliable build/test command is known.
- `protocol_mapped`: value flow, assets, roles, oracles, and accounting map
  exists.
- `candidate_queue_ready`: ranked candidates exist.
- `poc_validation_active`: a candidate is being converted into a local PoC.
- `confirmed_or_exhausted`: a confirmed finding exists, or the target is
  explicitly paused/exhausted with evidence.

## Candidate States

- `suspected`: suspicious code path, scanner hit, or weak hypothesis.
- `plausible but unproven`: concrete preconditions and attack path exist.
- `test written`: a local test/harness exists but result is not classified.
- `tested failed/security relevant`: a test fails and security impact is being
  classified.
- `tested no impact`: tested locally but impact is absent or blocked.
- `confirmed with PoC`: local reproducible evidence proves the issue.
- `false positive`: disproved by code, tests, runtime semantics, privilege, or
  scope.
- `informational`: robustness/tooling/SDK issue without funds impact.
- `blocked`: progress needs external input or unavailable private dependency.

## Proof Gates

Use `gate-candidate` before promoting any candidate to `confirmed with PoC`.
The framework separates these gates:

- `local_poc`: a local test, invariant, fuzz case, deterministic crash, or
  read-only fork simulation ran and is recorded.
- `risk_path`: the behavior reaches accounting, borrow, liquidation,
  withdrawal, solvency, share, or other security-relevant logic.
- `deployment_reachability`: the affected adapter/module is reachable from
  in-scope deployment/config or a core consumer.
- `external_precondition_or_scope`: any external oracle/admin/config
  precondition is proven plausible and in scope, not merely mocked.
- `report_package`: a confirmed finding row and report/log/PoC artifacts exist.

For oracle-composition candidates, a mock negative sub-feed is not enough by
itself. The candidate stays `plausible but unproven` until the external
sub-feed or configuration precondition is also proven in scope.

### ERC4626 Value-Conversion Gates

ERC4626 hits must be classified before a PoC route is chosen. The first
question is who controls the ERC4626 receiver, not whether a fake vault can be
written locally.

- `erc4626-user-controlled-value-conversion`: calldata, route input, market
  creation, or public config can supply the receiver. A fake ERC4626 PoC is
  useful only after that source path is proven.
- `erc4626-constructor-bound-adapter-conversion`: constructor or init config
  fixes the receiver. Treat this as a deployment/config scope question, not a
  user-token injection issue.
- `trusted-erc4626-oracle-dependency`: a fixed trusted receiver contributes to
  price, oracle, risk, or accounting value. Prove the fixed dependency can
  enter the bad conversion state in scope, then prove the value reaches borrow,
  liquidation, solvency, share, redeem, swap, or reward logic.

False-positive filters:

- constructor-only `asset()` metadata calls are not value-conversion findings;
- immutable/address-book receivers are not attacker-controlled unless a public
  path can change them;
- fake ERC4626 receiver tests do not prove fixed-dependency risk;
- trusted-admin replacement is not a public exploit path unless the scope
  explicitly includes that configuration failure.

Use `triage-candidates` to demote stale scanner hits after the receiver class
is clear. Use `gate-candidate` to require `erc4626_receiver_classified`,
`erc4626_trust_boundary`, `local_poc`, `risk_path`,
`deployment_reachability`, `external_precondition_or_scope`, and
`report_package` before confirmation.

## Structured Subagent Merge

Every subagent should return these fields so the main Codex can merge without
guesswork:

- `role`
- `files_reviewed`
- `candidate_ids`
- `evidence_refs`
- `confidence`
- `next_validation`
- `false_positive_filters`
- `changed_files`

The main Codex should merge only evidence-backed candidate changes into
`candidates.tsv` or `findings.tsv`.

State table writes are serialized by the framework. Subagents should not edit
`candidates.tsv` directly; they should return structured output or ask the main
agent to run `update-candidate`. This keeps parallel research from corrupting
the queue.

## Safety Boundary

Keep all PoCs in local tests, invariant harnesses, fuzz harnesses, or read-only
fork simulations. Do not provide or run live exploitation against third-party
contracts, and do not move real funds.
