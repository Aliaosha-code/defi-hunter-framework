# DeFi Hunter Framework

Reusable local workflow for authorized DeFi and on-chain pool security audits.

This is not an exploit runner. It is a repeatable framework for turning an
authorized project scope into local tests, invariants, private evidence, and
report drafts.

Start with [FRAMEWORK.md](FRAMEWORK.md). The main controller is:

```bash
python3 scripts/auditctl.py --help
```

For a fresh authorized audit, copy and fill this startup prompt:
[prompts/authorized-defi-audit.md](prompts/authorized-defi-audit.md).

## Workflow

1. Read the target `scope.md` and confirm authorization.
2. Use only the project repository or repositories in the authorized scope.
3. Run baseline build and tests before adding harnesses.
4. Map value flows before reading files line by line.
5. Convert each hypothesis into a local invariant, unit test, fuzz test, or
   read-only fork simulation.
6. Treat every finding as unconfirmed until it has a minimal reproduction.

## Framework Commands

Discover local DeFi targets:

```bash
python3 scripts/auditctl.py discover --root .
python3 scripts/auditctl.py recommend --top 10
```

Import the best targets:

```bash
python3 scripts/auditctl.py import-discovered --top 5 --authorization user-owned
```

Initialize a target:

```bash
python3 scripts/auditctl.py init my-target --repo ./my-repo --authorization user-owned
```

Show the cross-target queue:

```bash
python3 scripts/auditctl.py queue
```

Get the next action:

```bash
python3 scripts/auditctl.py next my-target
```

Run scanner and promote hits only to `suspected`:

```bash
python3 scripts/auditctl.py scan my-target
python3 scripts/auditctl.py rank-candidates my-target
```

Check whether the audit goal is actually complete:

```bash
python3 scripts/auditctl.py complete my-target
```

Update state after validation:

```bash
python3 scripts/auditctl.py update-candidate my-target MY-CANDIDATE-001 --state "plausible but unproven"
python3 scripts/auditctl.py log-evidence my-target --type poc_test --candidate-id MY-CANDIDATE-001
python3 scripts/auditctl.py merge-agent my-target --file agent-output.json
```

## Safety Rules

- Do not test against mainnet or public testnet contracts unless the
  authorization explicitly permits that exact action.
- Do not publish suspected issues before disclosure is accepted or cleared.
- Keep PoCs local and self-contained.
- Do not include private keys, RPC credentials, or bounty account tokens in this
  repository.

## Directory Map

- `scripts/`: framework CLI and audit-state helpers.
- `prompts/`: startup prompts for authorized local audits.
- `targets/`: generated local audit workspaces. Keep this directory private if
  it contains project-specific findings, PoCs, logs, or reports.
