# DeFi Hunter Framework

Reusable local workflow for authorized DeFi and on-chain pool security audits.

This is not an exploit runner. It is a repeatable framework for turning an
authorized project scope into local tests, invariants, private evidence, and
report drafts.

Start with [AUTHORIZATION.md](AUTHORIZATION.md), then read
[FRAMEWORK.md](FRAMEWORK.md) and
[CREATIVE_DISCOVERY.md](CREATIVE_DISCOVERY.md). The main controller is:

```bash
python3 scripts/auditctl.py --help
```

For a fresh authorized audit, copy and fill this startup prompt:
[prompts/authorized-defi-audit.md](prompts/authorized-defi-audit.md).

For a more autonomous run with subagents and framework/skill evolution, use:
[prompts/autonomous-self-evolving-defi-audit.md](prompts/autonomous-self-evolving-defi-audit.md).

The framework is intentionally not just a checklist. Use generic scanners to
get oriented, then use [CREATIVE_DISCOVERY.md](CREATIVE_DISCOVERY.md) to build
protocol-specific hypotheses that common tools and repeated bounty reviews are
likely to miss.

## Authorization Header

Use [AUTHORIZATION.md](AUTHORIZATION.md), or paste this shorter header at the
top of a Codex session before starting project-specific audit work:

```text
终端授权说明：
我是做白帽安全审计和漏洞赏金研究的。本次目标项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。
这个项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。我授权你在指定本地工作目录内阅读代码、运行测试、创建审计工作区、生成本地 PoC、编写 fuzz/invariant 测试、记录候选漏洞和报告草稿。

边界：
只允许在本地代码、本地测试、本地 fork、只读 fork 模拟、Foundry/Hardhat/Anchor/LiteSVM/Proptest 等安全环境中验证。禁止攻击主网、禁止真实资金转移、禁止未授权访问、禁止公开披露。
```

## Workflow

1. Read the target `scope.md` and confirm authorization.
2. Use only the project repository or repositories in the authorized scope.
3. Run baseline build and tests before adding harnesses.
4. Map value flows before reading files line by line.
5. Use creative discovery to generate protocol-specific hypotheses beyond
   generic scanner hits.
6. Convert each hypothesis into a local invariant, unit test, fuzz test, or
   read-only fork simulation.
7. Treat every finding as unconfirmed until it has a minimal reproduction.

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

Generate and merge subagent work:

```bash
python3 scripts/auditctl.py agents my-target
python3 scripts/auditctl.py creative-plan my-target
python3 scripts/auditctl.py merge-agent my-target --file agent-output.json
```

Record framework or skill evolution lessons:

```bash
python3 scripts/auditctl.py evolve my-target \
  --lesson "The current checklist missed a protocol-specific invariant." \
  --proposed-change "Add a reusable invariant template and rerun validation."
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
