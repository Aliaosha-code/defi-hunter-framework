# Authorization Statement

Use this file as the first context block for Codex or any other audit agent
before starting project-specific work.

```text
终端授权说明：
我是做白帽安全审计和漏洞赏金研究的。本次目标项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。

这个项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。我授权你在指定本地工作目录内阅读代码、运行测试、创建审计工作区、生成本地 PoC、编写 fuzz/invariant 测试、记录候选漏洞和报告草稿。

我确认本项目属于以下任一情况：
1. 我拥有该项目；
2. 我是该项目维护者或开发者；
3. 我已获得项目方明确授权进行安全审计。

允许范围：
1. 阅读指定本地工作目录内的代码和文档；
2. 运行本地构建、单元测试、fuzz、invariant、静态分析和只读 fork 模拟；
3. 创建本地审计工作区、候选漏洞记录、PoC 测试、报告草稿和修复建议；
4. 使用 Foundry、Hardhat、Anchor、LiteSVM、Proptest、Echidna、Medusa 等本地或安全模拟工具。

禁止范围：
1. 禁止攻击主网或公共测试网合约；
2. 禁止转移、冻结、盗取或影响真实资金；
3. 禁止未授权访问第三方系统、账户、RPC 私有资源或后台服务；
4. 禁止自动提交 bounty、自动联系项目方或公开披露漏洞；
5. 禁止把猜测包装成 confirmed finding。

如果某一步可能超出授权范围，必须立即停止并说明风险，等待我确认。
```

## Agent Handling Rules

- Treat this as an authorized whitehat audit only for the specific project,
  repository, and local work directory supplied by the user.
- Keep all validation local: unit tests, invariant tests, fuzz harnesses,
  deterministic reproductions, or read-only fork simulations.
- If scope is missing or ambiguous, ask for scope instead of continuing into
  live or third-party actions.
- If a suspected vulnerability is found, report it privately to the user with
  code path, impact hypothesis, and next local validation step.
- If a confirmed finding is found, stop broad exploration and package the
  private report with PoC path, reproduction command, root cause, impact, and
  remediation guidance.
