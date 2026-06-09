# Autonomous Self-Evolving DeFi Audit Prompt

Use this prompt when Codex should run an authorized DeFi audit as an adaptive
workflow instead of staying inside a fixed checklist.

Read these files first:

1. `AUTHORIZATION.md`
2. `README.md`
3. `FRAMEWORK.md`
4. `prompts/authorized-defi-audit.md`
5. `CREATIVE_DISCOVERY.md`

Replace the placeholders before running:

- `<project name>`
- `<vault / lending / AMM / staking / rewards / oracle / bridge / 其他>`
- `<GitHub URL 或本地路径>`
- `<EVM / Solana / Anchor / Move / CosmWasm / 其他>`
- `<本地路径>`

```text
终端授权说明：
我是做白帽安全审计和漏洞赏金研究的。本次目标项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。
这个项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。我授权你在指定本地工作目录内阅读代码、运行测试、创建审计工作区、生成本地 PoC、编写 fuzz/invariant 测试、记录候选漏洞和报告草稿。

边界：
只允许在本地代码、本地测试、本地 fork、只读 fork 模拟、Foundry/Hardhat/Anchor/LiteSVM/Proptest/Echidna/Medusa 等安全环境中验证。
禁止攻击主网、禁止真实资金转移、禁止未授权访问、禁止公开披露。
不要自动提交 bounty，不要自动联系外部项目方。所有发现只报告给我。
如果某一步可能超出授权范围，立即停止并说明风险，等待我确认。

目标：
对我授权的 DeFi / 链上资金池项目 `<project name>` 进行自主安全审计，寻找真实、可复现、可能影响资金安全或协议安全性的漏洞。

项目信息：
- 项目类型：<vault / lending / AMM / staking / rewards / oracle / bridge / 其他>
- 官方或本地仓库：<GitHub URL 或本地路径>
- 链/运行时：<EVM / Solana / Anchor / Move / CosmWasm / 其他>
- 工作目录：<本地路径>

核心要求：
1. 不要只分析，要实际推进审计工作。
2. 不要被 `README.md`、`FRAMEWORK.md`、`prompts/` 或现有 skill 框死。
3. `defi-pool-auditor`、`defi-audit-orchestrator`、`defi-poc-pattern-hunter` 和 `scripts/auditctl.py` 只是初始工作流和状态管理工具。
4. 如果当前框架、提示词、脚本、模板、测试 harness、扫描器、子代理分工不够用，你可以在本地创建或修改它们。
5. 每一次自进化都必须服务于当前授权审计目标，并记录原因、改动、验证方式和下一步用途。
6. 不要把猜测当漏洞。高危判断必须有代码路径、影响路径和可复现本地证据。
7. 常见漏洞和 scanner hits 只作为热身。大部分明显漏洞别人已经扫过，必须额外做协议特有、反事实、组合路径、顺序扰动和负空间发现。
8. 每轮至少提出 3 个非模板化 creative hypotheses，并给出最快本地验证或证伪方式。

完成条件：
只有满足以下任一条件才允许停止：
1. 已发现 confirmed finding，并完成完整汇报；
2. 已发现 suspected vulnerability，需要我确认下一步授权边界；
3. 本地环境真实阻塞，且已尝试修复并记录失败原因；
4. 我明确要求停止。

如果没有 confirmed finding，也没有 suspected vulnerability，也没有真实阻塞，不要输出最终总结；继续进入下一轮审计。

启动步骤：
1. 读取 `AUTHORIZATION.md`，确认本轮只做授权/本地/只读模拟审计。
2. 读取 `FRAMEWORK.md`、`CREATIVE_DISCOVERY.md` 和 `prompts/authorized-defi-audit.md`，把它们作为起点，不作为限制。
3. 运行：
   `python3 scripts/auditctl.py --help`
4. 初始化或附加目标：
   `python3 scripts/auditctl.py init <project name> --repo <本地路径> --family <项目类型> --authorization explicit-whitehat-authorization`
5. 生成子代理提示词：
   `python3 scripts/auditctl.py agents <project name>`
6. 生成创造性发现计划：
   `python3 scripts/auditctl.py creative-plan <project name>`
7. 如果 multi-agent 工具可用，立即创建下面的子代理并行研究；如果不可用，就由主代理按角色顺序执行。

子代理要求：
- 子代理 A：scope mapper
  负责 repo、commit、授权边界、入口函数、测试命令、核心模块、不可触碰范围。
- 子代理 B：value-flow auditor
  负责 deposit / withdraw / redeem / swap / borrow / repay / liquidate / claim 等价值流和状态机。
- 子代理 C：accounting auditor
  负责 share、LP、debt、fee、reward、interest index、rounding、decimal、first deposit、donation、dust。
- 子代理 D：oracle/economic auditor
  负责 oracle、price feed、TWAP、fallback、quote direction、stale price、清算边界、经济攻击面。
- 子代理 E：invariant designer
  负责把协议安全属性转成 Foundry/Echidna/Medusa/Proptest/Anchor/LiteSVM fuzz 或 invariant 测试。
- 子代理 F：validator
  负责把 top candidates 缩成最小本地 PoC，或用代码/测试证伪。
- 子代理 G：framework evolution reviewer
  负责发现当前框架、skill、提示词、脚本、模板、扫描器、子代理分工的不足，并提出或直接落地本地改进。
- 子代理 H：novelty hunter
  负责基于 `CREATIVE_DISCOVERY.md` 生成协议特有假设，重点寻找常见扫描器不容易发现的 weird state、顺序扰动、组合边界和负空间问题。
- 子代理 I：adversarial reviewer
  负责攻击当前审计计划本身，找出被过早降权的 scanner hit、误判 false positive、未读文件、隐含信任假设和缺失测试。

每个子代理输出必须包含：
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

子代理合并规则：
1. 不要让子代理直接把猜测写成 confirmed finding。
2. 使用 `python3 scripts/auditctl.py merge-agent <project name> --file <agent-output.json>` 合并结构化结果。
3. 只有在有代码路径、影响路径、验证计划或本地测试证据时，才把候选项写入 `candidates.tsv`。
4. 只有本地 PoC、测试失败、invariant failure、fuzz case、deterministic crash 或只读 fork simulation 证明成立，才允许升级为 `confirmed with PoC`。

自进化规则：
如果现有框架不足，允许做以下事情：
1. 新增或修改 prompt 模板；
2. 新增或修改 `scripts/` 里的本地扫描器、候选排序器、证据记录器、PoC 生成器；
3. 新增或修改 Foundry/Hardhat/Anchor/LiteSVM/Proptest/Echidna/Medusa 测试模板；
4. 新增或修改子代理角色、输出字段和合并规则；
5. 生成 `skill-evolution.md` 或 `skill-patches/*.md`；
6. 如果本地 skill 目录可写，并且改动明显有用，可以提出或落地 skill 更新。

每次自进化必须记录：
- 触发原因；
- 当前框架哪里不够；
- 新增/修改了什么；
- 如何验证这个改动有用；
- 是否影响当前候选漏洞判断；
- 下一轮应该如何复用。

创造性发现规则：
每轮审计必须至少执行一次 creative discovery pass：
1. 写出协议自己的独特承诺，不要只套通用 checklist；
2. 构造协议以为“不可能”的状态；
3. 重排正常用户操作顺序；
4. 跟踪所有单位、精度、rounding、share、debt、oracle quote 边界；
5. 使用 honest-but-surprising dependency 行为，而不是只假设恶意依赖；
6. 找 missing checks、missing postconditions、missing binding，而不是只找可疑代码；
7. 为每个假设写出最快本地证伪路径；
8. 只有经本地证据证明，才升级候选状态。

高价值攻击面优先级：
- solvency 破坏；
- ERC4626 / LP share accounting 错误；
- first deposit / donation / dust 攻击；
- oracle decimals / stale / fallback / quote direction 错误；
- liquidation 边界、partial liquidation、bad debt；
- interest / fee / reward index 更新顺序错误；
- reentrancy / callback / transfer hook；
- 权限、controller、vault、PDA、account binding 错误；
- pause / emergency / withdrawal queue 导致资金冻结；
- 协议特有机制带来的新攻击面。

候选漏洞状态：
- suspected
- plausible but unproven
- test written
- tested failed/security relevant
- tested no impact
- confirmed with PoC
- false positive
- informational
- blocked

汇报规则：
一旦发现 suspected vulnerability，立即报告：
- 代码路径；
- 初步影响；
- 为什么怀疑；
- 需要我确认的授权边界；
- 下一步本地验证方式。

一旦确认 confirmed finding，停止扩大范围并优先汇报：
- 漏洞标题；
- 严重级别初判；
- 影响范围；
- root cause；
- attack path；
- PoC 文件路径和运行命令；
- 复现结果；
- 修复建议；
- 回归测试建议；
- 报告草稿。

持续审计循环：
如果当前假设被证伪，标记为 false positive，记录原因，选择下一个高价值攻击面，继续。
如果测试覆盖不足，创建新的 fuzz/invariant/PoC 测试，继续。
如果协议地图不完整，回到代码阅读，补全资金流、权限、oracle、费用、清算或奖励逻辑，继续。
如果框架不够用，先自进化框架或 skill，再继续审计。
```
