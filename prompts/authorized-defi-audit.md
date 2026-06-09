# Authorized DeFi Audit Prompt

Use this prompt to start Codex on a DeFi / on-chain pool project that you own,
maintain, develop, or are explicitly authorized to audit.

Replace the placeholders before running:

- `<vault / lending / AMM / staking / rewards / oracle / bridge / 其他>`
- `<GitHub URL 或本地路径>`
- `<EVM / Solana / Anchor / Move / CosmWasm / 其他>`
- `<本地路径>`

```text
目标：使用 defi-pool-auditor skill 作为基础工作流，开始审计我自己的 DeFi / 链上资金池项目。

授权说明：
这个项目是我拥有、维护、开发，或我已获得明确授权进行安全审计的项目。我授权你在指定本地工作目录内阅读代码、运行测试、创建审计工作区、生成本地 PoC、编写 fuzz/invariant 测试、记录候选漏洞和报告草稿。

我确认本项目属于以下任一情况：
1. 我拥有该项目；
2. 我是该项目维护者或开发者；
3. 我已获得项目方明确授权进行安全审计；

重要边界：
1. 只允许在本地代码、本地测试、本地 fork、只读 fork 模拟、Foundry/Hardhat/Anchor/LiteSVM/Proptest 等安全环境中验证。
2. 禁止攻击主网、禁止真实资金转移、禁止未授权访问、禁止公开披露。
3. 不要自动提交 bounty，不要联系外部项目方。所有发现只报告给我。
4. 如果某一步可能超出授权范围，必须立即停止并说明风险，等待我确认。

项目信息：
- 项目类型：<vault / lending / AMM / staking / rewards / oracle / bridge / 其他>
- 官方或本地仓库：<GitHub URL 或本地路径>
- 链/运行时：<EVM / Solana / Anchor / Move / CosmWasm / 其他>
- 工作目录：<本地路径>
- 审计目标：寻找真实、可复现、可能影响资金安全或协议安全性的漏洞。

最高优先级要求：
不要只分析，要实际推进审计工作。
不要因为“暂未发现漏洞”而停止。
在没有 confirmed finding 之前，持续扩展审计路径、测试假设、编写 PoC、运行 fuzz/invariant、复查资金流和边界条件。

只有满足以下任一条件才允许停止：
1. 已发现 confirmed finding，并完成完整汇报；
2. 发现 suspected vulnerability，需要我确认下一步授权边界；
3. 本地环境阻塞，且已尝试修复并记录失败原因；
4. 我明确要求停止。

如果没有 confirmed finding，也没有阻塞，不要输出最终总结；继续审计下一轮。

完成标准：
一次有效交付必须至少满足以下之一：
- 找到 confirmed finding，并提供可复现证据；
- 发现 suspected vulnerability，并说明代码路径、怀疑原因、影响范围和下一步验证方式；
- 遇到真实阻塞，并说明已尝试的解决方式和需要我提供的信息。

执行流程：

1. 建立审计 scope
   - 确认本地 repo 和 commit
   - 识别核心合约/模块
   - 识别测试框架
   - 记录已运行命令
   - 明确本轮审计范围和不碰的范围

2. 建立协议地图
   - 资产和资金池
   - deposit / withdraw / redeem / swap / borrow / repay / liquidate / claim 等价值流
   - 核心状态变量
   - 权限角色
   - oracle / price feed / TWAP / fallback
   - fee / interest / reward / share accounting
   - pause / emergency / upgrade 机制
   - 外部依赖和 trust assumptions

3. 如果 multi-agent 工具可用，直接创建子代理协同：
   - 子代理 A：scope mapper，负责 repo、模块、入口函数、测试命令
   - 子代理 B：value-flow auditor，负责资金流和状态机
   - 子代理 C：accounting auditor，负责 share、debt、fee、reward、rounding、decimal
   - 子代理 D：oracle/economic auditor，负责 oracle、价格边界、清算、经济攻击面
   - 子代理 E：invariant designer，负责 fuzz/invariant 测试计划
   - 子代理 F：validator，负责把候选漏洞缩成最小本地 PoC
   - 子代理 G：skill evolution reviewer，负责提出框架或 skill 升级建议

4. 优先寻找：
   - solvency 破坏
   - ERC4626 / LP share accounting 错误
   - first deposit / donation / dust 攻击
   - oracle decimals / stale / fallback / quote direction 错误
   - liquidation 边界、partial liquidation、bad debt
   - interest / fee / reward index 更新顺序错误
   - reentrancy / callback / transfer hook
   - 权限、controller、vault、PDA、account binding 错误
   - pause / emergency / withdrawal queue 导致资金冻结
   - 协议特有机制带来的新攻击面

5. 候选漏洞状态分类：
   - confirmed with PoC
   - plausible but unproven
   - false positive
   - informational

6. 汇报规则：
   一旦发现 suspected vulnerability，立即报告：
   - 代码路径
   - 初步影响
   - 为什么怀疑
   - 下一步验证方式

   一旦本地 PoC、测试失败、invariant failure、fork simulation 或 trace 证明漏洞成立，立即停止扩大范围，优先汇报 confirmed finding。

   confirmed finding 必须包含：
   - 漏洞标题
   - 严重级别初判
   - 影响范围
   - root cause
   - attack path
   - PoC 文件路径和运行命令
   - 复现结果
   - 修复建议
   - 回归测试建议
   - 报告草稿

7. 持续审计循环：
   如果当前假设被证伪：
   - 标记为 false positive
   - 记录原因
   - 选择下一个高价值攻击面
   - 编写新的测试或 PoC
   - 继续运行

   如果测试覆盖不足：
   - 创建新的 fuzz/invariant 测试
   - 增加边界输入
   - 增加异常状态组合
   - 继续运行

   如果协议地图不完整：
   - 回到代码阅读
   - 补全资金流、权限、oracle、费用、清算或奖励逻辑
   - 继续运行

8. 自进化要求：
   - 记录本轮新增攻击面
   - 记录无效 checklist
   - 记录需要新增的 invariant 模板
   - 记录需要新增的脚本或自动化扫描器
   - 如果 skill 需要升级，生成 skill-evolution.md
   - 如果适合直接更新本地框架，就创建或修改对应模板、脚本、文档

最终输出要求：
只有在发现 confirmed finding、suspected vulnerability、授权边界问题或真实阻塞时，才输出给我。

输出内容包括：
- 当前审计 scope
- 已运行命令
- 当前 repo commit
- 协议价值流地图
- 高价值攻击面排序
- 正在推进的测试
- 候选漏洞列表和状态
- 子代理结果合并
- skill / 框架自进化建议
- 下一步具体命令
- 如有 confirmed finding，生成完整报告草稿

硬性要求：
- 不要把猜测当漏洞。
- 每个高危判断都必须有代码路径和可复现测试。
- 不要用“没有发现明显漏洞”作为结束理由。
- 如果没有发现漏洞，就继续审计。
- 如果上下文、时间或环境限制导致无法继续，必须明确说明阻塞原因，而不是给出空泛总结。
```
