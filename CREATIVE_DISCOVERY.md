# Creative Vulnerability Discovery

Most obvious bug classes are already scanned by other auditors and tools. This
framework should still use known patterns, but the main value comes from
protocol-specific reasoning, state-machine imagination, and local validation.

Use this file after the baseline protocol map exists and before spending too
long on generic scanner hits.

## Principle

Do not ask only "which known bug pattern is present?"

Also ask:

- What unusual promise does this protocol make that other protocols do not?
- Which state is supposed to be impossible, but is not explicitly forbidden?
- Which value is assumed to be synchronized, fresh, monotonic, conserved,
  bounded, or owned by the right account?
- Which external dependency can be honest but surprising?
- Which action is safe alone but unsafe when ordered before or after another
  safe action?
- Which path is ignored because it looks like an admin, preview, queue,
  callback, migration, cancel, rounding, dust, or emergency path?

## Novelty Lanes

### 1. Protocol-Specific Promise Breaking

Write down the protocol's own unique promises in plain language, then try to
break each one locally.

Examples of promises:

- A share always represents a proportional claim on assets.
- A liquidation always improves solvency.
- A queued withdrawal cannot be diluted by later deposits.
- A reward index cannot overpay a late entrant.
- A position close cannot leave unaccounted residue.
- A fallback oracle is only a safety net, not a value source.

Turn each promise into an invariant or differential test.

### 2. Counterfactual State Machine

Create states the protocol implicitly believes should not exist:

- partially initialized pools;
- stale but nonzero oracle values;
- dust positions that round to zero in one unit and nonzero in another;
- paused deposits with unpaused claims;
- cancelled orders with leftover accounting;
- bad debt below threshold;
- expired maturity with pending reward;
- migration halfway complete;
- callback succeeds but downstream accounting reverts;
- receiver has pre-existing residue before a route.

Then ask which public or authorized local path can reach that state.

### 3. Order Perturbation

Take normal flows and reorder them:

- deposit -> donate -> withdraw;
- accrue -> borrow -> repay -> accrue;
- claim -> update index -> exit;
- oracle update -> liquidate -> fallback update;
- cancel -> execute -> refund;
- migrate -> pause -> emergency withdraw;
- partial liquidation -> interest update -> full liquidation.

If two operations are both allowed, prove whether their order matters.

### 4. Unit Boundary And Rounding Mismatch

Track every conversion boundary:

- token decimals;
- shares/assets;
- debt/principal/interest;
- collateral value/debt value;
- oracle quote/base direction;
- signed/unsigned;
- raw amount/scaled amount;
- internal precision/external token precision;
- slot/tick/liquidity units;
- epoch/maturity/time units.

Look for places where one side rounds for user convenience and the other side
rounds for solvency.

### 5. Honest-But-Surprising Dependencies

Do not assume a dependency is malicious. Instead test legitimate edge behavior:

- ERC20 with fee, rebasing, missing return, callback, or transfer hook;
- ERC4626 with donation, paused redeem, delayed accounting, or virtual shares;
- oracle that is stale, zero, negative, inverted, delayed, or fallback-only;
- router that leaves residue;
- account system with delayed status checks;
- Solana account with valid owner but unexpected extension;
- governance/admin config at allowed extreme values.

The strongest findings often come from a dependency behaving legally but
outside the protocol's mental model.

### 6. Negative Space Audit

Search for code that is important because it is missing:

- no upper bound;
- no lower bound;
- no freshness check;
- no receiver binding;
- no market/pool/account binding;
- no "already initialized" guard;
- no callback post-condition;
- no conservation assertion;
- no stale queue cleanup;
- no decimal normalization;
- no post-liquidation solvency check.

Convert missing checks into concrete state properties, not vague claims.

### 7. Differential Reference Models

Build a smaller model that encodes the intended property, then compare the
protocol against it under weird sequences.

Useful reference models:

- solvency must not worsen after liquidation;
- total assets should cover redeemable shares within rounding tolerance;
- reward paid cannot exceed emitted reward plus dust tolerance;
- oracle value should be monotonic only when the source is monotonic;
- debt socialization must not make a solvent account insolvent without cause;
- cancel/refund/execute paths must conserve user value.

### 8. Scanner Inversion

For each scanner hit, ask why it might be boring. For each boring hit, ask what
nearby code the scanner cannot understand:

- deployment reachability;
- cross-contract state;
- time/order dependency;
- callback side effect;
- rounding after several conversions;
- dependency behavior across multiple calls;
- queue or maturity state;
- admin config extremes.

Do not chase generic hits unless they connect to a protocol-specific property.

## Creative Subagent Roles

Add these roles when multi-agent support is available:

- Novelty Hunter: generate protocol-specific hypotheses that are not direct
  copies of common checklists.
- Adversarial Reviewer: attack the current audit plan itself; identify which
  assumptions, skipped files, boring scanner hits, or false positives could
  hide a real issue.

Both roles must output local validation ideas, not just speculation.

## Output Format

For every creative hypothesis, record:

- hypothesis;
- protocol promise being challenged;
- code path;
- weird state or sequence;
- why common scanners may miss it;
- local test idea;
- expected security impact if true;
- fastest disproof path;
- candidate state.

Do not promote creative hypotheses to confirmed findings without the same proof
gates used for every other candidate.
