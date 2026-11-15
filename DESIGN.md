# Design notes — BSC Approval Risk Scorer

## A single score is useful but dangerous if unexplained

A 0–100 score is the right *interface*: it lets a user compare wallets, track
risk over time, and decide "should I do something about this now?" in one
glance. But a bare number is also a lie by omission. A wallet can score 60
because it has five unlimited approvals to a DEX everyone uses, or because it
has one unlimited approval to a contract nobody has heard of — same number,
completely different risk. The score alone cannot distinguish those, and a
user who only sees the number will either panic over nothing or ignore a real
problem.

So the score is the headline, not the product. The product is the breakdown:
every factor with its raw count and its deduction, and the top 3 revokes
ranked by points recovered. If you disagree with a score, the breakdown shows
you exactly which judgement to argue with. If a factor is wrong (say, a
spender you trust is labelled "unknown"), you can see it and discount it.
A score you cannot audit is a black box; a score with its working shown is a
tool.

That is also why the report states its own coverage limits in plain words
(`coverage` field). A 100 that means "no risky approval found *in the
28-token × 4-spender matrix*" is honest; a 100 presented as "this wallet is
safe" would be a false claim. The tool never makes the second claim.

## How the weights were chosen — and what would change them

The model is deliberately simple: start at 100, subtract per-factor
deductions, each capped. Five factors, chosen because each maps to a distinct
failure mode:

- **Unlimited approvals (−8 each, cap −40).** The worst factor, by design.
  An unlimited approval lets a compromised spender drain the *entire* token
  balance — the loss is bounded only by what you hold. This is the dominant
  real-world exploit pattern (approval phishing). Five unlimited approvals
  hit the cap; beyond five, the marginal risk of the sixth is small compared
  with the first, hence the cap.
- **Unknown spenders (−4 each, cap −20).** An approval to a contract you
  cannot identify is the classic phishing vector. The list of 4 known
  spenders is intentionally tiny (verified routers only) — the bias is toward
  flagging, not toward trusting. The cap keeps a wallet with many small
  legitimate dApp approvals from being scored as harshly as one with
  unlimited approvals.
- **Approval count (−1 each beyond 5, cap −15).** Each approval is attack
  surface. The first 5 are free: normal DeFi usage (a router, an aggregator,
  a lending pool) should not be penalised. Beyond that you are accumulating
  exposure, and the deduction grows linearly until the cap.
- **Stale approvals (−2 each over 180 days, cap −10).** Old approvals you
  forgot about are the ones that get exploited — you no longer remember
  granting them, so you never think to revoke them. 180 days is a judgement
  call: long enough that a genuinely-used approval would usually have been
  refreshed, short enough to catch forgotten ones. Requires the event scan;
  when the scan is unavailable the factor is reported as "unknown" and
  deducts 0 (never penalise what you cannot measure).
- **Dust approvals (−2 each, cap −10).** An approval for a token you no
  longer hold is pure risk with zero utility — there is no reason to keep it.
  Cheap to fix, so it is weighted lightly, but it is the most common finding
  in practice.

The caps sum to 95, so the worst possible score under this model is 5, not 0.
That is intentional: 0 is reserved for a factor this model does not have — a
*known-malicious* spender. There is no blocklist in the tool, because a wrong
blocklist is worse than none (false accusations against legitimate contracts,
and false reassurance when a malicious contract is not yet listed). The
unknown-spender factor covers that risk conservatively instead.

What would change the weights: real loss data. If approval-phishing losses
were dominated by *limited* approvals rather than unlimited ones, the
unlimited weight should fall and the unknown-spender weight should rise. If
wallets with 20+ approvals were rarely exploited, the count cap should fall.
The weights are priors, not measurements — the README and the JSON report
expose them (`factors` with counts and deductions) precisely so they can be
argued with and revised.

## The known-spender list, and how it was verified

Every address in the tool was verified, because an address copied from memory
is how a wrong contract ends up in the list — and during development, five
token addresses and three spender addresses written from memory turned out
truncated or wrong. All 28 token addresses were cross-checked against the
PancakeSwap token lists and then confirmed on-chain (`symbol()` returns the
expected symbol). All 4 spenders were confirmed on-chain (`eth_getCode`
non-empty) or in the projects' official deployment docs — notably, Uniswap V3
SwapRouter02 on BSC is `0xB971eF...`, *not* the mainnet address; Uniswap's
own docs warn against assuming cross-chain addresses. A spender that cannot
be verified is left out (the 0x Exchange Proxy was dropped for exactly this
reason) — omitting a legitimate router only costs a false "unknown" flag,
while including a wrong address would mislabel real approvals.

## zkVerify: how an audit claim could become checkable (future work)

Today the report is a claim: "I ran this code against this wallet at this
block and got this score." Anyone reading it has to trust that the run
happened and the numbers are real. A zkVerify proof could turn that claim
into something checkable without revealing the wallet's full history:

- The scorer's decision rule (the five factors, the caps, the arithmetic) is
  a pure function of public inputs: the list of (token, spender, allowance,
  balance) tuples and the head block. That function could be expressed as a
  circuit, and the scorer could generate a Groth16 proof that "this score
  follows from these inputs under this rule". The proof would be submitted to
  zkVerify and the proof transaction referenced in the report.
- What that proves: the arithmetic is correct and the score was computed by
  the stated rule. What it does *not* prove: that the inputs are complete —
  a proof cannot attest that an approval was not missed, because completeness
  depends on the RPC and the discovery coverage, which live outside the
  circuit. The coverage statement would remain a human claim, not a proven
  one. That limitation matters and should not be papered over.
- The honest scope for a first proof is therefore narrow: prove the *scoring*
  (given these approvals, this score), not the *discovery* (these are all the
  approvals). That is still useful — it stops a forged score — but it is not
  a proof of safety, and the report should keep saying so.

This is deliberately not implemented here. The tool's value is the
transparent scoring model and the honest coverage reporting; a proof of the
arithmetic without a proof of completeness would invite exactly the
over-trusting the design above tries to avoid. When the discovery path is
more robust (a working event scan on the deployment network), the proof
becomes worth building — the scoring function is already pure and
deterministic, which is the hard part.
