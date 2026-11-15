# BSC Approval Risk Scorer

Scores a BSC wallet's ERC-20 approval risk from **0 to 100** (100 = safest) and
explains the score in plain words — including the top 3 revokes that would
raise it, with the revoke calldata.

**Read-only.** It never signs, never sends a transaction, never asks for a
private key. It only reads public chain state through BSC RPCs.

## The problem

Every time you swap on a DEX or use a dApp, you `approve()` a contract to
spend your tokens. Most wallets approve **unlimited** amounts, and most
people forget the approvals exist. When one of those contracts gets hacked —
or turns out to be a phishing site — the attacker drains everything the
approval covers. The standard advice ("revoke your approvals") is useless
without knowing *which* approvals matter. This tool answers that: one number,
with the breakdown behind it.

## How it works

```
node scorer.mjs <wallet-address>
```

1. **Find approvals** (two sources, both read-only):
   - *Approval events* — `eth_getLogs` for `Approval(owner, spender, value)`
     where owner is the wallet. Finds **any** (token, spender) pair, including
     unknown dApps. Best-effort: many public RPCs rate-limit `eth_getLogs`.
   - *Curated allowance matrix* — `allowance()` checks for 28 major BSC
     tokens × 4 well-known spenders. The reliable path: plain `eth_call`,
     works on every public RPC. Token addresses verified against the
     PancakeSwap token lists; spender addresses verified on-chain / in the
     projects' official deployment docs.
2. **Score** (transparent, each factor capped):
   | Factor | Deduction |
   |---|---|
   | Unlimited approvals | −8 each, max −40 |
   | Approvals to unknown spenders | −4 each, max −20 |
   | Approval count (beyond 5 free) | −1 each, max −15 |
   | Stale approvals (>180 days) | −2 each, max −10 |
   | Dust approvals (token balance 0) | −2 each, max −10 |
   Score = max(0, 100 − total deductions). Bands: 90+ Low, 70–89 Moderate,
   40–69 Elevated, <40 High.
3. **Explain** — the human-readable output lists every factor with its raw
   numbers, then the top 3 revokes ranked by points recovered, each with
   `approve(spender, 0)` calldata. The calldata is **informational only**:
   verify the spender and token yourself before revoking anything, and never
   sign a transaction you do not understand.

## Example

```
$ node scorer.mjs --demo
BSC Approval Risk — 0x0000000000000000000000000000000000000000
Score: 74/100 — Moderate risk
Head block: 133633090 · 4 active approval(s)

Why this score:
  - Unlimited approvals: 2  ->  -16 pts
  - Approvals to unknown spenders: 1  ->  -4 pts
  - Total approval count: 4  ->  -0 pts
  - Stale approvals (>180d): 2  ->  -4 pts
  - Dust approvals (balance 0): 1  ->  -2 pts

Top 3 actions to raise the score:
  1. Revoke WBNB approval to 0x9f4a3b7c...  (+12 pts)
     revoke calldata: 0x095ea7b3...  (verify before use; never sign blind)
  ...
```

`--demo` runs the scorer on built-in synthetic data (2 unlimited, 1 unknown
spender, 1 dust, 1 stale) so the scoring is visible without a real wallet.

A real run against a wallet with one limited approval to a known router:

```
$ node scorer.mjs 0x715b8804fd26a4c0c165b957b806d23f7572f1ce --tokens 0xd2ba025dcf06f1aea9ab1b9126781fb9092a3c8e
Score: 100/100 — Low risk · 1 active approval(s)
```

## Options

```
node scorer.mjs <wallet-address> [--days N] [--json] [--tokens a,b,c] [--debug]
node scorer.mjs --demo [--json]
```

- `--days N` — how far back the Approval-event scan looks (default 30, max 365).
- `--json` — machine-readable report instead of the human summary.
- `--tokens a,b,c` — extra token addresses to check (comma-separated). Use it
  for tokens outside the built-in list of 28 majors.
- `--debug` — log RPC activity to stderr (endpoint, batch sizes, pairs found).

## Coverage — read this

The score is only as complete as the approval discovery, and the tool tells
you exactly what it covered in every report (`coverage` field):

- **Event scan works** (normal network): finds every approval, including to
  unknown spenders. This is the complete path.
- **Event scan rate-limited** (some public RPCs, including the shared-IP
  networks this was developed on): falls back to the curated 28-token ×
  4-spender matrix. Approvals to other tokens/spenders are **missed** — the
  report says so explicitly. Widen coverage with `--tokens`, or re-run from a
  network with a full RPC.

A score of 100 means "no risky approval *found*", not "no risky approval
*exists*". The tool never hides that distinction.

## What it cannot do

- It cannot find approvals the RPCs will not show it (see Coverage above).
- It cannot judge whether an *unknown* spender is malicious — it only knows
  the 4 verified spenders; everything else is "unknown" by design (a bias
  toward caution, not a verdict).
- It cannot revoke anything itself. Revoking is your transaction, your call.
- It does not check NFT approvals (`setApprovalForAll`) — ERC-20 only.
- It does not use any API key, indexer, or paid service. Only public BSC
  RPCs, only `eth_call` / `eth_getLogs` / `eth_blockNumber` / `eth_getCode`.

## Running it

No dependencies. Node 18+ (uses global `fetch`).

```
node scorer.mjs 0xYourWalletAddress
node scorer.mjs 0xYourWalletAddress --json > report.json
```

Sample real output: [`sample-report.json`](sample-report.json) — a live run
against `0xaefe73BF42f925dc704173db66428A1C8dA95Ae7` (score 100, 0 approvals;
a fresh wallet with no approval history).

## Design

[`DESIGN.md`](DESIGN.md) — why a single score is useful but dangerous if
unexplained, how the weights were chosen and what would change them, and how
a zkVerify proof could make an audit claim checkable in future.

## License

MIT. See [LICENSE](LICENSE).
