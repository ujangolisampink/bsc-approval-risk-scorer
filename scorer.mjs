#!/usr/bin/env node
/**
 * BSC Approval Risk Scorer — scores a BSC wallet's ERC-20 approval risk
 * 0–100 (100 = safest) and explains the score in plain words. Read-only:
 * never signs, never sends a transaction, never asks for a private key.
 *
 * Discovery (both read-only): (1) Approval events via eth_getLogs — finds
 * ANY (token, spender) pair; best-effort, public RPCs often rate-limit it.
 * (2) Curated allowance matrix — allowance() for 28 major tokens × 4
 * verified spenders; the reliable path (plain eth_call).
 *
 * Scoring (each factor capped): unlimited −8 each (max −40); unknown
 * spenders −4 (max −20); count −1 beyond 5 free (max −15); stale >180d
 * −2 (max −10); dust (balance 0) −2 (max −10). Score = max(0, 100 − total);
 * worst possible is 5 — see DESIGN.md.
 *
 * Usage: node scorer.mjs <wallet> [--days N] [--json] [--tokens a,b,c] [--debug]
 *        node scorer.mjs --demo   (scored example on synthetic data)
 * No dependencies. Node 18+ (global fetch).
 */

const RPCS = [
  "https://bsc.publicnode.com",
  "https://bsc-dataseed.bnbchain.org",
  "https://bsc-dataseed1.bnbchain.org",
  "https://bsc-dataseed2.bnbchain.org",
  "https://bsc-dataseed3.bnbchain.org",
  "https://bsc-dataseed4.bnbchain.org",
];

// Set by --debug: logs RPC activity to stderr. Off by default.
let DEBUG = false;
const debug = (...a) => { if (DEBUG) console.error("[debug]", ...a); };

// keccak256("Approval(address,address,uint256)")
const APPROVAL_TOPIC =
  "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const MAX_UINT256 = (1n << 256n) - 1n;
const BLOCKS_PER_DAY = 28800; // BSC ~3s blocks
const LOG_CHUNK = 10000; // blocks per eth_getLogs call
const LOG_CONCURRENCY = 4;

// ---- Curated lists (intentionally conservative — see DESIGN.md) ------------

// Major BSC tokens people actually approve. Addresses verified against the
// PancakeSwap token lists (default + extended, fetched 2026-11-15) — every
// address below was cross-checked, because an address copied from memory is
// how a wrong contract ends up in the list. Anything not on this list is
// still found by the event scan (source 1); this list only backs the
// fallback path.
const MAJOR_TOKENS = [
  { address: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", symbol: "WBNB" },
  { address: "0x55d398326f99059fF775485246999027B3197955", symbol: "USDT" },
  { address: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", symbol: "BUSD" },
  { address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", symbol: "USDC" },
  { address: "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", symbol: "CAKE" },
  { address: "0x2170Ed0880ac9A755fd29B2688956BD959F933F8", symbol: "ETH" },
  { address: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", symbol: "BTCB" },
  { address: "0x3EE2200Efb3400fAbB9AacF31297cBdD1d435D47", symbol: "ADA" },
  { address: "0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE", symbol: "XRP" },
  { address: "0x7083609fCE4d1d8Dc0C979AAb8c869Ea2C873402", symbol: "DOT" },
  { address: "0xbA2aE424d960c26247Dd6c32edC70B295c744C43", symbol: "DOGE" },
  { address: "0xF8A0BF9cF54Bb92F17374d9e9A321E6a111a51bD", symbol: "LINK" },
  { address: "0xBf5140A22578168FD562DCcF235E5D43A02ce9B1", symbol: "UNI" },
  { address: "0x4338665CBB7B2485A8855A139b75D5e34AB0DB94", symbol: "LTC" },
  { address: "0x8fF795a6F4D97E7887C79beA79aba5cc76444aDf", symbol: "BCH" },
  { address: "0x0D8Ce2A99Bb6e3B7Db580eD848240e4a0F9aE153", symbol: "FIL" },
  { address: "0x85EAC5Ac2F758618dFa09bDbe0cf174e7d574D5B", symbol: "TRX" },
  { address: "0x1CE0c2827e2eF14D5C4f29a091d735A204794041", symbol: "AVAX" },
  { address: "0x570A5D26f7765Ecb712C0924E4De545B89fD43dF", symbol: "SOL" },
  { address: "0x0Eb3a705fc54725037CC9e008bDede697f62F335", symbol: "ATOM" },
  { address: "0x1Fa4a73a3F0133f0025378af00236f3aBDEE5D63", symbol: "NEAR" },
  { address: "0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409", symbol: "FDUSD" },
  { address: "0x40af3827F39D0EAcBF4A168f8D4ee67c121D11c9", symbol: "TUSD" },
  { address: "0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", symbol: "DAI" },
  { address: "0x0555E30da8f98308EdB960aa94C0Db47230d2B9c", symbol: "WBTC" },
  { address: "0x25d887Ce7a35172C62FeBFD67a1856F20FaEbB00", symbol: "PEPE" },
  { address: "0x2859e4544C4bB03966803b044A93563Bd2D0DD4D", symbol: "SHIB" },
  { address: "0xfb5B838b6cfEEdC2873aB27866079AC55363D37E", symbol: "FLOKI" },
];

// Well-known, widely-used spenders. Every address verified on-chain or
// against the project's official deployment docs (PancakeSwap V2/V3 routers
// + 1inch v5 confirmed by eth_getCode; Uniswap V3 SwapRouter02 on BSC is
// 0xB971eF... per Uniswap's official BNB deployments page — NOT the mainnet
// address). Anything not on this list is UNKNOWN — a deliberate bias toward
// caution (see DESIGN.md).
const KNOWN_SPENDERS = new Map([
  ["0x10ed43c718714eb63d5aa57b78b54704e256024e", "PancakeSwap V2 Router"],
  ["0x1b81d678ffb9c0263b24a97847620c99d213eb14", "PancakeSwap V3 SwapRouter"],
  ["0x1111111254eeb25477b68fb85ed929f73a960582", "1inch Aggregation Router v5"],
  ["0xb971ef87ede563556b2ed4b1c0b0019111dd85d2", "Uniswap V3 SwapRouter02 (BSC)"],
]);

// ---- Scoring model ---------------------------------------------------------

const WEIGHTS = {
  unlimitedPer: 8, unlimitedCap: 40,
  unknownPer: 4, unknownCap: 20,
  countFree: 5, countPer: 1, countCap: 15,
  stalePer: 2, staleCap: 10, staleDays: 180,
  dustPer: 2, dustCap: 10,
};

function gradeBand(score) {
  if (score >= 90) return "Low risk";
  if (score >= 70) return "Moderate risk";
  if (score >= 40) return "Elevated risk";
  return "High risk";
}

// ---- Small helpers ---------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const padAddr = (a) => a.slice(2).toLowerCase().padStart(64, "0");
const isAddress = (s) => /^0x[0-9a-fA-F]{40}$/.test(s || "");
const hexToBigInt = (h) => (h ? BigInt(h) : 0n);
const fmtAmount = (raw, decimals) => {
  // Human-readable token amount, trimmed to 4 significant decimals.
  const d = 10n ** BigInt(decimals);
  const whole = raw / d;
  const frac = raw % d;
  const fracStr = frac.toString().padStart(decimals, "0").slice(0, 4).replace(/0+$/, "");
  return fracStr ? `${whole}.${fracStr}` : `${whole}`;
};

// ---- RPC client (batch + rotate + retry) -----------------------------------

let rpcIndex = 0;

async function rpcCall(url, method, params, timeoutMs = 20000) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
  return json.result;
}

async function rpcBatch(url, calls, timeoutMs = 30000) {
  // calls: [{method, params, tag}] -> Map tag -> result (throws per-call on error)
  // NOTE: public BSC RPCs rate-limit LARGE batches ("method eth_call in batch
  // triggered rate limit" for 100-call batches). Keep batches small (<=10)
  // and let rpcWithRetry rotate endpoints on failure. A top-level (non-array)
  // error response must THROW — silently dropping it made every allowance
  // read return "0 approvals" with no visible error.
  const body = calls.map((c, i) => ({ jsonrpc: "2.0", id: i, method: c.method, params: c.params }));
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const json = await res.json();
  if (!Array.isArray(json)) {
    if (json.error) throw new Error(json.error.message || "batch rpc error");
    throw new Error("unexpected non-array batch response");
  }
  debug("batch", url, "n=" + calls.length, "resp=" + json.length,
    "nonzero=" + json.filter((x) => x.result && x.result !== "0x" && BigInt(x.result) > 0n).length,
    "errors=" + json.filter((x) => x.error).length);
  const out = new Map();
  for (const item of json) {
    const tag = calls[item.id]?.tag;
    if (tag === undefined) continue;
    if (item.error) out.set(tag, { error: item.error.message || "rpc error" });
    else out.set(tag, { result: item.result });
  }
  // If EVERY item errored, this is a transport/endpoint failure (e.g. the
  // endpoint rejects batched eth_call), not per-item data — throw so the
  // caller rotates to the next RPC instead of silently returning nothing.
  const errored = [...out.values()].filter((v) => v.error).length;
  if (out.size > 0 && errored === out.size) {
    const first = [...out.values()].find((v) => v.error);
    throw new Error("batch all errored: " + (first.error || "unknown"));
  }
  return out;
}

async function rpcWithRetry(fn, attempts = 3) {
  // Rotate RPC endpoints on failure; back off on rate limits.
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    const url = RPCS[(rpcIndex + i) % RPCS.length];
    try {
      const out = await fn(url);
      rpcIndex = RPCS.indexOf(url);
      return out;
    } catch (e) {
      lastErr = e;
      if (/rate limit|limit exceeded|429/i.test(e.message)) await sleep(1500 * (i + 1));
      else await sleep(300 * (i + 1));
    }
  }
  throw lastErr;
}

const ethCall = (to, data, block = "latest") =>
  rpcWithRetry((url) => rpcCall(url, "eth_call", [{ to, data }, block]));

// ---- Token metadata --------------------------------------------------------

async function tokenMeta(address, owner) {
  // symbol(), decimals(), balanceOf(owner) — batched into one request.
  const symData = "0x95d89b41";
  const decData = "0x313ce567";
  const balData = "0x70a08231" + padAddr(owner);
  const calls = [
    { method: "eth_call", params: [{ to: address, data: symData }, "latest"], tag: "sym" },
    { method: "eth_call", params: [{ to: address, data: decData }, "latest"], tag: "dec" },
    { method: "eth_call", params: [{ to: address, data: balData }, "latest"], tag: "bal" },
  ];
  const out = await rpcWithRetry((url) => rpcBatch(url, calls));
  let symbol = "UNKNOWN";
  const symRaw = out.get("sym")?.result;
  if (symRaw && symRaw !== "0x") {
    try {
      const bytes = Buffer.from(symRaw.slice(2), "hex");
      // ABI string: offset(32) + length(32) + data; or raw bytes32 for old tokens.
      if (bytes.length >= 96) {
        const len = Number(BigInt("0x" + bytes.slice(32, 64).toString("hex")));
        symbol = bytes.slice(64, 64 + len).toString("utf8").replace(/\0/g, "").trim() || "UNKNOWN";
      } else {
        symbol = bytes.toString("utf8").replace(/\0/g, "").trim() || "UNKNOWN";
      }
    } catch { /* keep UNKNOWN */ }
  }
  let decimals = 18;
  const decRaw = out.get("dec")?.result;
  if (decRaw && decRaw !== "0x") {
    try { decimals = Number(hexToBigInt(decRaw)); } catch { /* keep 18 */ }
  }
  let balance = 0n;
  const balRaw = out.get("bal")?.result;
  if (balRaw && balRaw !== "0x") {
    try { balance = hexToBigInt(balRaw); } catch { /* keep 0 */ }
  }
  return { symbol, decimals, balance };
}

// ---- Discovery -------------------------------------------------------------

async function scanApprovalEvents(owner, head, days) {
  // Returns { pairs: Map "token|spender" -> { token, spender, lastBlock }, failed: string|null }
  const fromBlock = Math.max(0, head - days * BLOCKS_PER_DAY);
  const ownerTopic = "0x000000000000000000000000" + owner.slice(2).toLowerCase();
  const chunks = [];
  for (let from = fromBlock; from <= head; from += LOG_CHUNK) {
    chunks.push([from, Math.min(from + LOG_CHUNK - 1, head)]);
  }
  const pairs = new Map();
  let failed = null;
  let done = 0;
  let consecutiveFailures = 0;
  let aborted = false; // fast-fail: if the RPC rate-limits eth_getLogs, every
  // chunk fails the same way — stop after 3 consecutive failures.
  const workers = Array.from({ length: LOG_CONCURRENCY }, async () => {
    while (done < chunks.length && !aborted) {
      const idx = done++;
      const [from, to] = chunks[idx];
      try {
        const logs = await rpcWithRetry((url) =>
          rpcCall(url, "eth_getLogs", [{
            fromBlock: "0x" + from.toString(16),
            toBlock: "0x" + to.toString(16),
            topics: [APPROVAL_TOPIC, ownerTopic],
          }], 30000), 2);
        consecutiveFailures = 0;
        for (const log of logs || []) {
          const token = log.address.toLowerCase();
          const spender = ("0x" + log.topics[2].slice(26)).toLowerCase();
          const key = token + "|" + spender;
          const block = parseInt(log.blockNumber, 16);
          const prev = pairs.get(key);
          if (!prev || block > prev.lastBlock) pairs.set(key, { token, spender, lastBlock: block });
        }
      } catch (e) {
        // One bad chunk must not kill the scan; remember the failure.
        if (!failed) failed = e.message.slice(0, 120);
        if (/rate limit|limit exceeded|429/i.test(e.message)) {
          consecutiveFailures++;
          if (consecutiveFailures >= 3) aborted = true;
        } else {
          consecutiveFailures = 0;
        }
      }
      await sleep(150);
    }
  });
  await Promise.all(workers);
  if (pairs.size === 0 && failed) return { pairs, failed: "event scan failed: " + failed };
  return { pairs, failed: failed ? "event scan partially failed: " + failed : null };
}

async function scanCuratedMatrix(owner) {
  // allowance() for every (major token, known spender). Returns pairs found.
  const calls = [];
  for (const t of MAJOR_TOKENS) {
    for (const spender of KNOWN_SPENDERS.keys()) {
      const data = "0xdd62ed3e" + padAddr(owner) + padAddr(spender);
      calls.push({ method: "eth_call", params: [{ to: t.address, data }, "latest"], tag: t.address.toLowerCase() + "|" + spender });
    }
  }
  const found = new Map();
  const BATCH = 10; // small batches: public RPCs rate-limit large eth_call batches
  for (let i = 0; i < calls.length; i += BATCH) {
    const slice = calls.slice(i, i + BATCH);
    const out = await rpcWithRetry((url) => rpcBatch(url, slice));
    for (const [tag, v] of out) {
      if (v.error || !v.result || v.result === "0x") continue;
      const allowance = hexToBigInt(v.result);
      if (allowance > 0n) {
        const [token, spender] = tag.split("|");
        found.set(tag, { token, spender, allowance });
      }
    }
    await sleep(300);
  }
  debug("curated matrix: found", found.size, "nonzero allowances");
  return found;
}

// ---- Scoring ----------------------------------------------------------------

function scoreApprovals(approvals, headBlock) {
  // approvals: [{ token, spender, allowance, unlimited, known, balance, lastBlock|null, symbol }]
  const factors = {};
  const unlimited = approvals.filter((a) => a.unlimited);
  factors.unlimited = {
    count: unlimited.length,
    deduction: Math.min(unlimited.length * WEIGHTS.unlimitedPer, WEIGHTS.unlimitedCap),
    detail: unlimited.map((a) => `${a.symbol} -> ${a.spenderName || a.spender.slice(0, 10) + "..."}`),
  };
  const unknown = approvals.filter((a) => !a.known);
  factors.unknownSpender = {
    count: unknown.length,
    deduction: Math.min(unknown.length * WEIGHTS.unknownPer, WEIGHTS.unknownCap),
    detail: unknown.map((a) => `${a.symbol} -> ${a.spender.slice(0, 10)}...`),
  };
  const extra = Math.max(0, approvals.length - WEIGHTS.countFree);
  factors.approvalCount = {
    count: approvals.length,
    deduction: Math.min(extra * WEIGHTS.countPer, WEIGHTS.countCap),
    detail: `${approvals.length} active approvals (${WEIGHTS.countFree} free, ${extra} counted)`,
  };
  const staleDays = WEIGHTS.staleDays;
  const stale = approvals.filter((a) => a.lastBlock != null && (headBlock - a.lastBlock) / BLOCKS_PER_DAY > staleDays);
  const staleKnown = approvals.some((a) => a.lastBlock != null);
  factors.stale = {
    count: stale.length,
    deduction: staleKnown ? Math.min(stale.length * WEIGHTS.stalePer, WEIGHTS.staleCap) : 0,
    detail: staleKnown
      ? stale.map((a) => `${a.symbol} approved ${Math.floor((headBlock - a.lastBlock) / BLOCKS_PER_DAY)}d ago`)
      : "age unknown (event scan unavailable)",
  };
  const dust = approvals.filter((a) => a.balance === 0n);
  factors.dust = {
    count: dust.length,
    deduction: Math.min(dust.length * WEIGHTS.dustPer, WEIGHTS.dustCap),
    detail: dust.map((a) => `${a.symbol} (balance 0)`),
  };
  const totalDeduction = Object.values(factors).reduce((s, f) => s + f.deduction, 0);
  const score = Math.max(0, 100 - totalDeduction);
  return { score, band: gradeBand(score), totalDeduction, factors };
}

function revokeCalldata(spender) {
  // approve(spender, 0) — the standard revoke. Informational only; never sent.
  return "0x095ea7b3" + padAddr(spender) + "0".repeat(64);
}

function topActions(approvals, factors) {
  // Rank revokes by points recovered: unlimited first, then unknown, then dust.
  const ranked = approvals
    .map((a) => {
      let points = 0;
      if (a.unlimited) points += WEIGHTS.unlimitedPer;
      if (!a.known) points += WEIGHTS.unknownPer;
      if (a.balance === 0n) points += WEIGHTS.dustPer;
      return { ...a, points };
    })
    .filter((a) => a.points > 0)
    .sort((x, y) => y.points - x.points || (y.allowance > x.allowance ? 1 : -1));
  return ranked.slice(0, 3).map((a) => ({
    action: `Revoke ${a.symbol} approval to ${a.spenderName || a.spender}`,
    pointsRecovered: Math.min(a.points, 100),
    token: a.token,
    spender: a.spender,
    revokeCalldata: revokeCalldata(a.spender),
  }));
}

// ---- Demo (synthetic data, so a non-trivial score is visible) --------------

function demoReport() {
  const head = 133633090;
  const approvals = [
    { token: "0x55d398326f99059ff775485246999027b3197955", symbol: "USDT", spender: "0x10ed43c718714eb63d5aa57b78b54704e256024e", spenderName: "PancakeSwap V2 Router", known: true, unlimited: true, allowance: MAX_UINT256, balance: 1500n * 10n ** 6n, lastBlock: head - 200 * BLOCKS_PER_DAY, decimals: 6 },
    { token: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", symbol: "WBNB", spender: "0x9f4a3b7c2d1e0f8a6b5c4d3e2f1a0b9c8d7e6f5a4", known: false, unlimited: true, allowance: MAX_UINT256, balance: 2n * 10n ** 18n, lastBlock: head - 400 * BLOCKS_PER_DAY, decimals: 18 },
    { token: "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", symbol: "CAKE", spender: "0x1b81d678ffb9c0263b24a97847620c99d213eb", spenderName: "PancakeSwap V3 SwapRouter", known: true, unlimited: false, allowance: 1000n * 10n ** 18n, balance: 0n, lastBlock: head - 30 * BLOCKS_PER_DAY, decimals: 18 },
    { token: "0xe9e7cea3dedca5984780bafc599bd3cff091d6", symbol: "BUSD", spender: "0x1111111254eeb25477b68fb85ed929f73a960582", spenderName: "1inch Aggregation Router v5", known: true, unlimited: false, allowance: 500n * 10n ** 18n, balance: 120n * 10n ** 18n, lastBlock: head - 10 * BLOCKS_PER_DAY, decimals: 18 },
  ];
  const scored = scoreApprovals(approvals, head);
  return buildReport("0x0000000000000000000000000000000000000000", approvals, scored, head, {
    eventScan: "demo mode — synthetic approvals, not a real wallet",
    curatedPairs: approvals.length,
    note: "Demo data: 2 unlimited, 1 unknown spender, 1 dust approval, 1 stale approval.",
  });
}

// ---- Report -----------------------------------------------------------------

function buildReport(owner, approvals, scored, headBlock, coverage) {
  const rows = approvals.map((a) => ({
    token: a.token,
    symbol: a.symbol,
    spender: a.spender,
    spenderName: a.spenderName || null,
    spenderKnown: a.known,
    allowance: a.allowance.toString(),
    allowanceHuman: a.unlimited ? "UNLIMITED" : fmtAmount(a.allowance, a.decimals),
    unlimited: a.unlimited,
    tokenBalance: a.balance.toString(),
    tokenBalanceHuman: fmtAmount(a.balance, a.decimals),
    dust: a.balance === 0n,
    lastApprovalBlock: a.lastBlock ?? null,
    lastApprovalDaysAgo: a.lastBlock != null ? Math.floor((headBlock - a.lastBlock) / BLOCKS_PER_DAY) : null,
  }));
  return {
    tool: "bsc-approval-risk-scorer",
    version: "1.0.0",
    chain: "BSC (56)",
    wallet: owner,
    headBlock,
    score: scored.score,
    band: scored.band,
    totalDeduction: scored.totalDeduction,
    factors: scored.factors,
    approvals: rows,
    topActions: topActions(approvals, scored.factors),
    coverage,
    disclaimer: "Read-only audit. Revoke calldata is informational — verify the spender and token yourself before revoking anything, and never sign a transaction you do not understand.",
  };
}

function printHuman(report) {
  const L = [];
  L.push(`BSC Approval Risk — ${report.wallet}`);
  L.push(`Score: ${report.score}/100 — ${report.band}`);
  L.push(`Head block: ${report.headBlock} · ${report.approvals.length} active approval(s)`);
  L.push("");
  L.push("Why this score:");
  const f = report.factors;
  const lines = [
    [`Unlimited approvals`, f.unlimited.count, f.unlimited.deduction],
    [`Approvals to unknown spenders`, f.unknownSpender.count, f.unknownSpender.deduction],
    [`Total approval count`, f.approvalCount.count, f.approvalCount.deduction],
    [`Stale approvals (>180d)`, f.stale.count, f.stale.deduction],
    [`Dust approvals (balance 0)`, f.dust.count, f.dust.deduction],
  ];
  for (const [name, count, ded] of lines) {
    L.push(`  - ${name}: ${count}  ->  -${ded} pts`);
  }
  if (report.approvals.length === 0) {
    L.push("");
    L.push("No active approvals found. Nothing a spender can drain — that is why the score is 100.");
  }
  if (report.topActions.length > 0) {
    L.push("");
    L.push("Top 3 actions to raise the score:");
    report.topActions.forEach((a, i) => {
      L.push(`  ${i + 1}. ${a.action}  (+${a.pointsRecovered} pts)`);
      L.push(`     revoke calldata: ${a.revokeCalldata}  (verify before use; never sign blind)`);
    });
  }
  if (report.coverage.eventScan) {
    L.push("");
    L.push(`Coverage note: ${report.coverage.eventScan}`);
  }
  if (report.coverage.note) L.push(`Note: ${report.coverage.note}`);
  console.log(L.join("\n"));
}

// ---- Main -------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  DEBUG = args.includes("--debug");
  if (args.includes("--demo")) {
    const report = demoReport();
    if (args.includes("--json")) console.log(JSON.stringify(report, null, 2));
    else printHuman(report);
    return;
  }
  const address = args.find((a) => !a.startsWith("--"));
  if (!address || !isAddress(address)) {
    console.error("Usage: node scorer.mjs <wallet-address> [--days N] [--json] [--tokens a,b,c]");
    console.error("       node scorer.mjs --demo   (scored example on synthetic data)");
    process.exit(2);
  }
  const owner = address.toLowerCase();
  const daysIdx = args.indexOf("--days");
  const days = daysIdx >= 0 ? Math.max(1, Math.min(365, parseInt(args[daysIdx + 1], 10) || 30)) : 30;
  const extraTokens = [];
  const tokIdx = args.indexOf("--tokens");
  if (tokIdx >= 0 && args[tokIdx + 1]) {
    for (const t of args[tokIdx + 1].split(",")) if (isAddress(t.trim())) extraTokens.push(t.trim().toLowerCase());
  }
  if (extraTokens.length > 0) {
    for (const t of extraTokens) {
      if (!MAJOR_TOKENS.some((m) => m.address.toLowerCase() === t)) MAJOR_TOKENS.push({ address: t, symbol: "?" });
    }
  }

  const headHex = await rpcWithRetry((url) => rpcCall(url, "eth_blockNumber", []));
  const head = parseInt(headHex, 16);

  // 1) Event scan (best-effort) + 2) curated matrix.
  const { pairs, failed } = await scanApprovalEvents(owner, head, days);
  const curated = await scanCuratedMatrix(owner);

  // Merge: event pairs carry lastBlock; curated pairs carry allowance.
  const merged = new Map();
  for (const [key, p] of pairs) merged.set(key, { ...p, allowance: null });
  for (const [key, p] of curated) {
    const prev = merged.get(key);
    merged.set(key, prev ? { ...prev, allowance: p.allowance } : { ...p, lastBlock: null });
  }

  // 3) Resolve each pair: current allowance (if not already known) + token meta.
  const approvals = [];
  const pairList = [...merged.values()];
  const BATCH = 10; // small batches: public RPCs rate-limit large eth_call batches
  for (let i = 0; i < pairList.length; i += BATCH) {
    const slice = pairList.slice(i, i + BATCH);
    const calls = [];
    slice.forEach((p, j) => {
      if (p.allowance == null) {
        calls.push({ method: "eth_call", params: [{ to: p.token, data: "0xdd62ed3e" + padAddr(owner) + padAddr(p.spender) }, "latest"], tag: `allow:${j}` });
      }
    });
    let allowOut = new Map();
    if (calls.length > 0) allowOut = await rpcWithRetry((url) => rpcBatch(url, calls));
    for (let j = 0; j < slice.length; j++) {
      const p = slice[j];
      let allowance = p.allowance;
      if (allowance == null) {
        const v = allowOut.get(`allow:${j}`);
        if (!v || v.error || !v.result || v.result === "0x") continue;
        allowance = hexToBigInt(v.result);
      }
      if (allowance <= 0n) continue; // approval revoked or spent
      const meta = await tokenMeta(p.token, owner);
      const spenderKey = p.spender.toLowerCase();
      const spenderName = KNOWN_SPENDERS.get(spenderKey) || null;
      approvals.push({
        token: p.token,
        symbol: meta.symbol,
        decimals: meta.decimals,
        spender: p.spender,
        spenderName,
        known: spenderName !== null,
        allowance,
        unlimited: allowance === MAX_UINT256,
        balance: meta.balance,
        lastBlock: p.lastBlock ?? null,
      });
    }
    await sleep(100);
  }

  approvals.sort((a, b) => {
    const risk = (x) => (x.unlimited ? 4 : 0) + (!x.known ? 2 : 0) + (x.balance === 0n ? 1 : 0);
    return risk(b) - risk(a) || (b.allowance > a.allowance ? 1 : -1);
  });

  const scored = scoreApprovals(approvals, head);
  debug("merged pairs:", merged.size, "resolved approvals:", approvals.length);
  const coverage = {
    eventScan: failed || `scanned Approval events for the last ${days} day(s) (${pairs.size} pair(s) found)`,
    curatedPairs: curated.size,
    eventPairs: pairs.size,
    note: failed
      ? "Event scan unavailable (public RPC rate limits eth_getLogs from this network). Coverage is the curated token x known-spender matrix only — approvals to unknown spenders older than the scan window may be missed. Re-run from a network with a full RPC, or widen with --tokens, for fuller coverage."
      : null,
  };
  const report = buildReport(owner, approvals, scored, head, coverage);
  if (args.includes("--json")) console.log(JSON.stringify(report, null, 2));
  else printHuman(report);
}

main().catch((e) => {
  console.error("scorer failed:", e.message);
  process.exit(1);
});
