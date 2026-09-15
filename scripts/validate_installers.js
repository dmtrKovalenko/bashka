#!/usr/bin/env node
// Run `bashka --check` over every installer in installers.toml and show, at a glance, how each
// one is rated. Runs on Node.js or Bun.
//
// The verdict comes from bashka's EXIT CODE, which cannot be misparsed:
//   0 green · 1 neutral · 2 red · 3 strong gate (red) · 4 critical (dead)
// The finding names in the report are parsed only as extra detail; if that ever fails the verdict
// still stands. "ERROR" is reserved for real harness failures (no URL, fetch failed, binary would
// not run), never for an analysis result.
//
// Scripts are fetched once into target/installers/ (delete to refresh) and never executed.
// Usage: cargo build --release && node scripts/validate_installers.js [--markdown docs/validation.md]
//        (or: bun scripts/validate_installers.js --markdown docs/validation.md)

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const BIN = path.join(REPO, "target/release/bashka");
const CACHE = path.join(REPO, "target/installers");
const CONFIG = path.join(CACHE, "check.toml");

// Exit code -> verdict. `key` is the canonical severity used for grouping/sorting.
const VERDICTS = {
  0: { key: "GREEN", label: "green", rank: 0 },
  1: { key: "NEUTRAL", label: "neutral", rank: 1 },
  2: { key: "RED", label: "red", rank: 2 },
  3: { key: "RED", label: "red (strong gate)", rank: 2 },
  4: { key: "DEAD", label: "critical", rank: 3 },
};

// --- Colors (only when stdout is a real terminal and NO_COLOR is unset). ---
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  redBold: "\x1b[1;31m",
  gray: "\x1b[90m",
};
const paint = (code, s) => (useColor ? code + s + C.reset : String(s));
const STYLE = {
  GREEN: C.green,
  NEUTRAL: C.yellow,
  RED: C.red,
  DEAD: C.redBold,
  ERROR: C.gray,
};
const BADGE = { GREEN: "PASS", NEUTRAL: "meh ", RED: "FLAG", DEAD: "DEAD", ERROR: "ERR " };

// --- Minimal TOML reader: enough for installers.toml's `[tools.<slug>]` blocks. ---
function parseTools(text) {
  const tools = {};
  let slug = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const section = line.match(/^\[tools\.([^\]]+)\]$/);
    if (section) {
      slug = section[1];
      tools[slug] = {};
      continue;
    }
    if (line.startsWith("[")) {
      slug = null;
      continue;
    }
    if (!slug) continue;
    const kv = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
    if (kv) tools[slug][kv[1]] = parseValue(kv[2]);
  }
  return tools;
}

function parseValue(v) {
  const quote = v[0];
  if (quote === '"' || quote === "'") {
    let out = "";
    for (let i = 1; i < v.length; i++) {
      const c = v[i];
      if (c === quote) break;
      if (quote === '"' && c === "\\" && i + 1 < v.length) {
        const next = v[++i];
        out += { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\" }[next] ?? next;
      } else {
        out += c;
      }
    }
    return out;
  }
  return v.split("#")[0].trim();
}

function urlOf(command) {
  let m = command.match(/https?:\/\/[^\s"'|)]+/);
  if (m) return m[0];
  m = command.match(/\b([a-z0-9.-]+\.[a-z]{2,}\/[^\s"'|)]+)/); // `railway.com/install.sh`
  return m ? `https://${m[1]}` : null;
}

// Promise wrapper around spawn: feeds `input` on stdin, collects streams, enforces a timeout.
function run(cmd, args, { input = null, env = null, timeoutMs = 0, detached = false } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { env: env ?? process.env, detached });
    } catch (e) {
      return resolve({ code: -1, stdout: "", stderr: String(e) });
    }
    let stdout = "";
    let stderr = "";
    let timer = null;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    if (timeoutMs) timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("error", (e) => {
      if (timer) clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr + String(e) });
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr });
    });
    child.stdin.end(input ?? "");
  });
}

const countLines = (buf) => {
  let n = 0;
  for (const b of buf) if (b === 0x0a) n++;
  return n;
};

async function check(slug, tool) {
  const url = urlOf(tool.command || "");
  const row = { slug, url };
  if (!url) {
    row.status = "ERROR";
    row.error = "no URL in the install command";
    return row;
  }
  const file = path.join(CACHE, `${slug}.sh`);
  if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
    const fetch = await run("curl", ["-fsSL", "--max-time", "40", "-A", "bashka-validate", url, "-o", file], {
      timeoutMs: 60000,
    });
    if (fetch.code !== 0) {
      row.status = "ERROR";
      row.error = `fetch failed: ${fetch.stderr.trim().slice(0, 100)}`;
      return row;
    }
  }
  const source = fs.readFileSync(file);
  row.lines = countLines(source);

  const started = Date.now();
  let res;
  // A concurrent `cargo build` can be rewriting the binary as we exec it (ETXTBSY). Retry so a
  // parallel rebuild can't corrupt the run; we trust the exit code once we get real output.
  for (let attempt = 0; attempt < 5; attempt++) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "bashka-validate-"));
    res = await run(BIN, ["--check", "--config", CONFIG], {
      input: source,
      timeoutMs: 180000,
      // Detach from the controlling terminal: otherwise bashka writes its report to /dev/tty
      // (invisible to us) and only falls back to stderr when no tty exists.
      detached: true,
      env: { PATH: "/usr/bin:/bin", HOME: home, XDG_CONFIG_HOME: `${home}/.config` },
    });
    fs.rmSync(home, { recursive: true, force: true });
    if (VERDICTS[res.code] || res.stderr.trim()) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  row.ms = Date.now() - started;
  const report = res.stderr;
  fs.writeFileSync(path.join(CACHE, `${slug}.report.txt`), report);

  const verdict = VERDICTS[res.code];
  if (!verdict) {
    row.status = "ERROR";
    const tail = report.trim().split("\n").filter(Boolean).pop() || "no output (binary failed to run)";
    row.error = `bashka exit ${res.code}: ${tail.slice(0, 120)}`;
    return row;
  }
  row.status = verdict.key;
  row.rank = verdict.rank;
  row.verdictLabel = verdict.label;

  // Best-effort detail from the report; never affects the verdict.
  const counts = new Map();
  for (const m of report.matchAll(/^\s*\S+ \[(\w+)\]: /gm)) counts.set(m[1], (counts.get(m[1]) || 0) + 1);
  row.flags = [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  const tallies = report.match(/(\d+) {2}\S+ (\d+) {2}\S+ (\d+) {2}(?:GREEN|NEUTRAL|RED|DANGER)/);
  const layers = report.match(/across (\d+) layers/);
  row.layers = layers ? Number(layers[1]) : 1;
  row.notes = report
    .split("\n")
    .filter((l) => l.startsWith("chain:"))
    .map((l) => l.replace(/^chain:\s*/, "").trim());
  return row;
}

// --- Rendering ---
function statusCell(status) {
  return paint((STYLE[status] || "") + (useColor ? C.bold : ""), BADGE[status] || status);
}

function atAGlance(rows) {
  const order = ["DEAD", "RED", "NEUTRAL", "GREEN", "ERROR"];
  const by = (s) => rows.filter((r) => r.status === s);
  const total = rows.length;

  // Summary header.
  const lines = [""];
  lines.push(paint(C.bold, `bashka validation: ${total} installers`));
  lines.push("");
  const legend = [
    ["GREEN", "safe (green)"],
    ["NEUTRAL", "neutral"],
    ["RED", "flagged (red)"],
    ["DEAD", "critical (dead)"],
    ["ERROR", "harness error"],
  ];
  for (const [status, name] of legend) {
    const n = by(status).length;
    if (status === "ERROR" && n === 0) continue;
    const bar = "█".repeat(Math.round((n / Math.max(total, 1)) * 30));
    lines.push(
      `  ${statusCell(status)}  ${String(n).padStart(3)}  ${name.padEnd(16)} ${paint(STYLE[status] || C.dim, bar)}`,
    );
  }
  lines.push("");

  // Per-installer, grouped by severity (worst first).
  const width = Math.max(...rows.map((r) => r.slug.length));
  for (const status of order) {
    const group = by(status);
    if (!group.length) continue;
    for (const r of group) {
      const detail =
        r.status === "ERROR"
          ? paint(C.gray, r.error)
          : paint(C.dim, (r.flags || []).map(([f, n]) => (n > 1 ? `${f}×${n}` : f)).join(" "));
      lines.push(`  ${statusCell(status)}  ${r.slug.padEnd(width)}  ${detail}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function markdown(rows) {
  const out = [
    "| installer | verdict | layers | findings | notes |",
    "|---|---|---|---|---|",
  ];
  const order = { DEAD: 0, RED: 1, NEUTRAL: 2, GREEN: 3, ERROR: 4 };
  const sorted = [...rows].sort((a, b) => (order[a.status] - order[b.status]) || a.slug.localeCompare(b.slug));
  for (const r of sorted) {
    if (r.status === "ERROR") {
      out.push(`| ${r.slug} | ERROR | | | ${r.error} |`);
      continue;
    }
    const flags = (r.flags || []).map(([f, n]) => (n > 1 ? `${f}×${n}` : f)).join(", ");
    out.push(`| ${r.slug} | ${r.status} | ${r.layers} | ${flags} | ${(r.notes || []).join("; ")} |`);
  }
  return out.join("\n");
}

async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const drain = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, drain));
  return results;
}

function today() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function ensureBinary() {
  if (fs.existsSync(BIN)) return true;
  console.error(paint(C.redBold, `error: ${BIN} not found. Run \`cargo build --release\` first.`));
  return false;
}

async function main() {
  const argv = process.argv.slice(2);
  if (!ensureBinary()) process.exit(1);
  fs.mkdirSync(CACHE, { recursive: true });
  fs.writeFileSync(CONFIG, '[interaction]\nfollow_remote = "always"\n');

  const tools = parseTools(fs.readFileSync(path.join(REPO, "installers.toml"), "utf8"));
  const slugs = Object.keys(tools);
  const rows = await pool(slugs, 8, (slug) => check(slug, tools[slug]));
  fs.writeFileSync(path.join(CACHE, "results.json"), JSON.stringify(rows, null, 1));

  console.log(atAGlance(rows));

  const flagCounts = new Map();
  for (const r of rows) for (const [f, n] of r.flags || []) flagCounts.set(f, (flagCounts.get(f) || 0) + n);
  const topFlags = [...flagCounts.entries()].sort((a, b) => b[1] - a[1]);
  console.log(paint(C.dim, "findings across all installers:"));
  console.log(paint(C.dim, "  " + topFlags.map(([f, n]) => `${f} ${n}`).join("  ")));

  const errors = rows.filter((r) => r.status === "ERROR").length;
  const mdIdx = argv.indexOf("--markdown");
  if (mdIdx !== -1) {
    const target = argv[mdIdx + 1];
    const counts = { DEAD: 0, RED: 0, NEUTRAL: 0, GREEN: 0, ERROR: 0 };
    for (const r of rows) counts[r.status]++;
    const body =
      `# Corpus validation (${today()})\n\n` +
      "`bashka --check` (verdict taken from the exit code) over every installer in " +
      "`installers.toml`, with `follow_remote = \"always\"`; nothing is executed.\n\n" +
      "The harness feeds each script on stdin without a real `curl`, so origin-based trust is not " +
      "exercised: installers served from a vanity domain show NEUTRAL here but are GREEN under real " +
      "`curl <url> | bashka` use.\n\n" +
      `Verdicts: DEAD ${counts.DEAD}, RED ${counts.RED}, NEUTRAL ${counts.NEUTRAL}, GREEN ${counts.GREEN}` +
      (counts.ERROR ? `, ERROR ${counts.ERROR}` : "") +
      ".\n\n" +
      markdown(rows) +
      "\n";
    fs.writeFileSync(target, body);
    console.log(paint(C.dim, `\nwrote ${target}`));
  }

  // Exit non-zero only on a real harness failure, so `make validate` surfaces genuine breakage.
  process.exit(errors ? 1 : 0);
}

main();
