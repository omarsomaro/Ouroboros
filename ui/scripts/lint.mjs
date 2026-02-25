import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC_DIR = "src";
const FORBIDDEN_PATTERNS = [
  { name: "console.log", regex: /\bconsole\.log\s*\(/g },
  { name: "debugger", regex: /\bdebugger\s*;/g }
];

function collectFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      out.push(...collectFiles(full));
      continue;
    }
    if (full.endsWith(".ts") || full.endsWith(".tsx")) {
      out.push(full);
    }
  }
  return out;
}

const files = collectFiles(SRC_DIR);
const violations = [];

for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const pattern of FORBIDDEN_PATTERNS) {
    const match = pattern.regex.exec(text);
    pattern.regex.lastIndex = 0;
    if (match) {
      const line = text.slice(0, match.index).split("\n").length;
      violations.push(`${file}:${line} contains ${pattern.name}`);
    }
  }
}

if (violations.length > 0) {
  console.error("lint failed:");
  for (const v of violations) console.error(`- ${v}`);
  process.exit(1);
}

console.log(`lint ok (${files.length} files scanned)`);
