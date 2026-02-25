import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

function read(path) {
  return readFileSync(join(process.cwd(), path), "utf8");
}

function testMainEntry() {
  const text = read("src/main.tsx");
  assert.match(text, /document\.getElementById\("root"\)/);
  assert.match(text, /createRoot\(container\)\.render\(/);
}

function testFlowModes() {
  const text = read("src/features/app/model.ts");
  const expectedModes = [
    "classic",
    "offer",
    "hybrid",
    "target",
    "phrase",
    "guaranteed",
    "space"
  ];

  for (const mode of expectedModes) {
    assert.match(text, new RegExp(`"${mode}"`));
  }
}

try {
  testMainEntry();
  testFlowModes();
  console.log("smoke tests ok (2 checks)");
} catch (err) {
  console.error("smoke tests failed");
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
