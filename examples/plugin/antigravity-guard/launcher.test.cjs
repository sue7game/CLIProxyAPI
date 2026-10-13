const assert = require("node:assert/strict");
const { mkdtempSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");

const root = resolve(__dirname, "../../..");
const script = readFileSync(join(root, "run-antigravity-guard-macos.sh"), "utf8");
const detectPort = script.match(/^detect_port\(\) \{\n[\s\S]*?^\}/m)?.[0];
assert.ok(detectPort, "launcher must define detect_port");

const cases = [
  ["legacy", "port: 9001\nplugins:\n  enabled: true\n", "9001"],
  ["v8", "server:\n  host: localhost\n  port: 9002 # listener\n", "9002"],
  ["v8 flow map", "server: {port: 9002}\n", "9002"],
  ["quoted v8 keys", "\"server\": {'port': 9002}\n", "9002"],
  ["v8 precedence", "server:\n  port: 9003\nport: 9001\n", "9003"],
  ["v8 flow precedence", "port: 9001\nserver: {port: 9003}\n", "9003"],
  ["legacy fallback", "port: 9001\nserver:\n  host: localhost\n", "9001"],
  ["unrelated port", "server:\n  host: localhost\nother:\n  port: 9999\n", "0"],
  ["null precedence", "port: 9001\nserver: {port: null}\n", "0"],
  ["empty precedence", "port: 9001\nserver:\n  port:\n", "0"],
  ["zero precedence", "port: 9001\nserver: {port: 0}\n", "0"],
  ["merged v8 map", "defaults: &listener {port: 9002}\nserver: {<<: *listener}\n", "9002"],
];

for (const [name, yaml, expected] of cases) {
  test(`launcher detects ${name} port without starting a service`, () => {
    const directory = mkdtempSync(join(tmpdir(), "guard-launcher-"));
    try {
      const config = join(directory, "config.yaml");
      writeFileSync(config, yaml, "utf8");
      const result = spawnSync("bash", ["-c", `${detectPort}\ndetect_port`], {
        cwd: directory,
        encoding: "utf8",
        env: { ...process.env, ROOT_DIR: root, CONFIG_FILE: config },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), expected);
      assert.equal(readFileSync(config, "utf8"), yaml, "port detection must not rewrite configuration");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("launcher rejects invalid v8 port instead of falling back to legacy", () => {
  const directory = mkdtempSync(join(tmpdir(), "guard-launcher-"));
  try {
    const config = join(directory, "config.yaml");
    writeFileSync(config, "port: 9001\nserver: {port: bad}\n", "utf8");
    const result = spawnSync("bash", ["-c", `${detectPort}\ndetect_port`], {
      cwd: directory,
      encoding: "utf8",
      env: { ...process.env, ROOT_DIR: root, CONFIG_FILE: config },
    });
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /port 必须是整数或空值/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
