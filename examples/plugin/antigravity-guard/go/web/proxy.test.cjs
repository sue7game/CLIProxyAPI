"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./proxy.js");
require("./format.js");

const proxy = globalThis.GuardProxy;
const view = globalThis.GuardView;

test("proxy choices deduplicate the same proxy id and exclude direct routes", () => {
  const choices = globalThis.GuardProxy.choicesForCredentials([
    { auth_index: "ag-1", name: "one.json", proxy_id: "proxy-alpha", proxy_alias: "美国住宅", effective_proxy: "socks5://u:***@one:1080", proxy_reusable: true },
    { auth_index: "ag-2", name: "two.json", proxy_id: "proxy-alpha", proxy_alias: "美国住宅", effective_proxy: "socks5://u:***@one:1080", proxy_reusable: true },
    { auth_index: "ag-3", name: "three.json", effective_proxy: "强制直连", proxy_reusable: false },
  ]);
  assert.equal(choices.filter((choice) => choice.value.startsWith("copy:")).length, 1);
  assert.match(choices[1].label, /美国住宅/);
  assert.doesNotMatch(choices[1].label, /#-alpha|socks5:/);
  assert.equal(choices.some((choice) => choice.value === "copy:ag-3"), false);
});

test("proxy labels show only the alias when one is configured", () => {
  assert.equal(proxy.proxyLabel({
    proxy_id: "proxy-alpha",
    proxy_alias: "aws-3-代理",
    effective_proxy: "socks5://u:***@one:1080",
  }), "aws-3-代理");
});

test("masked-equal proxies stay distinct when proxy ids differ", () => {
  const choices = globalThis.GuardProxy.choicesForCredentials([
    { auth_index: "ag-1", name: "one.json", proxy_id: "proxy-secret-a", effective_proxy: "socks5://u:***@one:1080", proxy_reusable: true },
    { auth_index: "ag-2", name: "two.json", proxy_id: "proxy-secret-b", effective_proxy: "socks5://u:***@one:1080", proxy_reusable: true },
  ]);
  assert.equal(choices.filter((choice) => choice.value.startsWith("copy:")).length, 2);
});

test("copy payload sends only the source credential reference", () => {
  assert.deepEqual(globalThis.GuardProxy.actionPayload("target", "copy:source"), {
    auth_index: "target",
    mode: "copy",
    source_auth_index: "source",
  });
});

test("filter values use proxy ids instead of masked addresses", () => {
  const options = globalThis.GuardProxy.filterOptions([
    { proxy_id: "proxy-a", proxy_alias: "A", proxy: "socks5://u:***@same:1080" },
    { proxy_id: "proxy-b", proxy_alias: "B", proxy: "socks5://u:***@same:1080" },
  ]);
  assert.deepEqual(new Set(options.map((option) => option.value)), new Set(["proxy-a", "proxy-b"]));
  assert.equal(globalThis.GuardProxy.matchesProxy({ proxy_id: "proxy-b" }, "proxy-b"), true);
  assert.equal(globalThis.GuardProxy.matchesProxy({ proxy_id: "proxy-a" }, "proxy-b"), false);
});

test("legacy filter keys keep direct routes from different sources separate", () => {
  const address = "强制直连";
  const options = globalThis.GuardProxy.filterOptions([
    { source: "credential", proxy: address },
    { source: "config", proxy: address },
  ]);

  assert.equal(new Set(options.map((option) => option.value)).size, 2);
  const credentialKey = globalThis.GuardProxy.proxyKey({ proxy_source: "credential", effective_proxy: address });
  const configKey = globalThis.GuardProxy.proxyKey({ proxy_source: "config", effective_proxy: address });
  assert.equal(globalThis.GuardProxy.matchesProxy({ proxy_source: "credential", effective_proxy: address }, credentialKey), true);
  assert.equal(globalThis.GuardProxy.matchesProxy({ proxy_source: "config", effective_proxy: address }, credentialKey), false);
  assert.notEqual(credentialKey, configKey);
});

test("creates and posts an in-memory proxy alias", async () => {
  const payload = globalThis.GuardProxy.aliasPayload(" proxy-a ", " 美国住宅 01 ");
  const calls = [];
  await globalThis.GuardProxy.postProxyAlias(async (...args) => {
    calls.push(args);
    return payload;
  }, payload);
  assert.deepEqual(payload, { proxy_id: "proxy-a", alias: "美国住宅 01" });
  assert.deepEqual(calls, [["/proxy/alias", { method: "POST", body: JSON.stringify(payload) }]]);
});

test("empty alias clears it and invalid aliases are rejected", () => {
  assert.deepEqual(globalThis.GuardProxy.aliasPayload("proxy-a", "   "), { proxy_id: "proxy-a", alias: "" });
  assert.equal(globalThis.GuardProxy.aliasPayload("proxy-a", "🌍".repeat(40)).alias, "🌍".repeat(40));
  assert.throws(() => globalThis.GuardProxy.aliasPayload("", "name"), /代理标识无效/);
  assert.throws(() => globalThis.GuardProxy.aliasPayload("proxy-a", "🌍".repeat(41)), /40 个字符/);
});

test("proxy cards show only configured and in-use credential counts", () => {
  const credentials = [
    { proxy_id: "proxy-a", effective_disabled: false },
    { proxy_id: "proxy-a", effective_disabled: false, cooldown: { action: "priority" } },
    { proxy_id: "proxy-a", effective_disabled: true, cooldown: { action: "disable", trigger: "five_hour_quota_empty" } },
    { proxy_id: "proxy-a", effective_disabled: true, weekly_quota: { empty: false } },
    { proxy_id: "proxy-a", effective_disabled: true },
    {
      proxy_id: "proxy-a",
      effective_disabled: true,
      cooldown: { trigger: "weekly_quota_empty", manual_release_required: true },
    },
  ];
  const counts = proxy.inUseCounts(credentials, view.isCredentialInUse);
  const html = proxy.proxyCardHTML({
    proxy_id: "proxy-a",
    proxy: "socks5://proxy.example:1080",
    source: "credential",
    credentials: 6,
  }, counts.get("proxy-a"), false, view.esc, view.sourceLabel);

  assert.equal(counts.get("proxy-a"), 2);
  assert.match(html, /配置凭证<strong>6<\/strong>/);
  assert.match(html, /使用\/5 小时冷却<strong>2<\/strong>/);
  assert.doesNotMatch(html, />最近<|>失败<|>429</);
});
