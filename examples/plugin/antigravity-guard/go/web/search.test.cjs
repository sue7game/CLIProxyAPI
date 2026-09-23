"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./search.js");

const credential = {
  name: "antigravity-ghthtc253@gmail.com.json",
  email: "ghthtc253@gmail.com",
  auth_index: "antigravity:demo",
  last_model: "gemini-2.5-pro",
};

test("matches credential names without separator or case sensitivity", () => {
  for (const query of ["ght.htc253", "gh.tht.c253", "GhthtC253"]) {
    assert.equal(globalThis.GuardSearch.matchesCredential(credential, query), true, query);
  }
});

test("matches the most recently used model", () => {
  assert.equal(globalThis.GuardSearch.matchesCredential(credential, "Gemini 2.5 Pro"), true);
});

test("matches proxy aliases with normalized separators", () => {
  const item = { ...credential, proxy_alias: "US Residential 01" };
  assert.equal(globalThis.GuardSearch.matchesCredential(item, "us.residential-01"), true);
});

test("treats empty and separator-only queries as no filter", () => {
  for (const query of ["", "   ", "---", "..."]) {
    assert.equal(globalThis.GuardSearch.matchesCredential(credential, query), true, query);
  }
});

test("matches every searchable credential identity field", () => {
  const item = {
    name: "antigravity-primary.json",
    email: "member@example.com",
    label: "Weekly Backup",
    auth_index: "a1b2-c3d4",
  };

  for (const query of ["MEMBER EXAMPLE", "weekly.backup", "A1B2 C3D4"]) {
    assert.equal(globalThis.GuardSearch.matchesCredential(item, query), true, query);
  }
});

test("rejects unrelated credentials", () => {
  assert.equal(globalThis.GuardSearch.matchesCredential(credential, "another-account"), false);
});
