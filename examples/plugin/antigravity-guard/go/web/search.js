"use strict";

(() => {
  function normalizeSearch(value) {
    return String(value ?? "")
      .normalize("NFKC")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, "");
  }

  function matchesCredential(item, query) {
    const plainQuery = String(query ?? "").trim().toLowerCase();
    if (!plainQuery) return true;

    const compactQuery = normalizeSearch(plainQuery);
    if (!compactQuery) return true;

    const fields = [item?.name, item?.email, item?.label, item?.auth_index, item?.last_model, item?.proxy_alias];
    return fields.some((field) => {
      const plainField = String(field ?? "").toLowerCase();
      if (plainField.includes(plainQuery)) return true;
      return normalizeSearch(plainField).includes(compactQuery);
    });
  }

  globalThis.GuardSearch = { normalizeSearch, matchesCredential };
})();
