"use strict";

(() => {
  const button = document.querySelector("#bulkQuotaButton");
  const progress = document.querySelector("#bulkQuotaProgress");
  globalThis.guardBulkQuota = globalThis.GuardBulkQuota.createBulkQuotaController({
    button,
    progress,
    request: globalThis.GuardAPI.request,
    intervalMs: 3000,
    showToast,
    handleError: handleAPIError,
    reloadState: () => loadState({ force: true }),
    setGlobalBusy: setBusy,
  });
  button.addEventListener("click", () => globalThis.guardBulkQuota.start([...state.selected]));
})();
