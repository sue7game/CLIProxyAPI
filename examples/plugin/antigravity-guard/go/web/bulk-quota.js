"use strict";

(() => {
  const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

  function createBulkQuotaController(options) {
    const intervalMs = Math.max(1000, Number(options.intervalMs || 3000));
    const waitForNext = options.wait || wait;
    let busy = false;

    function render(selectedCount, globalBusy = false) {
      options.button.disabled = busy || globalBusy || selectedCount === 0;
      if (!busy) options.button.textContent = "获取选中额度";
    }

    async function start(authIndices) {
      const queue = [...new Set(authIndices || [])].filter(Boolean);
      if (busy) return;
      if (!queue.length) {
        options.showToast("请先选择凭证", true);
        return;
      }

      busy = true;
      options.setGlobalBusy(true);
      const failures = [];
      try {
        for (let index = 0; index < queue.length; index += 1) {
          const current = index + 1;
          options.button.textContent = `获取额度 ${current}/${queue.length}`;
          options.progress.textContent = `正在获取第 ${current} 个，共 ${queue.length} 个`;
          try {
            await options.request("/quota", {
              method: "POST",
              body: JSON.stringify({ auth_index: queue[index] }),
            });
          } catch (error) {
            failures.push({ authIndex: queue[index], error });
          }
          if (current < queue.length) await waitForNext(intervalMs);
        }
        await options.reloadState();
        const successCount = queue.length - failures.length;
        options.showToast(
          failures.length ? `额度获取完成：成功 ${successCount} 个，失败 ${failures.length} 个` : `已获取 ${successCount} 个凭证的额度`,
          failures.length > 0,
        );
      } catch (error) {
        options.handleError(error);
      } finally {
        busy = false;
        options.progress.textContent = "";
        options.setGlobalBusy(false);
        render(queue.length, false);
      }
    }

    return { start, render, isBusy: () => busy };
  }

  globalThis.GuardBulkQuota = { createBulkQuotaController };
})();
