/* Keep startup recovery independent of the application and its helper scripts. */
"use strict";

(() => {
  const loading = document.getElementById("view-loading");
  const title = document.getElementById("startup-title");
  const detail = document.getElementById("startup-detail");
  let ready = false;

  function failed() {
    if (ready) return;
    loading.hidden = false;
    title.textContent = "Could not finish loading the application";
    detail.textContent = "Some application files did not load correctly. Reload to fetch the latest version. Your saved settings and transactions are unchanged.";
  }

  // Capture both script download failures and errors while app.js initializes.
  window.addEventListener("error", (event) => {
    if (event.target instanceof HTMLScriptElement || event instanceof ErrorEvent) failed();
  }, true);
  window.addEventListener("unhandledrejection", failed);
  const timeout = window.setTimeout(failed, 15000);
  window.addEventListener("squareprotect:ready", () => {
    ready = true;
    window.clearTimeout(timeout);
    loading.hidden = true;
  }, { once: true });

  document.getElementById("startup-reload").addEventListener("click", (event) => {
    event.preventDefault();
    const url = new URL(window.location.href);
    url.searchParams.set("reload", Date.now().toString());
    window.location.replace(url.href);
  });
})();
