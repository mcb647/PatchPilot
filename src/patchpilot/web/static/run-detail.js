/*
 * PatchPilot run detail: load one file diff only when its <details> is opened.
 *
 * The fetched body is a server-rendered, auto-escaped HTML fragment from
 * /runs/{run_id}/changes/{change_id}?fragment=1.  Long files page their hunks
 * inside the fragment; the pager links carry a data-fragment-href that this
 * script follows without leaving the Run page (the href itself remains a full
 * change page for no-script users).  No external resources, no dynamic code
 * execution, injection only from the server response.
 */
(function () {
  "use strict";

  function showFallback(details, slot) {
    var fallback = details.getAttribute("data-fallback");
    var source = details.getAttribute("data-src");
    slot.textContent = "";
    var link = document.createElement("a");
    link.href = fallback || source || "#";
    link.textContent = "差异加载失败，打开该文件差异页";
    slot.appendChild(link);
  }

  function fetchFragment(url, onSuccess, onError) {
    fetch(url, {
      credentials: "same-origin",
      headers: { "X-Requested-With": "patchpilot-run-detail" }
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        var contentType = response.headers.get("Content-Type") || "";
        if (contentType.indexOf("text/html") !== 0) {
          throw new Error("unexpected content type");
        }
        return response.text();
      })
      .then(onSuccess)
      .catch(onError);
  }

  function wireHunkPager(details, slot) {
    var links = slot.querySelectorAll("a[data-fragment-href]");
    Array.prototype.forEach.call(links, function (link) {
      link.addEventListener("click", function (event) {
        event.preventDefault();
        var url = link.getAttribute("data-fragment-href");
        if (!url) {
          return;
        }
        slot.setAttribute("aria-busy", "true");
        slot.textContent = "正在加载差异…";
        fetchFragment(
          url,
          function (html) {
            slot.innerHTML = html;
            slot.removeAttribute("aria-busy");
            wireHunkPager(details, slot);
          },
          function () {
            slot.removeAttribute("aria-busy");
            showFallback(details, slot);
          }
        );
      });
    });
  }

  function loadDiff(details) {
    if (details.dataset.loaded === "1" || details.dataset.loading === "1") {
      return;
    }
    var slot = details.querySelector(".diff-slot");
    var source = details.getAttribute("data-src");
    if (!slot || !source) {
      return;
    }
    details.dataset.loading = "1";
    slot.textContent = "正在加载差异…";
    fetchFragment(
      source,
      function (html) {
        slot.innerHTML = html;
        details.dataset.loaded = "1";
        details.dataset.loading = "0";
        wireHunkPager(details, slot);
      },
      function () {
        details.dataset.loading = "0";
        showFallback(details, slot);
      }
    );
  }

  function enhance() {
    var nodes = document.querySelectorAll("details[data-src]");
    Array.prototype.forEach.call(nodes, function (details) {
      details.addEventListener("toggle", function () {
        if (details.open) {
          loadDiff(details);
        }
      });
      if (details.open) {
        loadDiff(details);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", enhance);
  } else {
    enhance();
  }
})();
