/* PatchPilot task form progressive enhancement (local asset, no dependencies).
 *
 * The server renders every field and the endpoint preview, so the form is fully
 * usable without JavaScript.  When this file loads it:
 *   - hides the endpoint fields that do not belong to the selected mode;
 *   - keeps the natural-language endpoint preview in sync;
 *   - collapses the Judge explanation until the Judge checkbox is checked.
 * It uses DOM text nodes only: no markup injection, no eval, no document.write and no
 * external requests.
 */
(function () {
  "use strict";

  var form = document.querySelector("[data-task-form]");
  if (!form) {
    return;
  }
  form.classList.add("task-form-enhanced");

  var modeSelect = form.querySelector('select[name="mode"]');
  var modeFields = form.querySelectorAll("[data-modes]");
  var preview = form.querySelector("[data-endpoint-preview]");
  var previewText = form.querySelector("[data-endpoint-text]");
  var previewHint = form.querySelector("[data-endpoint-hint]");
  var previewMode = form.querySelector("[data-endpoint-mode]");
  var defaultBase = preview ? preview.getAttribute("data-default-base") || "main" : "main";

  function fieldValue(name) {
    var element = form.elements[name];
    if (!element) {
      return "";
    }
    var value = typeof element.value === "string" ? element.value : "";
    return value.trim();
  }

  function selectedMode() {
    return modeSelect ? modeSelect.value : "";
  }

  function modeList(element) {
    var raw = element.getAttribute("data-modes") || "";
    return raw
      .split(",")
      .map(function (item) {
        return item.trim();
      })
      .filter(function (item) {
        return item.length > 0;
      });
  }

  function endpointPreview(mode) {
    var base = fieldValue("base_ref") || defaultBase;
    var commit = fieldValue("commit_ref");
    var range = fieldValue("range_spec");
    var parent = fieldValue("parent_index");
    if (mode === "worktree-net") {
      return {
        text: "HEAD → 工作区（含未提交与未忽略的未跟踪改动）",
        hint: "默认净差异：比较 HEAD 提交树与当前工作区。"
      };
    }
    if (mode === "staged") {
      return {
        text: "HEAD → 暂存区（index）",
        hint: "只比较已暂存内容，工作区未暂存改动不参与。"
      };
    }
    if (mode === "working-tree") {
      return {
        text: "暂存区（index） → 工作区",
        hint: "比较已暂存内容与当前工作区；可选包含未跟踪文件。"
      };
    }
    if (mode === "base") {
      return {
        text: base + "（合并基线） → HEAD",
        hint: "只读取提交树：merge-base(" + base + ", HEAD) → HEAD，工作区状态不影响结果。"
      };
    }
    if (mode === "commit") {
      var reference = commit || "（待填写提交引用）";
      var suffix = parent ? "（父提交 " + parent + "）" : "（父提交）";
      return {
        text: reference + "^" + suffix + " → " + reference,
        hint: "只读取 Git 对象；merge commit 建议在“高级选项”里选择父提交序号。"
      };
    }
    if (mode === "range") {
      if (range.indexOf("...") !== -1) {
        var three = range.split("...");
        var leftThree = (three[0] || "").trim() || "A";
        var rightThree = (three[1] || "").trim() || "B";
        return {
          text: leftThree + " 的合并基线 → " + rightThree,
          hint: "三点区间 A...B：比较共同祖先与 B。"
        };
      }
      if (range.indexOf("..") !== -1) {
        var two = range.split("..");
        var leftTwo = (two[0] || "").trim() || "A";
        var rightTwo = (two[1] || "").trim() || "B";
        return {
          text: leftTwo + " → " + rightTwo,
          hint: "两点区间 A..B：比较两个提交树。"
        };
      }
      return {
        text: "（输入 A..B 或 A...B）",
        hint: "range 模式必须提供非空的 A..B 或 A...B。"
      };
    }
    return { text: "-", hint: "" };
  }

  function applyMode() {
    var mode = selectedMode();
    Array.prototype.forEach.call(modeFields, function (element) {
      var modes = modeList(element);
      if (modes.length > 0) {
        element.hidden = modes.indexOf(mode) === -1;
      }
    });
    var labels = {
      "worktree-net": "工作区净差异",
      "staged": "仅暂存区",
      "working-tree": "暂存区 → 工作区",
      "base": "分支基线",
      "commit": "单提交",
      "range": "提交区间"
    };
    if (previewMode) {
      previewMode.textContent = labels[mode] || mode;
    }
    updatePreview(mode);
  }

  function updatePreview(mode) {
    if (!previewText || !previewHint) {
      return;
    }
    var data = endpointPreview(mode);
    previewText.textContent = data.text;
    previewHint.textContent = data.hint;
  }

  function applyJudge() {
    var toggle = form.querySelector("[data-judge-toggle]");
    var details = form.querySelector("[data-judge-details]");
    if (!details) {
      return;
    }
    var enabled = !!(toggle && toggle.checked && !toggle.disabled);
    details.hidden = !enabled;
  }

  if (modeSelect) {
    modeSelect.addEventListener("change", applyMode);
  }
  form.addEventListener("input", function (event) {
    if (event.target && event.target.name !== "mode") {
      updatePreview(selectedMode());
    }
  });
  var judgeToggle = form.querySelector("[data-judge-toggle]");
  if (judgeToggle) {
    judgeToggle.addEventListener("change", applyJudge);
  }

  applyMode();
  applyJudge();
})();
