/*
 * PatchPilot impact topology (progressive enhancement).
 *
 * Reads the persisted evidence JSON rendered into #impact-graph[data-graph],
 * draws it with the locally bundled Cytoscape.js and fills the evidence panel.
 * The server-rendered path list / evidence tables below the canvas remain the
 * no-JavaScript fallback. No network requests and no dynamic code execution;
 * all text is written with textContent (the JSON comes from escaped HTML data).
 */
(function () {
  "use strict";

  var KIND_CLASS = { call: "edge-call", import: "edge-import", global_read: "edge-global_read" };
  var RESOLUTION_LABEL = { resolved: "已解析", unresolved: "未解析" };
  var VERDICT_LABEL = { affected: "可能受影响", unaffected: "判断为不受影响", uncertain: "无法判断" };

  function text(tag, value, className) {
    var node = document.createElement(tag);
    if (value !== null && value !== undefined) {
      node.textContent = String(value);
    }
    if (className) {
      node.className = className;
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function graphNotice(message, warning) {
    var notice = document.getElementById("impact-filter-notice");
    if (!notice) {
      return;
    }
    if (!message) {
      notice.hidden = true;
      notice.textContent = "";
      return;
    }
    notice.hidden = false;
    notice.className = warning ? "notice notice-warn" : "notice notice-info";
    notice.textContent = message;
  }

  function evidencePanel(graph, evidence) {
    var panel = document.getElementById("impact-evidence");
    if (!panel) {
      return;
    }
    return function render(kind, item) {
      clear(panel);
      panel.appendChild(text("h3", kind === "node" ? "这段代码的位置" : "这条关系的依据"));

      var list = document.createElement("dl");
      function add(key, value, container) {
        if (value === null || value === undefined || value === "") {
          value = "-";
        }
        (container || list).appendChild(text("dt", key));
        (container || list).appendChild(text("dd", value));
      }
      var technical = document.createElement("details");
      technical.appendChild(text("summary", "技术信息"));
      var raw = document.createElement("dl");
      technical.appendChild(raw);

      var candidateIds = item.candidate_ids || [];
      var tests = [];
      var judge = [];
      var seenTests = {};
      candidateIds.forEach(function (candidateId) {
        (evidence.candidate_tests && evidence.candidate_tests[candidateId] || []).forEach(function (test) {
          var key = (test.test_path || "") + "::" + (test.qualified_name || "");
          if (!seenTests[key]) {
            seenTests[key] = true;
            tests.push(test);
          }
        });
        if (evidence.candidate_judge && evidence.candidate_judge[candidateId]) {
          judge.push({ candidate_id: candidateId, verdict: evidence.candidate_judge[candidateId] });
        }
      });

      if (kind === "node") {
        add("名称", item.label);
        add("文件", item.path);
        add("行号", item.line);
        add("比较范围", item.side === "after" ? "改动后" : "改动前");
        add("与改动的关系", item.depth === 0 ? "当前查看的改动" : "相隔 " + item.depth + " 层关系");
        if (item.missing) add("留存状态", "历史中只保留了引用");
        add("符号 ID", item.id, raw);
        add("符号类型", item.kind, raw);
        add("关联改动 ID", (item.seed_ids || []).join("、"), raw);
      } else {
        var verb = { call: "调用了", import: "导入了", global_read: "读取了" }[item.edge_kind];
        var caller = item.caller_label || "关联代码";
        var callee = item.callee_label || item.target_label || "目标代码";
        panel.appendChild(text("p", verb ? caller + " " + verb + " " + callee : caller + " 依赖 " + callee));
        add("比较范围", item.side === "after" ? "改动后" : "改动前");
        add("代码位置", (item.positions || [item.path + ":" + item.line]).join("、"));
        if (item.cycle) add("路径提示", "这条连线指回已经显示的代码");
        add("解析状态", RESOLUTION_LABEL[item.resolution] || item.resolution, raw);
        if (item.reason) add("解析依据", item.reason, raw);
      }
      panel.appendChild(list);
      if (candidateIds.length) add("关联线索 ID", candidateIds.join("、"), raw);
      panel.appendChild(technical);

      if (tests.length) {
        var testSection = document.createElement("div");
        testSection.className = "evidence-section";
        testSection.appendChild(text("h4", "测试建议（尚未执行）"));
        var testList = document.createElement("ul");
        testList.className = "evidence-list";
        tests.forEach(function (test) {
          var label = test.test_path + (test.qualified_name ? "::" + test.qualified_name : "");
          testList.appendChild(
            text("li", label + "（" + (test.strength === "strong" ? "调用链相关" : "弱关联") + "）")
          );
        });
        testSection.appendChild(testList);
        panel.appendChild(testSection);
      }

      if (judge.length) {
        var judgeSection = document.createElement("div");
        judgeSection.className = "evidence-section";
        judgeSection.appendChild(text("h4", "语义判断（尚未用测试验证）"));
        var judgeList = document.createElement("ul");
        judgeList.className = "evidence-list";
        judge.forEach(function (row) {
          var verdict = row.verdict || {};
          var label = VERDICT_LABEL[verdict.verdict] || verdict.verdict || "无法判断";
          judgeList.appendChild(
            text("li", verdict.reason ? label + "：" + verdict.reason : label)
          );
        });
        judgeSection.appendChild(judgeList);
        panel.appendChild(judgeSection);
      }
    };
  }

  function buildElements(graph) {
    var elements = [];
    (graph.nodes || []).forEach(function (node) {
      elements.push({
        group: "nodes",
        data: {
          id: node.id,
          label: node.label,
          depth: node.depth,
          side: node.side,
          kind: node.kind,
          path: node.path,
          line: node.line,
          missing: !!node.missing,
          seed_ids: node.seed_ids || [],
          candidate_ids: node.candidate_ids || [],
          is_seed: (node.seed_ids || []).length > 0 && node.depth === 0
        },
        classes: [
          "impact-node",
          "side-" + (node.side || "none"),
          node.missing ? "missing" : "",
          node.depth === 0 ? "seed" : ""
        ].filter(Boolean).join(" ")
      });
    });
    (graph.edges || []).forEach(function (edge) {
      elements.push({
        group: "edges",
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          edge_kind: edge.edge_kind,
          side: edge.side,
          resolution: edge.resolution,
          reason: edge.reason,
          path: edge.path,
          line: edge.line,
          positions: edge.positions || [],
          caller_label: edge.caller_label,
          callee_label: edge.callee_label,
          target_label: edge.target_label,
          candidate_ids: edge.candidate_ids || [],
          cycle: !!edge.cycle
        },
        classes: [
          "impact-edge",
          KIND_CLASS[edge.edge_kind] || "edge-other",
          edge.cycle ? "cycle" : ""
        ].filter(Boolean).join(" ")
      });
    });
    return elements;
  }

  function presetPositions(graph) {
    var positions = graph.positions || {};
    var maxLayer = 0;
    Object.keys(positions).forEach(function (id) {
      maxLayer = Math.max(maxLayer, positions[id].layer || 0);
    });
    var result = {};
    Object.keys(positions).forEach(function (id) {
      var position = positions[id];
      var layer = position.layer || 0;
      var order = position.order || 0;
      result[id] = {
        x: (maxLayer - layer) * 250 + 120,
        y: order * 110 + 70
      };
    });
    return result;
  }

  function styles() {
    return [
      {
        selector: "node.impact-node",
        style: {
          "label": "data(label)",
          "shape": "round-rectangle",
          "width": 150,
          "height": 40,
          "padding": "6px",
          "font-size": 11,
          "text-wrap": "wrap",
          "text-max-width": "140px",
          "background-color": "#eef2f7",
          "border-width": 1,
          "border-color": "#b9c3cf",
          "color": "#293542"
        }
      },
      { selector: "node.side-before", style: { "background-color": "#e9edf3" } },
      { selector: "node.side-after", style: { "background-color": "#d8e9ff" } },
      {
        selector: "node.seed",
        style: { "background-color": "#f4c542", "border-color": "#a8801d", "border-width": 2, "shape": "diamond" }
      },
      {
        selector: "node.missing",
        style: { "border-style": "dashed", "border-color": "#b23b3b", "background-color": "#fff3f3" }
      },
      { selector: "node:selected", style: { "border-width": 3, "border-color": "#2f5fb3" } },
      {
        selector: "edge.impact-edge",
        style: {
          "width": 1.6,
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "target-arrow-color": "#64748b",
          "line-color": "#64748b",
          "arrow-scale": 0.9
        }
      },
      { selector: "edge.edge-call", style: { "line-color": "#3f6fd1", "target-arrow-color": "#3f6fd1", "line-style": "solid" } },
      { selector: "edge.edge-import", style: { "line-color": "#7a5bb5", "target-arrow-color": "#7a5bb5", "line-style": "dashed" } },
      { selector: "edge.edge-global_read", style: { "line-color": "#b5762a", "target-arrow-color": "#b5762a", "line-style": "dotted" } },
      { selector: "edge.cycle", style: { "line-color": "#b23b3b", "target-arrow-color": "#b23b3b", "line-style": "dashed" } },
      { selector: "edge:selected", style: { "width": 3 } },
      { selector: ".hidden-by-filter", style: { "display": "none" } }
    ];
  }

  function init() {
    var container = document.getElementById("impact-graph");
    if (!container) {
      return;
    }
    var raw = container.getAttribute("data-graph");
    var graph;
    try {
      graph = JSON.parse(raw || "{}");
    } catch (error) {
      container.textContent = "图数据解析失败，请使用下方路径列表与证据表。";
      return;
    }
    var evidence = (graph && graph.evidence) || {};
    var panel = document.getElementById("impact-evidence");
    var renderEvidence = evidencePanel(graph, evidence);

    if (typeof window.cytoscape !== "function") {
      if (panel) {
        clear(panel);
        panel.appendChild(
          text("p", "本地图库未加载，已回退到下方路径列表与证据表。", "notice notice-warn")
        );
      }
      return;
    }

    var elements = buildElements(graph);
    if (!elements.length) {
      container.textContent = "没有找到符合筛选条件的关联代码。";
      if (panel) {
        clear(panel);
        panel.appendChild(text("p", "可切换改动位置或放宽筛选。", "meta"));
      }
      return;
    }

    container.textContent = "";
    var cy;
    try {
      cy = window.cytoscape({
        container: container,
        elements: elements,
        style: styles(),
        layout: { name: "preset", positions: presetPositions(graph), fit: true, padding: 24 },
        wheelSensitivity: 0.2,
        minZoom: 0.2,
        maxZoom: 2.5
      });
    } catch (error) {
      container.textContent = "加载拓扑图失败，请使用下方路径列表与证据表。";
      return;
    }

    // Keep the default view readable: a tiny fit zoom makes labels illegible
    // on narrow screens. Users can still zoom out with the toolbar.
    if (cy.zoom() < 0.7) {
      cy.zoom(0.7);
      cy.center();
    }

    var statsNode = document.getElementById("impact-graph-stats");
    function updateStats() {
      if (!statsNode) {
        return;
      }
      var visibleNodes = cy.nodes().filter(function (node) {
        return !node.hasClass("hidden-by-filter");
      }).length;
      var visibleEdges = cy.edges().filter(function (edge) {
        return !edge.hasClass("hidden-by-filter");
      }).length;
      statsNode.textContent =
        "显示 " + visibleNodes + "/" + cy.nodes().length + " 处代码" +
        " · " + visibleEdges + "/" + cy.edges().length + " 条关系";
    }

    function applyFilters() {
      var depthSelect = document.getElementById("graph-depth-filter");
      var kindSelect = document.getElementById("graph-kind-filter");
      var depthValue = depthSelect && depthSelect.value ? parseInt(depthSelect.value, 10) : null;
      var kindValue = kindSelect && kindSelect.value ? kindSelect.value : null;
      cy.batch(function () {
        cy.nodes().forEach(function (node) {
          var hidden = depthValue !== null && Number(node.data("depth")) > depthValue;
          node.toggleClass("hidden-by-filter", hidden);
        });
        cy.edges().forEach(function (edge) {
          var hidden = false;
          if (kindValue !== null && edge.data("edge_kind") !== kindValue) {
            hidden = true;
          }
          if (edge.source().hasClass("hidden-by-filter") || edge.target().hasClass("hidden-by-filter")) {
            hidden = true;
          }
          if (depthValue !== null && Number(edge.source().data("depth")) > depthValue) {
            hidden = true;
          }
          edge.toggleClass("hidden-by-filter", hidden);
        });
      });
      updateStats();
      var filtered = depthValue !== null || kindValue !== null;
      graphNotice(
        filtered
          ? "图中只显示符合当前筛选的代码和关系。"
          : "",
        filtered
      );
    }

    if (panel) {
      clear(panel);
      panel.appendChild(
        text("p", "点击图中的代码或连线，查看为什么会出现在这里。", "meta")
      );
    }

    cy.on("tap", "node", function (event) {
      var found = null;
      (graph.nodes || []).forEach(function (node) {
        if (node.id === event.target.id()) {
          found = node;
        }
      });
      renderEvidence("node", found || {});
    });
    cy.on("tap", "edge", function (event) {
      var found = null;
      (graph.edges || []).forEach(function (edge) {
        if (edge.id === event.target.id()) {
          found = edge;
        }
      });
      renderEvidence("edge", found || {});
    });
    cy.on("tap", function (event) {
      if (event.target === cy) {
        cy.elements().unselect();
        if (panel) {
          clear(panel);
          panel.appendChild(text("p", "点击图中的代码或连线，查看为什么会出现在这里。", "meta"));
        }
      }
    });

    var depthSelect = document.getElementById("graph-depth-filter");
    if (depthSelect) {
      var maxDepth = 0;
      (graph.nodes || []).forEach(function (node) {
        maxDepth = Math.max(maxDepth, Number(node.depth || 0));
      });
      for (var depth = 1; depth <= maxDepth; depth += 1) {
        var option = document.createElement("option");
        option.value = String(depth);
        option.textContent = "≤ " + depth;
        depthSelect.appendChild(option);
      }
      depthSelect.addEventListener("change", applyFilters);
    }
    var kindSelect = document.getElementById("graph-kind-filter");
    if (kindSelect) {
      kindSelect.addEventListener("change", applyFilters);
    }

    Array.prototype.forEach.call(
      document.querySelectorAll("[data-action]"),
      function (button) {
        button.addEventListener("click", function () {
          var action = button.getAttribute("data-action");
          if (action === "zoom-in") {
            cy.zoom(cy.zoom() * 1.25);
            cy.center();
          } else if (action === "zoom-out") {
            cy.zoom(cy.zoom() / 1.25);
            cy.center();
          } else if (action === "fit") {
            cy.fit(undefined, 28);
          } else if (action === "reset") {
            cy.layout({ name: "preset", positions: presetPositions(graph), fit: true, padding: 24 }).run();
            cy.elements().unselect();
          } else if (action === "filters-reset") {
            if (depthSelect) {
              depthSelect.value = "";
            }
            if (kindSelect) {
              kindSelect.value = "";
            }
            applyFilters();
            cy.fit(undefined, 28);
          }
        });
      }
    );

    function pan(dx, dy) {
      var pan = cy.pan();
      cy.pan({ x: pan.x + dx, y: pan.y + dy });
    }

    container.addEventListener("keydown", function (event) {
      var handled = true;
      if (event.key === "+" || event.key === "=") {
        cy.zoom(cy.zoom() * 1.2);
        cy.center();
      } else if (event.key === "-") {
        cy.zoom(cy.zoom() / 1.2);
        cy.center();
      } else if (event.key === "0" || event.key.toLowerCase() === "f") {
        cy.fit(undefined, 28);
      } else if (event.key === "ArrowLeft") {
        pan(60, 0);
      } else if (event.key === "ArrowRight") {
        pan(-60, 0);
      } else if (event.key === "ArrowUp") {
        pan(0, 60);
      } else if (event.key === "ArrowDown") {
        pan(0, -60);
      } else if (event.key === "Escape") {
        cy.elements().unselect();
        if (panel) {
          clear(panel);
          panel.appendChild(text("p", "已清除选择。", "meta"));
        }
      } else {
        handled = false;
      }
      if (handled) {
        event.preventDefault();
      }
    });

    updateStats();
    graphNotice("", false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
