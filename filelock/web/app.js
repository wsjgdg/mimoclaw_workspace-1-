/* filelock — 界面逻辑 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  /* ---------- 平台标识 ---------- */
  (function platform() {
    const ua = navigator.userAgent;
    let p = "未知系统";
    if (ua.includes("Windows")) p = "Windows";
    else if (ua.includes("Mac OS") || ua.includes("Macintosh")) p = "macOS";
    else if (ua.includes("Linux")) p = "Linux";
    $("platform").textContent = "● 运行平台：" + p;
  })();

  /* ---------- 通用 ---------- */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  /* ---------- CSRF 会话令牌 ----------
   * 后端只监听 127.0.0.1，但本机任意网页仍可向该端口发请求（CSRF / DNS rebinding），
   * 在用户不知情时结束进程、删除文件。页面加载时先取回随机令牌，
   * 所有危险 API（POST）必须携带 X-Filelock-Token 请求头。 */
  let SESSION_TOKEN = "";
  let TOKEN_READY = null;

  async function initSecurity() {
    for (let i = 0; i < 3; i++) {
      try {
        const res = await fetch("/api/init");
        const data = await res.json();
        if (data.token) { SESSION_TOKEN = data.token; return; }
      } catch (e) { /* 本地服务可能尚未就绪，稍后重试 */ }
      await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    }
    console.error("安全会话初始化失败：无法从本地服务获取令牌");
  }
  TOKEN_READY = initSecurity();

  async function api(url, payload) {
    if (!TOKEN_READY) TOKEN_READY = initSecurity();
    await TOKEN_READY;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Filelock-Token": SESSION_TOKEN
      },
      body: JSON.stringify(payload || {})
    });
    if (res.status === 403) throw new Error("安全校验失败，请刷新页面重试");
    return res.json();
  }

  function setBusy(btn, busy, text) {
    if (busy) {
      btn.dataset.label = btn.textContent;
      btn.disabled = true;
      btn.innerHTML = '<span class="loading"></span>' + esc(text || "处理中…");
    } else {
      btn.disabled = false;
      btn.textContent = btn.dataset.label || text || "确定";
    }
  }

  function showError(msg) {
    const card = $("resultCard");
    card.classList.remove("hidden");
    $("resultTitle").textContent = "出错了";
    $("conclusion").textContent = msg;
    $("conclusion").className = "conclusion bad";
    $("statusRow").innerHTML = "";
    ["lockerBlock", "reasonBlock", "fixBlock", "pathBlock"].forEach((id) => $(id).classList.add("hidden"));
    card.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ---------- Tab 切换 ---------- */
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("panel-" + tab.dataset.tab).classList.add("active");
    });
  });

  /* ---------- 文件/文件夹检测 ---------- */
  async function runScan(pathOverride) {
    const path = (pathOverride || $("pathInput").value).trim();
    if (!path) { showError("请先输入或选择一个路径"); return; }

    const btn = $("scanBtn");
    setBusy(btn, true, "正在检测…");
    try {
      const data = await api("/api/scan", { path: path, deep: $("deepScan").checked ? 1 : 0 });
      if (!data.ok) showError(data.error || "检测失败");
      else { renderScan(data); loadHistory(); }
    } catch (e) {
      showError("无法连接本地服务：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  }

  function renderScan(d) {
    $("resultCard").classList.remove("hidden");
    $("resultTitle").textContent = "诊断结果";
    $("pathBlock").classList.add("hidden");
    $("batchBlock").classList.add("hidden");

    const concl = $("conclusion");
    if (!d.exists) {
      concl.textContent = "⚠ 路径不存在";
      concl.className = "conclusion bad";
    } else if ((d.lockers || []).length > 0) {
      concl.textContent = "🔒 发现 " + d.lockers.length + " 个占用进程";
      concl.className = "conclusion bad";
    } else if (d.reasons && d.reasons.length > 0) {
      concl.textContent = "⚠ 找到受限原因";
      concl.className = "conclusion warn";
    } else {
      concl.textContent = "✅ 没有被占用，可正常操作";
      concl.className = "conclusion ok";
    }

    const badges = [];
    if (d.exists) {
      badges.push(badge(d.isDir ? "目录" : "文件", "neutral", "类型"));
      if (!d.isDir) badges.push(badge(fmtSize(d.size), "neutral", "大小"));
      badges.push(badge(d.canRead ? "可读" : "不可读", d.canRead ? "ok" : "bad", "读取"));
      badges.push(badge(d.canWrite ? "可写" : "不可写", d.canWrite ? "ok" : "bad", "写入"));
      badges.push(badge(d.canDelete ? "可删除/改名" : "无法删除", d.canDelete ? "ok" : "bad", "删除"));
      if (d.isLink) badges.push(badge("符号链接", "neutral", "备注"));
    }
    $("statusRow").innerHTML = badges.join("");

    renderLockers(d.lockers || []);
    renderList("reasonBlock", "reasonList", d.reasons || [], "没有发现异常原因");
    renderList("fixBlock", "fixList", d.fixes || [], "无需处理");

    $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function badge(text, cls, key) {
    return '<span class="badge ' + cls + '">' + (key ? '<span class="k">' + esc(key) + "</span> " : "") + esc(text) + "</span>";
  }

  function fmtSize(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + " GB";
    if (b >= 1048576) return (b / 1048576).toFixed(2) + " MB";
    if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
    return b + " B";
  }

  function renderList(blockId, listId, arr, emptyText) {
    const block = $(blockId), list = $(listId);
    if (!arr.length) {
      block.classList.remove("hidden");
      list.innerHTML = "<li>" + esc(emptyText) + "</li>";
      return;
    }
    block.classList.remove("hidden");
    list.innerHTML = arr.map((s) => "<li>" + esc(s) + "</li>").join("");
  }

  /* ---------- 进程树可视化 ----------
   * 利用后端返回的 ppid 把扁平占用列表组织成父子层级；
   * 父进程不在列表中或无 ppid 信息时自动退化为扁平展示。 */
  function buildProcessTree(lockers) {
    const map = {}, roots = [];
    lockers.forEach((l) => { map[l.pid] = Object.assign({}, l, { children: [] }); });
    lockers.forEach((l) => {
      const node = map[l.pid];
      if (node.ppid && map[node.ppid] && node.ppid !== node.pid) map[node.ppid].children.push(node);
      else roots.push(node);
    });
    /* 防御异常数据导致的环：从根出发遍历不到的节点补挂到顶层 */
    const seen = new Set();
    (function mark(ns) { ns.forEach((n) => { if (!seen.has(n.pid)) { seen.add(n.pid); mark(n.children); } }); })(roots);
    lockers.forEach((l) => { if (!seen.has(l.pid)) { seen.add(l.pid); roots.push(map[l.pid]); } });
    return roots;
  }

  function renderTreeRows(nodes, level, out) {
    nodes.forEach((node) => {
      const hasKids = node.children && node.children.length > 0;
      const indent = level * 20;
      out.push(
        `<tr class="tree-row${hasKids ? "" : " leaf"}" data-level="${level}"${hasKids ? ` data-expandable="1"` : ""}>` +
          `<td class="pid">` +
            `<span class="tw-indent" style="width:${indent}px"></span>` +
            (hasKids ? '<span class="arrow">▼</span>' : '<span class="arrow-spacer"></span>') +
            esc(node.pid) +
          `</td>` +
          `<td class="pname"><span class="node-icon">${hasKids ? "📂" : "📄"}</span> ${esc(node.name || "(未知)")}</td>` +
          `<td class="detail">${esc(node.detail || "-")}</td>` +
          `<td><button class="btn danger" data-pid="${esc(node.pid)}" data-name="${esc(node.name || "")}">结束此进程</button></td>` +
        `</tr>`);
      if (hasKids) renderTreeRows(node.children, level + 1, out);
    });
  }

  function renderLockers(lockers) {
    const block = $("lockerBlock"), body = $("lockerBody");
    if (!lockers.length) {
      block.classList.add("hidden");
      body.innerHTML = "";
      return;
    }
    block.classList.remove("hidden");
    const rows = [];
    renderTreeRows(buildProcessTree(lockers), 0, rows);
    body.innerHTML = rows.join("");

    /* 展开 / 折叠：隐藏被折叠节点的所有后代行 */
    body.querySelectorAll("tr[data-expandable]").forEach((tr) => {
      tr.querySelector(".arrow").addEventListener("click", (e) => {
        e.stopPropagation();
        const collapsed = tr.classList.toggle("collapsed");
        const lvl = +tr.dataset.level;
        let n = tr.nextElementSibling;
        while (n && +n.dataset.level > lvl) {
          n.classList.toggle("hidden", collapsed);
          n = n.nextElementSibling;
        }
      });
    });

    body.querySelectorAll(".btn.danger").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const pid = btn.dataset.pid, name = btn.dataset.name;
        if (!confirm("确定要强制结束进程吗？\n\n" + name + " (PID " + pid + ")\n\n未保存的数据可能丢失。")) return;
        setBusy(btn, true, "结束中…");
        try {
          const r = await api("/api/kill", { pid: pid });
          if (r.ok) {
            btn.outerHTML = '<span class="badge ok">已结束</span>';
            setTimeout(() => runScan($("pathInput").value.trim()), 600);
          } else {
            showError("结束进程失败（可能需要管理员权限）");
            setBusy(btn, false);
          }
        } catch (e) {
          showError("请求失败：" + e.message);
          setBusy(btn, false);
        }
      });
    });
  }

  /* ---------- 报错提示分析 ---------- */
  async function runAnalyze() {
    const text = $("pasteInput").value.trim();
    if (!text) { showError("请先粘贴报错提示文本"); return; }

    const btn = $("analyzeBtn");
    setBusy(btn, true, "分析中…");
    try {
      const data = await api("/api/analyze", { text: text });
      if (!data.ok) showError(data.error || "分析失败");
      else renderAnalyze(data);
    } catch (e) {
      showError("无法连接本地服务：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  }

  function renderAnalyze(d) {
    $("resultCard").classList.remove("hidden");
    $("resultTitle").textContent = "报错提示分析结果";
    $("statusRow").innerHTML = "";
    $("lockerBlock").classList.add("hidden");

    const rules = d.rules || [];
    const concl = $("conclusion");
    if (!rules.length) {
      concl.textContent = "❓ 未匹配到已知规则";
      concl.className = "conclusion warn";
    } else {
      concl.textContent = "✅ 匹配到 " + rules.length + " 条可能原因";
      concl.className = "conclusion ok";
    }

    // 原因
    const reasonArr = rules.map((r, i) => {
      const tag = r.platform === 1 ? "（Windows）" : r.platform === 2 ? "（macOS）" : "";
      return (i + 1) + ". " + r.cause + tag + "　命中度 " + r.hits;
    });
    if (!rules.length) reasonArr.push("没有匹配到规则库中的已知报错。可以：① 检查是否粘贴完整 ② 用“文件检测”直接扫描该文件 ③ 把报错发给开发者补充规则库");
    renderList("reasonBlock", "reasonList", reasonArr, "");

    // 对策（合并所有命中规则的对策，去重）
    const seen = new Set();
    const fixes = [];
    rules.forEach((r) => (r.fixes || []).forEach((f) => {
      if (!seen.has(f)) { seen.add(f); fixes.push(f); }
    }));
    renderList("fixBlock", "fixList", fixes, "暂无对策");

    // 检测到的路径
    const paths = d.paths || [];
    const pblock = $("pathBlock"), plinks = $("pathLinks");
    if (paths.length) {
      pblock.classList.remove("hidden");
      plinks.innerHTML = paths.map((p) => `<button class="path-link">${esc(p)}</button>`).join("");
      plinks.querySelectorAll(".path-link").forEach((b, i) => {
        b.addEventListener("click", () => {
          $("pathInput").value = paths[i];
          document.querySelector('.tab[data-tab="scan"]').click();
          runScan(paths[i]);
        });
      });
    } else {
      pblock.classList.add("hidden");
    }

    $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  /* ---------- 原生文件选择 ---------- */
  async function browse(type) {
    try {
      const d = await api("/api/browse", { type: type });
      if (d.ok && d.path) {
        $("pathInput").value = d.path;
        runScan(d.path);
      } else if (d.error && d.error !== "已取消") {
        showError(d.error);
      }
    } catch (e) {
      showError("无法调用系统对话框：" + e.message);
    }
  }

  /* ---------- 事件绑定 ---------- */
  $("scanBtn").addEventListener("click", () => runScan());
  $("analyzeBtn").addEventListener("click", runAnalyze);
  $("browseFile").addEventListener("click", () => browse("file"));
  $("browseDir").addEventListener("click", () => browse("dir"));

  $("pathInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runScan();
  });
  $("pasteInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runAnalyze();
  });

  document.querySelectorAll(".chip[data-demo]").forEach((chip) => {
    chip.addEventListener("click", () => {
      $("pasteInput").value = chip.dataset.demo;
      runAnalyze();
    });
  });

  /* ---------- 拖拽文件/文件夹 ---------- */
  const overlay = $("dropOverlay");
  let dragDepth = 0;

  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragDepth++;
    overlay.classList.remove("hidden");
  });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragleave", (e) => {
    e.preventDefault();
    if (--dragDepth <= 0) { dragDepth = 0; overlay.classList.add("hidden"); }
  });
  window.addEventListener("drop", async (e) => {
    e.preventDefault();
    dragDepth = 0;
    overlay.classList.add("hidden");

    // 情况 1：拖入文本（比如报错提示）→ 直接分析
    const text = e.dataTransfer.getData("text/plain") || "";
    const hasFiles = e.dataTransfer.files && e.dataTransfer.files.length > 0;

    if (hasFiles) {
      const names = [];
      const items = e.dataTransfer.items || [];
      for (const item of items) {
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
        if (entry && entry.name) names.push(entry.name);
      }
      if (!names.length) {
        for (const f of e.dataTransfer.files) if (f.name) names.push(f.name);
      }
      if (names.length === 1) await locateAndScan(names[0]);
      else await locateAndBatch(names);
      return;
    }

    if (text.trim()) {
      if (looksLikeError(text)) {
        $("pasteInput").value = text.trim();
        document.querySelector('.tab[data-tab="paste"]').click();
        runAnalyze();
      } else {
        $("pathInput").value = text.trim();
        document.querySelector('.tab[data-tab="scan"]').click();
        runScan(text.trim());
      }
    }
  });

  /* ---------- 批量检测（拖入多个文件） ---------- */
  async function locateAndBatch(names) {
    const btn = $("scanBtn");
    setBusy(btn, true, "批量定位中…");
    try {
      const located = await Promise.all(names.map(async (nm) => {
        try {
          const d = await api("/api/locate", { name: nm });
          return (d && d.paths && d.paths[0]) || null;
        } catch (e) { return null; }
      }));
      const paths = located.filter(Boolean);
      const missed = names.length - paths.length;
      if (!paths.length) {
        showError("没能自动定位到这些文件的完整路径，请用「选择文件」或粘贴路径");
        return;
      }
      const d = await api("/api/scan-batch", { paths: paths });
      if (!d.ok) { showError(d.error || "批量检测失败"); return; }
      renderBatch(d.results || [], missed);
    } catch (e) {
      showError("批量检测失败：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  }

  function renderBatch(results, missed) {
    $("resultCard").classList.remove("hidden");
    $("resultTitle").textContent = "批量检测结果";
    ["lockerBlock", "reasonBlock", "fixBlock", "pathBlock"].forEach((id) => $(id).classList.add("hidden"));

    const locked = results.filter((r) => r.nlockers > 0).length;
    const concl = $("conclusion");
    concl.textContent = "📊 共 " + results.length + " 项" +
      (missed ? "（另有 " + missed + " 项未定位）" : "") +
      (locked ? "，其中 " + locked + " 项被占用" : "，均未被占用");
    concl.className = "conclusion " + (locked ? "bad" : "ok");

    $("batchBlock").classList.remove("hidden");
    $("batchBody").innerHTML = results.map((r, i) => {
      const cls = r.nlockers > 0 ? "bad" : r.restricted ? "warn" : "ok";
      return '<tr>' +
        '<td class="detail">' + esc(r.path) + "</td>" +
        "<td>" + (r.isDir ? "目录" : "文件") + "</td>" +
        "<td>" + (r.nlockers || 0) + "</td>" +
        '<td><span class="badge ' + cls + '">' + esc(r.conclusion) + "</span></td>" +
        '<td><button class="btn ghost" style="padding:5px 10px;font-size:12px" data-i="' + i + '">详细</button></td>' +
        "</tr>";
    }).join("");
    $("batchBody").querySelectorAll("button").forEach((b) => {
      b.addEventListener("click", () => {
        const r = results[+b.dataset.i];
        $("pathInput").value = r.path;
        runScan(r.path);
      });
    });
    $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function locateAndScan(name) {
    if (!name) return;
    const btn = $("scanBtn");
    setBusy(btn, true, "定位文件中…");
    try {
      const d = await api("/api/locate", { name: name });
      const paths = (d && d.paths) || [];
      if (paths.length === 1) {
        $("pathInput").value = paths[0];
        setBusy(btn, false);
        runScan(paths[0]);
      } else if (paths.length > 1) {
        setBusy(btn, false);
        showError("找到多个同名项目，请选择要检测的路径");
        const pblock = $("pathBlock"), plinks = $("pathLinks");
        pblock.classList.remove("hidden");
        plinks.innerHTML = paths.map((p) => `<button class="path-link">${esc(p)}</button>`).join("");
        plinks.querySelectorAll(".path-link").forEach((b, i) => {
          b.addEventListener("click", () => {
            $("pathInput").value = paths[i];
            runScan(paths[i]);
          });
        });
      } else {
        setBusy(btn, false);
        showError("没能自动定位到 “" + name + "” 的完整路径，请用「选择文件」按钮或直接粘贴路径");
      }
    } catch (err) {
      setBusy(btn, false);
      showError("定位失败：" + err.message);
    }
  }

  /* ---------- 剪贴板自动感知 ---------- */
  const ERROR_RE = /占用|正在使用|被[^，。]*程序|拒绝访问|没有权限|需要权限|无法(删除|移动|复制|访问|完成|打开)|操作(无法|不能)完成|资源忙|写保护|只读|回收站|路径太长|损坏|没有空间|同步中|in use|being used|access denied|permission denied|cannot|can't|could not|locked|read-only|write protect|resource busy|file in use/i;

  function looksLikeError(s) {
    return ERROR_RE.test(s || "") && (s || "").length < 4000;
  }

  let lastClip = "";
  let lastPrompted = "";

  function showToast(title, text, onYes) {
    const wrap = $("toastWrap");
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML =
      '<div class="t-title">' + esc(title) + "</div>" +
      '<div class="t-text">' + esc(text) + "</div>" +
      '<div class="t-btns">' +
      '<button class="btn primary" style="padding:7px 14px;font-size:13px">立即分析</button>' +
      '<button class="btn ghost" style="padding:7px 14px;font-size:13px">忽略</button>' +
      "</div>";
    const [yes, no] = el.querySelectorAll("button");
    yes.addEventListener("click", () => { el.remove(); onYes && onYes(); });
    no.addEventListener("click", () => el.remove());
    wrap.appendChild(el);
    setTimeout(() => el.remove(), 20000);
  }

  async function pollClipboard() {
    if (!$("clipWatch") || !$("clipWatch").checked) return;
    if (document.visibilityState !== "visible") return;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 2500);
      const d = await fetch("/api/clipboard", { signal: ctrl.signal }).then((r) => r.json());
      clearTimeout(timer);
      if (!d.ok || !d.text) return;   /* 后端节流命中 unchanged 时也走这里，直接跳过 */
      const text = d.text.trim();
      if (!text || text === lastClip) return;
      lastClip = text;
      if (text === lastPrompted) return;
      if (!looksLikeError(text)) return;
      lastPrompted = text;
      showToast("📋 剪贴板里好像有一条报错提示", text, () => {
        $("pasteInput").value = text;
        document.querySelector('.tab[data-tab="paste"]').click();
        runAnalyze();
      });
    } catch (e) { /* 忽略 */ }
  }

  setInterval(pollClipboard, 3000);
  setTimeout(pollClipboard, 800);

  /* ---------- 复制报告 ---------- */
  function buildReportText() {
    const lines = ["【filelock 诊断报告】"];
    const concl = $("conclusion").textContent.trim();
    const badges = [...document.querySelectorAll("#statusRow .badge")].map((b) => b.textContent.trim());
    if (badges.length) lines.push("状态: " + badges.join(" | "));

    const lockers = [...document.querySelectorAll("#lockerBody tr")];
    if (lockers.length && !$("lockerBlock").classList.contains("hidden")) {
      lines.push("", "占用进程:");
      lockers.forEach((tr) => {
        const td = tr.querySelectorAll("td");
        lines.push("  - PID " + td[0].textContent.trim() + "  " + td[1].textContent.trim() +
                   (td[2].textContent.trim() ? "  (" + td[2].textContent.trim() + ")" : ""));
      });
    }
    const reasonLis = [...document.querySelectorAll("#reasonList li")];
    if (reasonLis.length && !$("reasonBlock").classList.contains("hidden")) {
      lines.push("", "原因分析:");
      reasonLis.forEach((li, i) => lines.push("  " + (i + 1) + ". " + li.textContent.trim()));
    }
    const fixLis = [...document.querySelectorAll("#fixList li")];
    if (fixLis.length && !$("fixBlock").classList.contains("hidden")) {
      lines.push("", "解决办法:");
      fixLis.forEach((li, i) => lines.push("  " + (i + 1) + ". " + li.textContent.trim()));
    }
    if (concl) lines.push("", "结论: " + concl);
    return lines.join("\n");
  }

  /* ---------- 导出 Markdown 报告（方便归档 / 发给同事） ---------- */
  function buildReportMarkdown() {
    const title = $("resultTitle").textContent.trim() || "诊断结果";
    let md = "# filelock " + title + "\n\n";
    const path = $("pathInput").value.trim();
    if (path) md += "**目标路径**: `" + path + "`\n\n";
    const badges = [...document.querySelectorAll("#statusRow .badge")].map((b) => b.textContent.trim());
    if (badges.length) md += "**状态**: " + badges.join(" | ") + "\n\n";

    const rows = [...document.querySelectorAll("#lockerBody tr")]
      .filter((tr) => !$("lockerBlock").classList.contains("hidden"));
    if (rows.length) {
      md += "## 🔒 占用进程\n\n| PID | 进程名 | 详情 |\n|---|---|---|\n";
      rows.forEach((tr) => {
        const td = tr.querySelectorAll("td");
        md += "| " + td[0].textContent.trim() + " | " + td[1].textContent.trim() +
              " | " + td[2].textContent.trim() + " |\n";
      });
      md += "\n";
    }
    const grab = (blockId, listId) =>
      [...document.querySelectorAll("#" + listId + " li")]
        .filter(() => !$(blockId).classList.contains("hidden"))
        .map((li) => li.textContent.trim());
    const reasons = grab("reasonBlock", "reasonList");
    if (reasons.length) md += "## 🔍 原因分析\n\n" + reasons.map((r) => "- " + r).join("\n") + "\n\n";
    const fixes = grab("fixBlock", "fixList");
    if (fixes.length) md += "## 🛠 解决办法\n\n" + fixes.map((f, i) => (i + 1) + ". " + f).join("\n") + "\n\n";
    const concl = $("conclusion").textContent.trim();
    if (concl) md += "**结论**: " + concl + "\n";
    md += "\n> 由 filelock 本地生成 · " + new Date().toLocaleString() + "\n";
    return md;
  }

  function exportReportMarkdown() {
    const blob = new Blob([buildReportMarkdown()], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "filelock_report_" + Date.now() + ".md";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  $("copyReport").addEventListener("click", async () => {
    const text = buildReportText();
    try {
      await navigator.clipboard.writeText(text);
      showToast("✅ 已复制到剪贴板", "可以直接粘贴发给别人了", null);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      showToast("✅ 已复制到剪贴板", "可以直接粘贴发给别人了", null);
    }
  });

  $("exportMd").addEventListener("click", () => {
    try { exportReportMarkdown(); }
    catch (e) { showError("导出失败：" + e.message); }
  });

  /* ---------- 检测历史 ---------- */
  function fmtTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    const pad = (x) => (x < 10 ? "0" + x : x);
    return d.getMonth() + 1 + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }

  async function loadHistory() {
    try {
      const d = await api("/api/history", {});
      const items = (d && d.items) || [];
      const card = $("historyCard"), list = $("historyList");
      if (!items.length) { card.classList.add("hidden"); return; }
      card.classList.remove("hidden");
      list.innerHTML = items.map((it) => {
        const cls = it.nlockers > 0 ? "bad" : it.restricted ? "warn" : "ok";
        return '<div class="hist-item" data-path="' + esc(it.path) + '">' +
               '<span class="badge ' + cls + '">' + esc(it.conclusion) + "</span>" +
               '<span class="h-path">' + esc(it.path) + "</span>" +
               '<span class="h-time">' + esc(fmtTime(it.ts)) + "</span></div>";
      }).join("");
      list.querySelectorAll(".hist-item").forEach((el) => {
        el.addEventListener("click", () => {
          const p = el.dataset.path;
          $("pathInput").value = p;
          document.querySelector('.tab[data-tab="scan"]').click();
          runScan(p);
        });
      });
    } catch (e) { /* 忽略 */ }
  }

  $("clearHistory").addEventListener("click", async () => {
    if (!confirm("确定清空检测历史吗？")) return;
    await api("/api/history/clear", {});
    $("historyCard").classList.add("hidden");
  });

  loadHistory();

  /* ---------- 强力清除（释放句柄 → 删除 → 复测） ---------- */
  $("forceCleanBtn").addEventListener("click", async () => {
    const path = $("pathInput").value.trim();
    if (!path) { showError("请先输入或选择一个路径"); return; }
    if (!confirm("⚡ 强力清除流程：\n\n1. 释放占用句柄（不结束进程）\n2. 尝试删除\n3. 自动复测\n\n目标：" + path +
                 "\n\n⚠ 删除后不可恢复；句柄释放可能导致对应程序异常。继续？")) return;
    const btn = $("forceCleanBtn");
    setBusy(btn, true, "清除中…");
    try {
      const d = await api("/api/force-clean", { path: path });
      if (!d.ok) { showError(d.error || "强力清除失败"); return; }
      const parts = [];
      if (d.closed > 0) parts.push("释放了 " + d.closed + " 个句柄");
      if (d.deleted) parts.push("文件已删除");
      else parts.push("删除失败：" + (d.deleteError || "未知原因"));
      if (d.stillExists) parts.push("文件仍存在，剩余 " + d.remainLockers + " 个占用进程");
      if (d.deleted) {
        showToast("⚡ 强力清除完成", parts.join("；"));
        $("resultCard").classList.add("hidden");
        loadHistory();
      } else {
        showToast("⚠ 未能完全清除", parts.join("；"));
        runScan(path);
      }
    } catch (e) {
      showError("请求失败：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  });

  /* ---------- 释放占用（句柄级，不杀进程） ---------- */
  $("unlockBtn").addEventListener("click", async () => {
    const path = $("pathInput").value.trim();
    if (!path) { showError("请先输入或选择一个路径"); return; }
    if (!confirm("将直接关闭其他进程持有的文件句柄（不结束进程）。\n\n目标：" + path +
                 "\n\n⚠ 可能导致对应程序异常（如未保存内容丢失），请先保存好工作。继续？")) return;
    const btn = $("unlockBtn");
    setBusy(btn, true, "释放中…");
    try {
      const d = await api("/api/unlock", { path: path });
      if (!d.ok) {
        showError(d.error || "释放失败");
      } else {
        const names = (d.processes || []).map((p) => p.name + "(PID " + p.pid + ")").join("、");
        showToast("🔓 已释放 " + d.closed + " 个句柄", names || "文件现在可以操作了");
        runScan(path);
      }
    } catch (e) {
      showError("请求失败：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  });

  /* ---------- 直接删除 ---------- */
  $("deleteBtn").addEventListener("click", async () => {
    const path = $("pathInput").value.trim();
    if (!path) { showError("请先输入或选择一个路径"); return; }
    if (!confirm("确定删除吗？此操作不可恢复。\n\n" + path)) return;
    const btn = $("deleteBtn");
    setBusy(btn, true, "删除中…");
    try {
      const d = await api("/api/act", { op: "delete", path: path });
      if (d.ok) {
        showToast("🗑 已删除", path);
        $("resultCard").classList.add("hidden");
        loadHistory();
      } else {
        showError("删除失败：" + (d.error || "未知原因") +
                  "。可先点「释放占用」再重试；顽固文件请用命令行强制删除");
      }
    } catch (e) {
      showError("请求失败：" + e.message);
    } finally {
      setBusy(btn, false);
    }
  });
})();
