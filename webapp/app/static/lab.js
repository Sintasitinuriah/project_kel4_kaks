/* ============================================================================
 * Defense-in-Depth Interactive Command Center (lab.js)
 * Mengirim request HTTP nyata melalui WAF ke /vulnerable & /secure
 * ============================================================================ */

const SCENARIOS = {
  normal: {
    label: "Trafik Normal",
    stepKey: "normal",
    target: "products",
    payload: "Cloud",
    password: "",
  },
  auth: {
    label: "SQLi Auth Bypass",
    stepKey: "auth",
    target: "login",
    payload: "' OR '1'='1' --",
    password: "salah123",
  },
  union: {
    label: "SQLi UNION Extract",
    stepKey: "union",
    target: "products",
    payload: "' UNION SELECT id, username, password, 0, 0, email FROM users --",
    password: "",
  },
  drop: {
    label: "Destruktif DROP TABLE",
    stepKey: "destructive",
    target: "products",
    payload: "'; DROP TABLE products; --",
    password: "",
  },
  delete: {
    label: "Destruktif DELETE Users",
    stepKey: "destructive",
    target: "products",
    payload: "'; DELETE FROM users; --",
    password: "",
  },
};

let activeScenarioKey = "normal";
const completedSteps = new Set();

function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showToast(msg) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

function openGuideModal() {
  const modal = document.getElementById("guideModal");
  if (modal) modal.classList.add("open");
}

function closeGuideModal(event) {
  const modal = document.getElementById("guideModal");
  if (!modal) return;
  if (!event || event.target === modal) {
    modal.classList.remove("open");
  }
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.textContent.trim();
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast("Perintah disalin ke clipboard!"));
  } else {
    const tmp = document.createElement("textarea");
    tmp.value = text;
    document.body.appendChild(tmp);
    tmp.select();
    document.execCommand("copy");
    document.body.removeChild(tmp);
    showToast("Perintah disalin ke clipboard!");
  }
}

function selectScenario(key, btnEl) {
  const cfg = SCENARIOS[key];
  if (!cfg) return;
  activeScenarioKey = key;

  document.querySelectorAll(".scenario-card").forEach((c) => c.classList.remove("active"));
  if (btnEl) btnEl.classList.add("active");

  const targetEl = document.getElementById("simTarget");
  const payloadEl = document.getElementById("simPayload");
  const passEl = document.getElementById("simPassword");
  if (targetEl) targetEl.value = cfg.target;
  if (payloadEl) payloadEl.value = cfg.payload;
  if (passEl) passEl.value = cfg.password || "salah123";

  togglePasswordField();
}

function togglePasswordField() {
  const targetEl = document.getElementById("simTarget");
  const passWrap = document.getElementById("simPassWrap");
  const vulnLabel = document.getElementById("vulnEndpointLabel");
  const secLabel = document.getElementById("secEndpointLabel");
  if (!targetEl) return;

  const isLogin = targetEl.value === "login";
  if (passWrap) passWrap.style.display = isLogin ? "flex" : "none";
  if (vulnLabel) vulnLabel.textContent = isLogin ? "/vulnerable/login" : "/vulnerable/products";
  if (secLabel) secLabel.textContent = isLogin ? "/secure/login" : "/secure/products";
}

function markStepDone(stepKey) {
  if (!stepKey) return;
  completedSteps.add(stepKey);
  const el = document.getElementById("step-" + stepKey);
  if (el) el.classList.add("done");

  const total = 4;
  const count = completedSteps.size;
  const pct = Math.round((count / total) * 100);
  const txt = document.getElementById("progressText");
  const fill = document.getElementById("progressFill");
  if (txt) txt.textContent = `${count} / ${total} Skenario Teruji`;
  if (fill) fill.style.width = pct + "%";
}

function setPipelineState(pipeId, states) {
  const pipe = document.getElementById(pipeId);
  if (!pipe) return;
  const nodes = pipe.querySelectorAll(".node");
  nodes.forEach((n) => {
    n.classList.remove("state-pass", "state-block", "state-danger", "state-idle", "state-shield", "pulse");
  });

  states.forEach((st, idx) => {
    setTimeout(() => {
      const node = nodes[idx];
      if (!node) return;
      node.classList.add("state-" + st.type, "pulse");
      const label = node.querySelector(".node-state");
      if (label) label.textContent = st.text;
    }, idx * 140);
  });
}

async function sendRealRequest(mode, target, payload, password) {
  const url = target === "login"
    ? `/${mode}/login`
    : `/${mode}/products?q=${encodeURIComponent(payload)}`;

  const options = {
    method: target === "login" ? "POST" : "GET",
    headers: {
      Accept: "application/json",
      "X-Requested-With": "XMLHttpRequest",
    },
  };

  if (target === "login") {
    const body = new URLSearchParams();
    body.set("username", payload);
    body.set("password", password);
    options.headers["Content-Type"] = "application/x-www-form-urlencoded";
    options.body = body.toString();
  }

  const t0 = performance.now();
  const res = await fetch(url, options);
  const elapsedMs = Math.round(performance.now() - t0);
  const defenseHeader = res.headers.get("X-Defense-Layer");

  if (res.status === 403) {
    return {
      httpStatus: 403,
      elapsedMs,
      wafBlocked: true,
      defenseLayer: "WAF-ModSecurity-CRS",
      data: null,
    };
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = { outcome: "error", error: `Respons non-JSON (HTTP ${res.status})` };
  }

  return {
    httpStatus: res.status,
    elapsedMs,
    wafBlocked: false,
    defenseLayer: defenseHeader || data?.defense_layer || null,
    data,
  };
}

function evaluateResult(mode, target, result, isAttack) {
  if (result.wafBlocked) {
    return {
      badgeClass: "verdict-blocked",
      shortTag: "Diblokir WAF (403)",
      title: "DITAHAN oleh Layer 2: WAF (ModSecurity v3 + OWASP CRS)",
      detail: "Request dihentikan di perimeter sebelum menyentuh server Flask atau database PostgreSQL (HTTP 403 Forbidden).",
      pipeline: [
        { type: "pass", text: "public_net" },
        { type: "block", text: "403 BLOCKED" },
        { type: "idle", text: "Tidak dicapai" },
        { type: "idle", text: "Terlindungi" },
      ],
    };
  }

  const d = result.data || {};

  if (d.outcome === "blocked_layer4") {
    return {
      badgeClass: "verdict-shield",
      shortTag: "Diblokir DB (Layer 4)",
      title: "DITAHAN oleh Layer 4: PostgreSQL Least Privilege (app_user)",
      detail: d.defense_blocked || "PostgreSQL menolak aksi destruktif karena app_user tidak memiliki hak DROP/DELETE.",
      pipeline: [
        { type: "pass", text: "VPC OK" },
        { type: "pass", text: "Lolos WAF" },
        { type: "danger", text: "Raw SQL!" },
        { type: "shield", text: "RBAC DENIED" },
      ],
    };
  }

  if (mode === "secure") {
    if (!isAttack) {
      return {
        badgeClass: "verdict-ok",
        shortTag: "Sukses (Aman)",
        title: "Trafik Sah Diproses Aman (Layer 3 Parameterized Query)",
        detail: target === "products"
          ? `Ditemukan ${d.count ?? 0} produk yang cocok dengan kata kunci pencarian.`
          : (d.user ? `Login sah sebagai ${d.user.username}.` : d.error || "Login ditolak."),
        pipeline: [
          { type: "pass", text: "VPC OK" },
          { type: "pass", text: "WAF Pass" },
          { type: "pass", text: "Param %s OK" },
          { type: "pass", text: "SELECT OK" },
        ],
      };
    }

    return {
      badgeClass: "verdict-ok",
      shortTag: "Aman (Layer 3)",
      title: "AMAN! Serangan Netral di Layer 3 (Parameterized Query)",
      detail: target === "login"
        ? "Payload SQLi diperlakukan sebagai string literal. Autentikasi ditolak tanpa membocorkan error SQL."
        : `Payload SQLi diperlakukan sebagai teks pencarian biasa (0 data sensitif bocor, hasil: ${d.count ?? 0}).`,
      pipeline: [
        { type: "pass", text: "VPC OK" },
        { type: "pass", text: "Lolos WAF" },
        { type: "block", text: "PARAM SAFE" },
        { type: "pass", text: "DB Aman" },
      ],
    };
  }

  // mode === "vulnerable"
  if (target === "login" && d.outcome === "authenticated") {
    return {
      badgeClass: isAttack ? "verdict-danger" : "verdict-ok",
      shortTag: isAttack ? "TEMBUS (Bypass!)" : "Login Sah",
      title: isAttack
        ? "TEREKSPLOITASI! Authentication Bypass Berhasil pada /vulnerable"
        : `Login berhasil sebagai ${d.user?.username}`,
      detail: isAttack
        ? `Penyerang masuk sebagai '${d.user?.username}' (role: ${d.user?.role}) tanpa mengetahui password asli!`
        : "Kredensial valid diterima.",
      pipeline: [
        { type: "pass", text: "VPC OK" },
        { type: "pass", text: "Lolos WAF" },
        { type: "danger", text: "SQL INJECTED" },
        { type: "danger", text: "Auth Bypass!" },
      ],
    };
  }

  if (target === "products" && d.outcome === "data_leaked") {
    return {
      badgeClass: "verdict-danger",
      shortTag: "TEMBUS (Data Bocor!)",
      title: "TEREKSPLOITASI! Kebocoran Data Tabel users via UNION SELECT",
      detail: "Kredensial seluruh akun (username, password, email) berhasil diekstrak dari tabel users!",
      pipeline: [
        { type: "pass", text: "VPC OK" },
        { type: "pass", text: "Lolos WAF" },
        { type: "danger", text: "SQL INJECTED" },
        { type: "danger", text: "Data Bocor!" },
      ],
    };
  }

  if (d.error) {
    return {
      badgeClass: "verdict-warn",
      shortTag: "SQL Error Leak",
      title: "Verbose SQL Error Terbuka pada /vulnerable",
      detail: d.error,
      pipeline: [
        { type: "pass", text: "VPC OK" },
        { type: "pass", text: "Lolos WAF" },
        { type: "danger", text: "Raw SQL Err" },
        { type: "pass", text: "DB Error" },
      ],
    };
  }

  return {
    badgeClass: "verdict-ok",
    shortTag: `OK (${d.count ?? 0} item)`,
    title: "Query Dieksekusi pada /vulnerable",
    detail: `Mengembalikan ${d.count ?? 0} baris hasil.`,
    pipeline: [
      { type: "pass", text: "VPC OK" },
      { type: "pass", text: "WAF Pass" },
      { type: "pass", text: "Raw SQL" },
      { type: "pass", text: "SELECT OK" },
    ],
  };
}

function renderPanel(prefix, target, result, evalInfo) {
  const httpBadge = document.getElementById(prefix + "HttpBadge");
  const verdict = document.getElementById(prefix + "Verdict");
  const queryWrap = document.getElementById(prefix + "QueryWrap");
  const queryCode = document.getElementById(prefix + "QueryCode");
  const dataWrap = document.getElementById(prefix + "DataWrap");

  if (httpBadge) {
    httpBadge.textContent = `HTTP ${result.httpStatus} • ${result.elapsedMs} ms`;
  }

  if (verdict) {
    verdict.className = "verdict-box " + evalInfo.badgeClass;
    verdict.innerHTML = `<strong>${esc(evalInfo.title)}</strong><div class="small mt-4">${esc(evalInfo.detail)}</div>`;
  }

  const d = result.data;
  if (d && d.executed_query) {
    queryWrap.style.display = "block";
    queryCode.textContent = d.executed_query;
  } else {
    queryWrap.style.display = "none";
  }

  if (!dataWrap) return;
  if (result.wafBlocked) {
    dataWrap.innerHTML = `<div class="mini-note">Audit log tercatat di <code>logs/waf/audit.log</code> (OWASP CRS Rule 942xxx).</div>`;
  } else if (d && d.user) {
    dataWrap.innerHTML = `
      <div class="mini-note">
        <strong>Akun Terautentikasi:</strong> <code>${esc(d.user.username)}</code>
        (Role: <code>${esc(d.user.role)}</code>, Email: <code>${esc(d.user.email)}</code>)
      </div>`;
  } else if (d && Array.isArray(d.products) && d.products.length > 0) {
    const rows = d.products.slice(0, 6).map((p) => {
      const isLeaked = String(p.description || "").endsWith("@cloudshop.local");
      return `<tr class="${isLeaked ? "row-leaked" : ""}">
        <td>${esc(p.id)}</td>
        <td><strong>${esc(p.name)}</strong></td>
        <td><code>${esc(p.category)}</code></td>
        <td>${esc(p.description)}</td>
      </tr>`;
    }).join("");
    dataWrap.innerHTML = `
      <div class="table-wrap">
        <table class="mini-table">
          <thead><tr><th>ID</th><th>Nama / Username</th><th>Kategori / Password</th><th>Deskripsi / Email</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } else {
    dataWrap.innerHTML = "";
  }
}

function appendHistoryRow(scenarioLabel, vulnTag, secTag) {
  const tbody = document.getElementById("simHistoryBody");
  if (!tbody) return;
  const emptyRow = document.getElementById("emptyHistoryRow");
  if (emptyRow) emptyRow.remove();

  const now = new Date();
  const timeStr = now.toTimeString().slice(0, 8);
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><code>${timeStr}</code></td>
    <td><strong>${esc(scenarioLabel)}</strong></td>
    <td><span class="history-tag">${esc(vulnTag)}</span></td>
    <td><span class="history-tag">${esc(secTag)}</span></td>
  `;
  tbody.prepend(tr);
}

async function runSideBySideSimulation() {
  const btn = document.getElementById("runSimBtn");
  const target = document.getElementById("simTarget").value;
  const payload = document.getElementById("simPayload").value;
  const password = document.getElementById("simPassword").value;

  const isAttack = /['";]|--|\b(union|select|drop|delete|or\s+1=1)\b/i.test(payload);
  const cfg = SCENARIOS[activeScenarioKey];
  const scenarioLabel = cfg && cfg.payload === payload ? cfg.label : `Custom (${target})`;

  if (btn) {
    btn.disabled = true;
    btn.textContent = "Menjalankan Simulasi...";
  }

  try {
    const [vulnRes, secRes] = await Promise.all([
      sendRealRequest("vulnerable", target, payload, password),
      sendRealRequest("secure", target, payload, password),
    ]);

    const vulnEval = evaluateResult("vulnerable", target, vulnRes, isAttack);
    const secEval = evaluateResult("secure", target, secRes, isAttack);

    setPipelineState("pipe-vuln", vulnEval.pipeline);
    setPipelineState("pipe-sec", secEval.pipeline);

    renderPanel("vuln", target, vulnRes, vulnEval);
    renderPanel("sec", target, secRes, secEval);

    const flowSub = document.getElementById("flowSubtitle");
    if (flowSub) {
      flowSub.innerHTML = `Hasil skenario <strong>${esc(scenarioLabel)}</strong>: Jalur <code>/vulnerable</code> &rarr; <strong>${esc(vulnEval.shortTag)}</strong> | Jalur <code>/secure</code> &rarr; <strong>${esc(secEval.shortTag)}</strong>.`;
    }

    appendHistoryRow(scenarioLabel, vulnEval.shortTag, secEval.shortTag);

    // Update checklist progress
    if (!isAttack) {
      markStepDone("normal");
    } else if (target === "login") {
      markStepDone("auth");
    } else if (/union\s+select/i.test(payload)) {
      markStepDone("union");
    } else if (/(drop\s+table|delete\s+from)/i.test(payload)) {
      markStepDone("destructive");
    }

    refreshTelemetry(true);
    showToast(`Simulasi "${scenarioLabel}" selesai!`);
  } catch (err) {
    showToast("Gagal terhubung ke server: " + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = "&#9654; Jalankan Simulasi Side-by-Side";
    }
  }
}

async function refreshTelemetry(silent = false) {
  try {
    const res = await fetch("/api/telemetry", { headers: { Accept: "application/json" } });
    if (!res.ok) return;
    const data = await res.json();

    const wafBadge = document.getElementById("liveWafBadge");
    if (wafBadge) {
      wafBadge.textContent = `${data.waf_mode} (Paranoia ${data.crs_paranoia})`;
      wafBadge.className = "pill " + (
        data.waf_mode === "On" ? "pill-ok" : data.waf_mode === "DetectionOnly" ? "pill-warn" : "pill-danger"
      );
    }

    const t = data.telemetry || {};
    const mProd = document.getElementById("metricProducts");
    const mUser = document.getElementById("metricUsers");
    const mLogs = document.getElementById("metricLogs");
    const integ = document.getElementById("liveIntegrityBadge");
    if (mProd) mProd.textContent = t.products_count ?? 0;
    if (mUser) mUser.textContent = t.users_count ?? 0;
    if (mLogs) mLogs.textContent = t.logs_count ?? 0;
    if (integ) integ.textContent = `${t.products_count ?? 0} Produk • ${t.users_count ?? 0} User`;

    const logsBody = document.getElementById("recentLogsBody");
    if (logsBody && Array.isArray(t.recent_logs)) {
      if (t.recent_logs.length === 0) {
        logsBody.innerHTML = `<tr><td colspan="3" class="muted">Belum ada log pencarian.</td></tr>`;
      } else {
        logsBody.innerHTML = t.recent_logs.map((log) => `
          <tr>
            <td><code>${esc(log.logged_at)}</code></td>
            <td><span class="pill ${log.endpoint_mode === "secure" ? "pill-ok" : "pill-danger"}">${esc(log.endpoint_mode)}</span></td>
            <td><code>${esc(log.query_text)}</code></td>
          </tr>
        `).join("");
      }
    }

    if (!silent) showToast("Telemetri database diperbarui!");
  } catch {
    if (!silent) showToast("Gagal memuat telemetri.");
  }
}

function clearHistory() {
  const tbody = document.getElementById("simHistoryBody");
  if (tbody) {
    tbody.innerHTML = `<tr id="emptyHistoryRow"><td colspan="4" class="muted">Belum ada simulasi dijalankan pada sesi ini.</td></tr>`;
  }
}
