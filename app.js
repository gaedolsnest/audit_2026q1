// file: <repo>/app.js
const DATA_URL = "webdata.bin";

const MAGIC = new TextEncoder().encode("SCOREENC\n");
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200_000;

const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";
const MASTER_KEY = "audit2026!";

let dataObj = null;
let isMaster = false;
let currentDd = null;

const $ = (id) => document.getElementById(id);

function setStatus(msg) {
  const el1 = $("status");
  const el2 = $("status2");
  if (el1) el1.textContent = msg || "";
  if (el2) el2.textContent = msg || "";
}

function toNorm(s) { return (s || "").replace(/\s+/g, "").trim().toLowerCase(); }
function fmt2(n) {
  if (n === null || n === undefined || n === "") return "";
  const v = Number(n);
  if (Number.isNaN(v)) return String(n);
  return v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function nl2br(s) { return String(s || "").replace(/\n/g, "<br/>"); }

async function pbkdf2Key(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

function startsWithMagic(buf) {
  if (buf.byteLength < MAGIC.byteLength) return false;
  const u = new Uint8Array(buf);
  for (let i = 0; i < MAGIC.byteLength; i++) if (u[i] !== MAGIC[i]) return false;
  return true;
}

async function decryptBlob(arrayBuffer) {
  if (!startsWithMagic(arrayBuffer)) throw new Error("Invalid webdata.bin (missing magic)");
  const u = new Uint8Array(arrayBuffer);
  let off = MAGIC.byteLength;
  const salt = u.slice(off, off + SALT_LEN); off += SALT_LEN;
  const nonce = u.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const ct = u.slice(off);

  const key = await pbkdf2Key(INTERNAL_PASSPHRASE, salt);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
  return new Uint8Array(plain);
}

function fillDdSelect(obj) {
  const sel = $("ddSelect");
  if (!sel) return;
  const dds = Object.keys(obj.regions || {}).sort((a, b) => a.localeCompare(b, "ko"));
  sel.innerHTML = "";
  for (const dd of dds) {
    const opt = document.createElement("option");
    opt.value = dd;
    opt.textContent = dd;
    sel.appendChild(opt);
  }
}

async function ensureDataLoaded() {
  if (dataObj) return;

  setStatus("데이터 다운로드 중...");
  const res = await fetch(DATA_URL, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${DATA_URL}: ${res.status}`);
  const buf = await res.arrayBuffer();

  setStatus("복호화 중...");
  const plainBytes = await decryptBlob(buf);
  const obj = JSON.parse(new TextDecoder("utf-8").decode(plainBytes));

  if (!obj || !obj.regions || !Array.isArray(obj.rows)) throw new Error("Invalid schema");
  dataObj = obj;

  fillDdSelect(obj);
  setStatus(`로드 완료: 지역 ${Object.keys(obj.regions).length} / 표시행 ${obj.rows.length}`);
}

function validateRegion(dd, code) {
  if (!dataObj) throw new Error("데이터 로드 실패. 새로고침 후 다시 시도.");
  if (!dd) throw new Error("지역 선택 필요");
  if (!code) throw new Error("암호 입력 필요");

  const expected = toNorm(dataObj.regions[dd] || "");
  if (!expected) throw new Error("지역 정보 없음");
  if (toNorm(code) !== expected) throw new Error("지역/암호가 틀립니다.");
}

function showAppView() {
  $("loginView").style.display = "none";
  $("appView").style.display = "block";
}

function showLoginView() {
  $("appView").style.display = "none";
  $("loginView").style.display = "block";
  setStatus("");
  $("qInput").value = "";
  $("resultTable").querySelector("tbody").innerHTML = "";
}

function renderTable(rows) {
  const tbody = $("resultTable").querySelector("tbody");
  tbody.innerHTML = "";

  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.dd || ""}</td>
      <td title="${r.store || ""}">${r.store || ""}</td>
      <td>${r.name || ""}</td>
      <td>${r.emp || ""}</td>
      <td>${r.pos || ""}</td>
      <td class="num">${fmt2(r.ap_avg)}</td>
    `;
    tr.addEventListener("click", () => openDetail(r));
    tbody.appendChild(tr);
  }
}

function kv(k, vHtml) {
  const div = document.createElement("div");
  div.className = "kv";
  div.innerHTML = `<div class="k">${k}</div><div class="v">${vHtml ?? ""}</div>`;
  return div;
}

function openDetail(row) {
  const dlg = $("detailDlg");
  const storeLabel = row.store === "(AVG)" ? "평균(점포간)" : row.store;
  $("dlgTitle").textContent = `${row.dd || ""} / ${storeLabel || ""} / ${row.name || ""}`;

  const body = $("dlgBody");
  body.innerHTML = "";

  body.appendChild(kv("성명", row.name || ""));
  body.appendChild(kv("사번", row.emp || ""));
  body.appendChild(kv("직책", row.pos || ""));
  body.appendChild(kv("점포", storeLabel || ""));

  if (row.store === "(AVG)") {
    body.appendChild(kv("점포간 평균 점수", `<span class="score-big score-single">${fmt2(row.ap_avg)}</span>`));

    const stores = Array.isArray(row.stores) ? row.stores : [];
    const ss = Array.isArray(row.store_scores) ? row.store_scores : [];

    const lines = [];
    if (stores.length) lines.push(`포함 점포: ${stores.join(", ")}`);

    const storeDesc = ss
      .slice()
      .sort((a, b) => String(b.latest_date || "").localeCompare(String(a.latest_date || ""), "ko"))
      .map((it) => `${it.store} (${it.latest_date || "-"}) : ${fmt2(it.ap_avg)}`);

    if (storeDesc.length) lines.push(...storeDesc);
    if (lines.length) body.appendChild(kv("요약", `<div class="mono">${nl2br(lines.join("\n"))}</div>`));

    dlg.showModal();
    return;
  }

  const records = Array.isArray(row.records) ? row.records : [];
  const isSingle = records.length === 1;

  const scoreLabel = isSingle ? "점수" : "평균 점수";
  const scoreValue = isSingle ? (records[0]?.ap ?? row.ap_avg) : row.ap_avg;
  const scoreHtml = `<span class="score-big ${isSingle ? "score-single" : ""}">${fmt2(scoreValue)}</span>`;
  body.appendChild(kv(scoreLabel, scoreHtml));

  if (records.length) {
    const h = document.createElement("div");
    h.style.marginTop = "10px";
    h.style.fontWeight = "800";
    h.textContent = `조사 상세(오름차순) - ${records.length}회`;
    body.appendChild(h);

    for (const rec of records) {
      body.appendChild(document.createElement("hr"));
      const d = rec.detail || {};
      body.appendChild(kv("조사일자", d.E || rec.date || ""));
      body.appendChild(kv("신발 전산 / 수량 / 차이", `${d.F ?? ""} / ${d.H ?? ""} / ${d.I ?? ""}`));
      body.appendChild(kv("용품 전산 / 수량 / 차이", `${d.O ?? ""} / ${d.Q ?? ""} / ${d.R ?? ""}`));
      body.appendChild(kv("의류 전산 / 수량 / 차이", `${d.X ?? ""} / ${d.Z ?? ""} / ${d.AA ?? ""}`));
      body.appendChild(kv("합계 전산 / 수량 / 차이", `${d.AG ?? ""} / ${d.AI ?? ""} / ${d.AJ ?? ""}`));
      body.appendChild(kv("최종점수", fmt2(rec.ap)));
    }
  }

  dlg.showModal();
}

function doSearch() {
  if (!dataObj) throw new Error("데이터 로드 실패. 새로고침 후 다시 시도.");

  const q = toNorm($("qInput").value);
  let rows = dataObj.rows;

  if (!isMaster && currentDd) rows = rows.filter(r => r.dd === currentDd);
  if (q) rows = rows.filter(r => toNorm(r.store).includes(q) || toNorm(r.name).includes(q));

  rows = rows.slice().sort((a, b) => {
    const d1 = (a.dd || "").localeCompare(b.dd || "", "ko");
    if (d1 !== 0) return d1;
    const n1 = (a.name || "").localeCompare(b.name || "", "ko");
    if (n1 !== 0) return n1;
    const e1 = (a.emp || "").localeCompare(b.emp || "", "ko");
    if (e1 !== 0) return e1;
    const p1 = (a.pos || "").localeCompare(b.pos || "", "ko");
    if (p1 !== 0) return p1;
    const aAvg = (a.store === "(AVG)") ? 1 : 0;
    const bAvg = (b.store === "(AVG)") ? 1 : 0;
    if (aAvg !== bAvg) return aAvg - bAvg;
    return (a.store || "").localeCompare(b.store || "", "ko");
  });

  renderTable(rows);
  setStatus(`표시: ${rows.length}행`);
}

/* ===== events ===== */

$("qInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    try { doSearch(); } catch (err) { setStatus(String(err.message || err)); }
  }
});

$("enterBtn").addEventListener("click", async () => {
  try {
    if (!dataObj) await ensureDataLoaded();

    if (isMaster) {
      currentDd = null;
      showAppView();
      doSearch();
      return;
    }

    const dd = $("ddSelect").value;
    const code = ($("codeInput").value || "").trim();
    validateRegion(dd, code);
    currentDd = dd;

    showAppView();
    doSearch();
  } catch (e) {
    setStatus(String(e.message || e));
  }
});

$("searchBtn").addEventListener("click", () => {
  try { doSearch(); } catch (e) { setStatus(String(e.message || e)); }
});

$("resetBtn").addEventListener("click", () => {
  $("qInput").value = "";
  $("resultTable").querySelector("tbody").innerHTML = "";
  setStatus("");
});

$("logoutBtn").addEventListener("click", () => {
  isMaster = false;
  currentDd = null;
  $("codeInput").value = "";
  showLoginView();
});

$("dlgClose").addEventListener("click", () => $("detailDlg").close());

document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === "M" || e.key === "m")) {
    const input = prompt("마스터키 입력");
    if (input !== null && String(input).trim() === MASTER_KEY) {
      isMaster = true;
      currentDd = null;
      setStatus("마스터 모드 ON");
      if ($("appView").style.display !== "none") {
        try { doSearch(); } catch {}
      }
    } else {
      setStatus("마스터키가 틀립니다.");
    }
  }
  if (e.key === "Escape" && isMaster) {
    isMaster = false;
    setStatus("마스터 모드 OFF");
  }
});

// ✅ 페이지 로드시 자동 로드해서 지역 드롭다운 즉시 채움
(async function bootstrap() {
  try {
    await ensureDataLoaded();
  } catch (e) {
    setStatus("데이터 로드 실패: " + String(e.message || e));
  }
})();
