  // file: <repo>/app.js
const DATA_URL = "webdata.bin";

const MAGIC = new TextEncoder().encode("SCOREENC\n");
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200_000;

const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";
const MASTER_KEY = "audit2026!";

let dataObj = null;
let masterMode = false;

const $ = (id) => document.getElementById(id);

function setStatus(msg) { $("status").textContent = msg || ""; }
function toNorm(s) { return (s || "").replace(/\s+/g, "").trim().toLowerCase(); }
function fmt2(n) {
  if (n === null || n === undefined || n === "") return "";
  const v = Number(n);
  if (Number.isNaN(v)) return String(n);
  return v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

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

async function loadData() {
  setStatus("데이터 다운로드 중...");
  const res = await fetch(DATA_URL, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${DATA_URL}: ${res.status}`);
  const buf = await res.arrayBuffer();

  setStatus("복호화 중...");
  const plainBytes = await decryptBlob(buf);
  const obj = JSON.parse(new TextDecoder("utf-8").decode(plainBytes));

  if (!obj || !obj.regions || !Array.isArray(obj.rows)) throw new Error("Invalid schema");
  dataObj = obj;

  const dds = Object.keys(obj.regions).sort((a, b) => a.localeCompare(b, "ko"));
  const sel = $("ddSelect");
  sel.innerHTML = "";
  for (const dd of dds) {
    const opt = document.createElement("option");
    opt.value = dd;
    opt.textContent = dd;
    sel.appendChild(opt);
  }

  setStatus(`로드 완료: 지역 ${dds.length} / 표시행 ${obj.rows.length}`);
}

function validateAccess() {
  if (!dataObj) throw new Error("먼저 '데이터 로드'를 눌러주세요.");
  if (masterMode) return { mode: "master", dd: null };

  const dd = $("ddSelect").value;
  const code = ($("codeInput").value || "").trim();

  if (!dd) throw new Error("지역 선택 필요");
  if (!code) throw new Error("암호 입력 필요");

  const expected = toNorm(dataObj.regions[dd] || "");
  if (!expected) throw new Error("지역 정보 없음");
  if (toNorm(code) !== expected) throw new Error("지역/암호가 틀립니다.");

  return { mode: "region", dd };
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

function nl2br(s) {
  return String(s || "").replace(/\n/g, "<br/>");
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

  // AVG row: show rounds + store scores
  if (row.store === "(AVG)") {
    body.appendChild(kv("점포간 평균 점수", `<span class="score-big">${fmt2(row.ap_avg)}</span>`));

    const rounds = Array.isArray(row.rounds) ? row.rounds : [];
    if (rounds.length) {
      const lines = rounds
        .map((it, idx) => `${idx + 1}차 (${it.date}) 평균: ${fmt2(it.avg_ap)}`)
        .join("\n");
      body.appendChild(kv("회차별 평균", `<div class="mono">${nl2br(lines)}</div>`));
    }

    const ss = Array.isArray(row.store_scores) ? row.store_scores : [];
    if (ss.length) {
      const lines = ss
        .map((it) => `${it.store} (${it.latest_date || "-"}) : ${fmt2(it.ap_avg)}`)
        .join("\n");
      body.appendChild(kv("점포별 점수", `<div class="mono">${nl2br(lines)}</div>`));
    }

    const stores = Array.isArray(row.stores) ? row.stores : [];
    if (stores.length) body.appendChild(kv("포함 점포", stores.join(", ")));

    dlg.showModal();
    return;
  }

  // Store row: BIG red score if 1 audit, else average score
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
  const access = validateAccess();
  const q = toNorm($("qInput").value);

  let rows = dataObj.rows;

  if (access.mode === "region") rows = rows.filter(r => r.dd === access.dd);

  if (q) rows = rows.filter(r => toNorm(r.store).includes(q) || toNorm(r.name).includes(q));

  // sort: 1) dd 2) name 3) emp 4) pos 5) avg last
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

function resetUi() {
  $("codeInput").value = "";
  $("qInput").value = "";
  $("resultTable").querySelector("tbody").innerHTML = "";
  setStatus("");
}

$("loadBtn").addEventListener("click", async () => {
  try { await loadData(); } catch (e) { setStatus(String(e.message || e)); }
});
$("searchBtn").addEventListener("click", () => {
  try { doSearch(); } catch (e) { setStatus(String(e.message || e)); }
});
$("resetBtn").addEventListener("click", resetUi);
$("dlgClose").addEventListener("click", () => $("detailDlg").close());

// Master mode hidden: Ctrl+Shift+M => ON, Esc => OFF
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === "M" || e.key === "m")) {
    const input = prompt("마스터키 입력");
    if (input !== null && String(input).trim() === MASTER_KEY) {
      masterMode = true;
      setStatus("마스터 모드 ON");
    } else {
      setStatus("마스터키가 틀립니다.");
    }
  }
  if (e.key === "Escape" && masterMode) {
    masterMode = false;
    setStatus("마스터 모드 OFF");
  }
});
