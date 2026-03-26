/*
  Web App (GitHub Pages) - PC parity (avg + multi-audit)
  - data file: webdata.bin (encrypted JSON)
  - region/dd + code OR master key
  - table shows ap_avg (average AP per display row)
  - detail modal shows all audits (records) sorted by date asc

  Expected schema (from web_build_data.py):
  {
    "regions": { "dd": "region_code", ... },
    "rows": [
      {
        "dd": "...",
        "store": "...",        // store name OR "(AVG)"
        "name": "...",
        "emp": "...",
        "pos": "...",
        "ap_avg": 12.34,       // average AP for this display row
        "audit_count": 2,      // number of audits included (records length)
        "records": [           // audits (date asc)
          { "date":"YYYY-MM-DD", "ap":12.0, "detail":{E,F,H,I,O,Q,R,X,Z,AA,AG,AI,AJ,AP} },
          ...
        ]
      }
    ]
  }
*/

const DATA_URL = "webdata.bin";

// ===== encrypted blob format =====
const MAGIC = new TextEncoder().encode("SCOREENC\n");
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200_000;

// MUST match web_build_data.py
const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";

// master key (UI input)
const MASTER_KEY = "audit2026!";

let dataObj = null; // decrypted JSON

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
  const jsonText = new TextDecoder("utf-8").decode(plainBytes);
  const obj = JSON.parse(jsonText);

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

  const dd = $("ddSelect").value;
  const code = ($("codeInput").value || "").trim();
  const master = ($("masterInput").value || "").trim();

  if (master === MASTER_KEY) return { mode: "master", dd: null };

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

function kv(k, v) {
  const div = document.createElement("div");
  div.className = "kv";
  div.innerHTML = `<div class="k">${k}</div><div class="v">${v ?? ""}</div>`;
  return div;
}

function openDetail(row) {
  const dlg = $("detailDlg");
  $("dlgTitle").textContent = `${row.dd || ""} / ${row.store || ""} / ${row.name || ""} / 조사 ${row.audit_count || 1}회`;

  const body = $("dlgBody");
  body.innerHTML = "";

  body.appendChild(kv("성명", row.name || ""));
  body.appendChild(kv("사번", row.emp || ""));
  body.appendChild(kv("직책", row.pos || ""));
  body.appendChild(kv("점포", row.store || ""));
  body.appendChild(kv("평균 점수(AP)", fmt2(row.ap_avg)));

  const records = Array.isArray(row.records) ? row.records : [];
  if (records.length) {
    const h = document.createElement("div");
    h.style.marginTop = "10px";
    h.style.fontWeight = "700";
    h.textContent = "조사 상세(오름차순)";
    body.appendChild(h);

    for (const rec of records) {
      body.appendChild(document.createElement("hr"));
      const d = rec.detail || {};
      body.appendChild(kv("조사일자", d.E || rec.date || ""));
      body.appendChild(kv("신발 전산 / 수량 / 차이", `${d.F ?? ""} / ${d.H ?? ""} / ${d.I ?? ""}`));
      body.appendChild(kv("용품 전산 / 수량 / 차이", `${d.O ?? ""} / ${d.Q ?? ""} / ${d.R ?? ""}`));
      body.appendChild(kv("의류 전산 / 수량 / 차이", `${d.X ?? ""} / ${d.Z ?? ""} / ${d.AA ?? ""}`));
      body.appendChild(kv("합계 전산 / 수량 / 차이", `${d.AG ?? ""} / ${d.AI ?? ""} / ${d.AJ ?? ""}`));
      body.appendChild(kv("최종점수(AP)", fmt2(rec.ap)));
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

  rows = rows.slice().sort((a, b) => {
    if (access.mode === "master") {
      const c1 = (a.dd || "").localeCompare(b.dd || "", "ko");
      if (c1 !== 0) return c1;
    }
    return (a.store || "").localeCompare(b.store || "", "ko");
  });

  renderTable(rows);
  setStatus(`표시: ${rows.length}행 (${access.mode === "master" ? "전체" : access.dd})`);
}

function resetUi() {
  $("codeInput").value = "";
  $("masterInput").value = "";
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
