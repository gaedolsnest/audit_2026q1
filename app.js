const DATA_URL = "webdata.bin";

// ===== desktop-like blob format =====
const MAGIC = new TextEncoder().encode("SCOREENC\n"); // 9 bytes
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200_000;

// internal passphrase used to encrypt the file (you choose one and keep it secret)
// NOTE: this is not the region code; this is an internal key for the whole file.
// In your pipeline, keep it same as used by web_build_data.py
const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";

// master key (UI input). if matches, show all.
const MASTER_KEY = "audit2026!";

let decryptedData = null; // { regions: {...}, rows: [...] }

const $ = (id) => document.getElementById(id);

function setStatus(msg) {
  $("status").textContent = msg || "";
}

function toNorm(s) {
  return (s || "").replace(/\s+/g, "").trim().toLowerCase();
}

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
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

function startsWithMagic(buf) {
  if (buf.byteLength < MAGIC.byteLength) return false;
  const u = new Uint8Array(buf);
  for (let i = 0; i < MAGIC.byteLength; i++) {
    if (u[i] !== MAGIC[i]) return false;
  }
  return true;
}

async function decryptBlob(arrayBuffer) {
  if (!startsWithMagic(arrayBuffer)) {
    throw new Error("Invalid webdata.bin (missing magic header)");
  }
  const u = new Uint8Array(arrayBuffer);
  let off = MAGIC.byteLength;

  const salt = u.slice(off, off + SALT_LEN);
  off += SALT_LEN;
  const nonce = u.slice(off, off + NONCE_LEN);
  off += NONCE_LEN;
  const ct = u.slice(off);

  const key = await pbkdf2Key(INTERNAL_PASSPHRASE, salt);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ct
  );

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

  let obj;
  try {
    obj = JSON.parse(jsonText);
  } catch {
    throw new Error("Decrypted content is not valid JSON");
  }

  if (!obj || typeof obj !== "object" || !obj.regions || !obj.rows) {
    throw new Error("Invalid JSON schema (need regions, rows)");
  }

  decryptedData = obj;
  setStatus(`로드 완료: 지역 ${Object.keys(obj.regions).length} / 행 ${obj.rows.length}`);

  // populate dd dropdown
  const dds = Object.keys(obj.regions).sort((a, b) => a.localeCompare(b, "ko"));
  const sel = $("ddSelect");
  sel.innerHTML = "";
  for (const dd of dds) {
    const opt = document.createElement("option");
    opt.value = dd;
    opt.textContent = dd;
    sel.appendChild(opt);
  }
}

function validateAccess() {
  if (!decryptedData) throw new Error("먼저 '데이터 로드'를 눌러주세요.");

  const dd = $("ddSelect").value;
  const code = $("codeInput").value;
  const master = $("masterInput").value;

  if (master && master === MASTER_KEY) {
    return { mode: "master", dd: null };
  }
  if (!dd) throw new Error("지역을 선택하세요.");
  if (!code) throw new Error("암호를 입력하세요.");

  const expected = toNorm(decryptedData.regions[dd] || "");
  if (!expected) throw new Error("지역 정보가 없습니다.");
  if (toNorm(code) !== expected) throw new Error("지역/암호가 틀립니다.");

  return { mode: "region", dd };
}

function renderTable(rows) {
  const tbody = $("resultTable").querySelector("tbody");
  tbody.innerHTML = "";

  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.dataset.rowId = r.id;

    tr.innerHTML = `
      <td>${r.dd || ""}</td>
      <td title="${r.store || ""}">${r.store || ""}</td>
      <td>${r.name || ""}</td>
      <td>${r.emp || ""}</td>
      <td>${r.pos || ""}</td>
      <td class="num">${fmt2(r.ap)}</td>
    `;
    tr.addEventListener("click", () => openDetail(r));
    tbody.appendChild(tr);
  }
}

function openDetail(r) {
  const dlg = $("detailDlg");
  $("dlgTitle").textContent = `${r.dd || ""} / ${r.store || ""} / ${r.name || ""}`;

  // 원하는 상세 항목만 (너가 말했던 컬럼들)
  const detail = r.detail || {};
  const fields = [
    ["조사일자", detail.E],
    ["신발 전산", detail.F],
    ["신발 수량", detail.H],
    ["신발 차이", detail.I],
    ["용품 전산", detail.O],
    ["용품 수량", detail.Q],
    ["용품 차이", detail.R],
    ["의류 전산", detail.X],
    ["의류 수량", detail.Z],
    ["의류 차이", detail.AA],
    ["합계 전산", detail.AG],
    ["합계 수량", detail.AI],
    ["합계 차이", detail.AJ],
    ["최종점수(AP)", fmt2(r.ap)],
  ];

  const body = $("dlgBody");
  body.innerHTML = "";
  for (const [k, v] of fields) {
    const div = document.createElement("div");
    div.className = "kv";
    div.innerHTML = `<div class="k">${k}</div><div class="v">${v ?? ""}</div>`;
    body.appendChild(div);
  }

  dlg.showModal();
}

function doSearch() {
  const access = validateAccess();
  const q = toNorm($("qInput").value);

  let rows = decryptedData.rows;

  if (access.mode === "region") {
    rows = rows.filter(r => r.dd === access.dd);
  }

  if (q) {
    rows = rows.filter(r => toNorm(r.store).includes(q) || toNorm(r.name).includes(q));
  }

  // 정렬: 지역조회면 점포 오름차순 / 마스터면 지역->점포 오름차순
  rows = rows.slice().sort((a, b) => {
    if (access.mode === "master") {
      const c1 = (a.dd || "").localeCompare(b.dd || "", "ko");
      if (c1 !== 0) return c1;
    }
    return (a.store || "").localeCompare(b.store || "", "ko");
  });

  renderTable(rows);
  setStatus(`표시: ${rows.length}건 (${access.mode === "master" ? "전체" : access.dd})`);
}

function resetUi() {
  $("codeInput").value = "";
  $("masterInput").value = "";
  $("qInput").value = "";
  $("resultTable").querySelector("tbody").innerHTML = "";
  setStatus("");
}

$("loadBtn").addEventListener("click", async () => {
  try {
    await loadData();
  } catch (e) {
    setStatus(String(e.message || e));
  }
});

$("searchBtn").addEventListener("click", () => {
  try {
    doSearch();
  } catch (e) {
    setStatus(String(e.message || e));
  }
});

$("resetBtn").addEventListener("click", () => resetUi());

$("dlgClose").addEventListener("click", () => $("detailDlg").close());
