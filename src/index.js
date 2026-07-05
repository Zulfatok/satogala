// src/index.js
import PostalMime from "postal-mime";

/**
 * Cloudflare Email Routing + Email Worker + Web Inbox
 * Features:
 * - Signup/Login/Logout
 * - Reset password via Resend (optional; but recommended)
 * - Mail (alias) management with per-user limit
 * - Admin dashboard: list users, set mail limit, disable user, DELETE user
 * - Email handler: accept via catch-all, store if mail registered else reject
 */

const encoder = new TextEncoder();

// -------------------- Security/Hashing constants --------------------
const PBKDF2_MAX_ITERS = 100000; // Cloudflare Workers WebCrypto limit
const PBKDF2_MIN_ITERS = 10000; // sensible floor

let USERS_HAS_PASS_ITERS = null;
let ALIASES_HAS_DOMAIN = null;
let EMAILS_HAS_DOMAIN = null;
let ATTACHMENTS_SCHEMA_READY = null;
let DOMAINS_SCHEMA_READY = null;

// -------------------- Response helpers --------------------
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

function badRequest(msg) {
  return json({ ok: false, error: msg }, 400);
}
function unauthorized(msg = "Unauthorized") {
  return json({ ok: false, error: msg }, 401);
}
function forbidden(msg = "Forbidden") {
  return json({ ok: false, error: msg }, 403);
}
function notFound() {
  return json({ ok: false, error: "Not found" }, 404);
}

// -------------------- Utils --------------------
function safeInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function envFlag(v, fallback = false) {
  if (v === undefined || v === null || v === "") return fallback;
  return /^(1|true|yes|on)$/i.test(String(v).trim());
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function clampPbkdf2Iters(n) {
  const x = safeInt(n, PBKDF2_MAX_ITERS);
  return Math.min(PBKDF2_MAX_ITERS, Math.max(PBKDF2_MIN_ITERS, x));
}

function pbkdf2Iters(env) {
  return clampPbkdf2Iters(env.PBKDF2_ITERS ?? PBKDF2_MAX_ITERS);
}

function base64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(b64url) {
  const b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Base64Url(inputBytes) {
  const digest = await crypto.subtle.digest("SHA-256", inputBytes);
  return base64Url(new Uint8Array(digest));
}

async function pbkdf2HashBase64Url(password, saltBytes, iterations) {
  const it = safeInt(iterations, 0);
  if (it > PBKDF2_MAX_ITERS) {
    const err = new Error(
      `PBKDF2 iterations too high for Workers (max ${PBKDF2_MAX_ITERS}, got ${it}).`
    );
    err.name = "NotSupportedError";
    throw err;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: it },
    keyMaterial,
    256
  );

  return base64Url(new Uint8Array(bits));
}

function getCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

function setCookieHeader(name, value, opts = {}) {
  const { httpOnly = true, secure = true, sameSite = "Lax", path = "/", maxAge } = opts;

  let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
  if (httpOnly) c += "; HttpOnly";
  if (secure) c += "; Secure";
  if (typeof maxAge === "number") c += `; Max-Age=${maxAge}`;
  return c;
}

async function readJson(request) {
  try {
    const ct = request.headers.get("content-type") || "";
    if (!ct.toLowerCase().includes("application/json")) return null;
    return await request.json();
  } catch {
    return null;
  }
}

function validLocalPart(local) {
  return /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(local);
}

async function usersHasPassIters(env) {
  if (USERS_HAS_PASS_ITERS !== null) return USERS_HAS_PASS_ITERS;
  try {
    const res = await env.DB.prepare(`PRAGMA table_info(users)`).all();
    USERS_HAS_PASS_ITERS = (res.results || []).some((r) => r?.name === "pass_iters");
  } catch {
    USERS_HAS_PASS_ITERS = false;
  }
  return USERS_HAS_PASS_ITERS;
}

async function aliasesHasDomain(env) {
  if (ALIASES_HAS_DOMAIN !== null) return ALIASES_HAS_DOMAIN;
  try {
    const res = await env.DB.prepare(`PRAGMA table_info(aliases)`).all();
    ALIASES_HAS_DOMAIN = (res.results || []).some((r) => r?.name === "domain");
  } catch {
    ALIASES_HAS_DOMAIN = false;
  }
  return ALIASES_HAS_DOMAIN;
}

async function emailsHasDomain(env) {
  if (EMAILS_HAS_DOMAIN !== null) return EMAILS_HAS_DOMAIN;
  try {
    const res = await env.DB.prepare(`PRAGMA table_info(emails)`).all();
    EMAILS_HAS_DOMAIN = (res.results || []).some((r) => r?.name === "domain");
  } catch {
    EMAILS_HAS_DOMAIN = false;
  }
  return EMAILS_HAS_DOMAIN;
}

function envAllowedDomains(env) {
  const domainsStr = env.ALLOWED_DOMAINS || env.DOMAIN || "";
  return domainsStr
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0);
}

function validDomainName(domain) {
  const d = String(domain || "").trim().toLowerCase();
  if (d.length < 4 || d.length > 253 || !d.includes(".")) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d);
}

async function ensureDomainsSchema(env) {
  if (DOMAINS_SCHEMA_READY) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS allowed_domains (
      domain TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL
    )`
  ).run();
  DOMAINS_SCHEMA_READY = true;
}

async function getStoredDomains(env) {
  try {
    await ensureDomainsSchema(env);
    const rows = await env.DB.prepare(
      `SELECT domain, created_at FROM allowed_domains ORDER BY domain ASC`
    ).all();
    return (rows.results || [])
      .map((r) => ({ domain: String(r.domain || "").toLowerCase(), created_at: r.created_at }))
      .filter((r) => validDomainName(r.domain));
  } catch (e) {
    console.log("domains db error:", e && e.message ? e.message : e);
    return [];
  }
}

async function getAllowedDomains(env) {
  const seen = new Set();
  const out = [];
  for (const d of [...envAllowedDomains(env), ...(await getStoredDomains(env)).map((r) => r.domain)]) {
    if (!validDomainName(d) || seen.has(d)) continue;
    seen.add(d);
    out.push(d);
  }
  return out;
}

async function getDomainSettings(env) {
  const envDomains = envAllowedDomains(env).filter(validDomainName);
  const envSet = new Set(envDomains);
  const storedDomains = await getStoredDomains(env);
  const storedSet = new Set(storedDomains.map((r) => r.domain));
  const all = [];
  const seen = new Set();

  for (const d of envDomains) {
    if (seen.has(d)) continue;
    seen.add(d);
    all.push({ domain: d, source: storedSet.has(d) ? "env+admin" : "env", can_delete: false });
  }
  for (const row of storedDomains) {
    if (seen.has(row.domain)) continue;
    seen.add(row.domain);
    all.push({ domain: row.domain, source: "admin", can_delete: true, created_at: row.created_at });
  }

  return all.sort((a, b) => a.domain.localeCompare(b.domain));
}

function cleanContentId(value) {
  let s = String(value || "").trim();
  try {
    s = decodeURIComponent(s);
  } catch { }
  return s.replace(/^<+|>+$/g, "").trim().toLowerCase();
}

function safeFileName(value, fallback = "attachment") {
  const name = String(value || fallback).trim() || fallback;
  return name.replace(/[^\w.\-()+ ]+/g, "_").slice(0, 120);
}

function sqlLikePattern(value) {
  const s = String(value || "").trim().toLowerCase().slice(0, 120);
  if (!s) return "";
  return `%${s.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

function attachmentBytes(att) {
  const content = att?.content;
  if (!content) return new Uint8Array();
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  if (ArrayBuffer.isView(content)) {
    return new Uint8Array(content.buffer, content.byteOffset, content.byteLength);
  }
  return new Uint8Array();
}

function attachmentMime(att) {
  return String(att?.mimeType || att?.contentType || "application/octet-stream").toLowerCase();
}

function isDisplayableImage(mime) {
  return /^image\/(png|jpe?g|gif|webp|bmp|svg\+xml)$/i.test(String(mime || ""));
}

function dataUrlForAttachment(att, maxBytes) {
  const bytes = attachmentBytes(att);
  const mime = attachmentMime(att);
  if (!bytes.length || bytes.byteLength > maxBytes || !isDisplayableImage(mime)) return null;

  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return `data:${mime};base64,${btoa(bin)}`;
}

function replaceCidRefs(htmlValue, cidToUrl) {
  if (!htmlValue || !cidToUrl || cidToUrl.size === 0) return htmlValue || "";
  return String(htmlValue).replace(/cid:([^"'\s>)]+)/gi, (full, cid) => {
    const url = cidToUrl.get(cleanContentId(cid));
    return url || full;
  });
}

async function ensureAttachmentsSchema(env) {
  if (ATTACHMENTS_SCHEMA_READY) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS email_attachments (
      id TEXT PRIMARY KEY,
      email_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      filename TEXT,
      mime_type TEXT NOT NULL,
      content_id TEXT,
      disposition TEXT,
      inline INTEGER NOT NULL DEFAULT 0,
      size INTEGER NOT NULL,
      r2_key TEXT,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`
  ).run();
  await env.DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_email_attachments_email ON email_attachments(email_id)`
  ).run();
  await env.DB.prepare(
    `CREATE INDEX IF NOT EXISTS idx_email_attachments_user ON email_attachments(user_id)`
  ).run();
  ATTACHMENTS_SCHEMA_READY = true;
}

async function getEmailAttachments(env, emailId, userId = null) {
  await ensureAttachmentsSchema(env);
  const q = userId
    ? env.DB.prepare(
      `SELECT id, email_id, filename, mime_type, content_id, disposition, inline, size, created_at
       FROM email_attachments
       WHERE email_id = ? AND user_id = ?
       ORDER BY created_at ASC`
    ).bind(emailId, userId)
    : env.DB.prepare(
      `SELECT id, email_id, filename, mime_type, content_id, disposition, inline, size, created_at
       FROM email_attachments
       WHERE email_id = ?
       ORDER BY created_at ASC`
    ).bind(emailId);

  const rows = await q.all();
  return (rows.results || []).map((a) => ({
    ...a,
    url: `/api/email-attachments/${encodeURIComponent(a.email_id)}/${encodeURIComponent(a.id)}`,
    is_image: isDisplayableImage(a.mime_type),
  }));
}


// -------------------- UI: Brand + Template --------------------
const LOGO_SVG = `
<svg viewBox="0 0 64 64" width="40" height="40" aria-hidden="true" focusable="false">
  <defs>
    <linearGradient id="nmLogoBg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#38d5c8"/>
      <stop offset="0.52" stop-color="#2563eb"/>
      <stop offset="1" stop-color="#f6c76f"/>
    </linearGradient>
    <linearGradient id="nmLogoText" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#f8fafc"/>
      <stop offset="1" stop-color="#7df4e7"/>
    </linearGradient>
    <filter id="nmLogoShadow" x="-35%" y="-35%" width="170%" height="170%">
      <feDropShadow dx="0" dy="10" stdDeviation="9" flood-color="#000" flood-opacity="0.38"/>
    </filter>
  </defs>
  <rect x="8" y="8" width="48" height="48" rx="15" fill="url(#nmLogoBg)" filter="url(#nmLogoShadow)"/>
  <rect x="13" y="13" width="38" height="38" rx="12" fill="rgba(5,9,16,0.78)" stroke="rgba(255,255,255,0.18)"/>
  <path d="M19 23 H45" stroke="rgba(125,244,231,0.82)" stroke-width="2" stroke-linecap="round"/>
  <path d="M19 43 H45" stroke="rgba(246,199,111,0.72)" stroke-width="2" stroke-linecap="round"/>
  <text x="32" y="38" text-anchor="middle" font-size="15" font-family="ui-sans-serif,system-ui,Arial" fill="url(#nmLogoText)" font-weight="900">N_M</text>
</svg>
`;
const FAVICON_DATA = encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="nmFavBg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#38d5c8"/>
      <stop offset="0.55" stop-color="#2563eb"/>
      <stop offset="1" stop-color="#f6c76f"/>
    </linearGradient>
    <linearGradient id="nmFavText" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#f8fafc"/>
      <stop offset="1" stop-color="#7df4e7"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="48" height="48" rx="15" fill="url(#nmFavBg)"/>
  <rect x="13" y="13" width="38" height="38" rx="12" fill="#070a10" opacity="0.78"/>
  <text x="32" y="38" text-anchor="middle" font-size="15" font-family="Arial" fill="url(#nmFavText)" font-weight="900">N_M</text>
</svg>
`);

function headerHtml({ badge, subtitle, rightHtml = "" }) {
  return `
  <header class="hdr">
    <div class="brand">
      <div class="logo">${LOGO_SVG}</div>
      <div class="brandText">
        <div class="brandName">N_MAZY</div>
        <div class="brandSub">${subtitle || ""}</div>
      </div>
      ${badge ? `<span class="pill">${badge}</span>` : ""}
    </div>
    <div class="hdrRight">${rightHtml}</div>
  </header>`;
}

function pageTemplate(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  <meta name="theme-color" content="#070a10">
  <link rel="icon" href="data:image/svg+xml,${FAVICON_DATA}">
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    base-uri 'none';
    object-src 'none';
    form-action 'self';
    frame-ancestors 'none';
    img-src 'self' data: https:;
    style-src 'self' 'unsafe-inline';
    script-src 'self' 'unsafe-inline';
    connect-src 'self';
    frame-src 'self';
  ">
  ${extraHead}
  <style>
    :root{
      /* Dark acrylic theme */
      --bg0:#07080d;
      --bg1:#0d0f16;
      --bg2:#161922;

      --card: rgba(20,23,31,.68);
      --card2: rgba(9,11,17,.78);
      --border: rgba(255,255,255,.12);

      --text:#f7f8fb;
      --muted:#a7adba;

      --brand:#38d5c8;
      --brand-light:#7df4e7;
      --brand2:#f6c76f;

      --danger:#ef4444;
      --success:#10b981;
      --warning:#f59e0b;

      /* paper (buat baca email biar jelas) */
      --paper:#f8fafc;
      --paperText:#0f172a;
      --paperBorder: rgba(2,6,23,.12);
    }

    *{box-sizing:border-box}
    body{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      margin:0;
      color:var(--text);
      min-height:100vh;
      background:
        linear-gradient(135deg, rgba(255,255,255,.045) 0 1px, transparent 1px 16px),
        linear-gradient(180deg, var(--bg1), var(--bg0) 55%, #050609);
      background-color: var(--bg0);
      position:relative;
    }
    body::before{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background:
        linear-gradient(120deg, rgba(56,213,200,.10), transparent 34%),
        linear-gradient(300deg, rgba(246,199,111,.08), transparent 38%);
      filter: blur(28px);
      opacity:.65;
    }

    a{color:var(--brand);text-decoration:none}
    a:hover{opacity:.92;text-decoration:underline}

    .wrap{max-width:1040px;margin:0 auto;padding:18px;position:relative;z-index:1}
    .hdr{
      display:flex;justify-content:space-between;align-items:center;
      gap:14px; padding:12px 0 6px;
    }
    .brand{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
    .logo{display:flex;align-items:center}
    .brandText{display:flex;flex-direction:column;line-height:1.05}
    .brandName{font-weight:900;letter-spacing:.2px}
    .brandSub{color:var(--muted);font-size:12.5px;margin-top:4px}
    .hdrRight{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

    .card{
      background:
        linear-gradient(180deg, rgba(255,255,255,.11), rgba(255,255,255,.025) 52%, rgba(0,0,0,.10)),
        var(--card);
      border:1px solid rgba(255,255,255,.14);
      border-radius:20px;
      padding:20px;
      margin:16px 0;
      box-shadow: 
        0 24px 70px rgba(0,0,0,.58),
        inset 0 1px 0 rgba(255,255,255,.12);
      backdrop-filter: blur(24px) saturate(135%);
      -webkit-backdrop-filter: blur(24px) saturate(135%);
      overflow:hidden;
    }

    input,button,select,textarea{font:inherit}
    label{display:block;margin-bottom:6px;color:var(--muted);font-size:13px}
    input,select,textarea{
      width:100%;
      padding:12px 12px;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(5,7,12,.72);
      color:var(--text);
      outline:none;
    }
    input::placeholder{color: rgba(167,173,186,.62)}
    input:focus,select:focus,textarea:focus{
      border-color: rgba(56,213,200,.72);
      box-shadow: 0 0 0 4px rgba(56,213,200,.12);
    }

    /* Password show/hide */
    .pwWrap{ position:relative; }
    .pwWrap input{ padding-right: 92px; } /* ruang buat tombol */
    .pwToggle{
      position:absolute;
      right:10px;
      top:50%;
      transform:translateY(-50%);
      padding:6px 10px;
      border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.075);
      color: #d9dde6;
      font-size:12px;
      cursor:pointer;
    }
    .pwToggle:hover{
      background: rgba(56,213,200,.14);
      color: var(--text);
      border-color: rgba(56,213,200,.34);
    }

    button{
      padding:11px 16px;
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.07);
      color:var(--text);
      cursor:pointer;
      font-weight:500;
      transition: all .2s ease;
      white-space:nowrap;
    }
    button:hover{
      background: rgba(255,255,255,.11);
      border-color: rgba(56,213,200,.38);
      transform: translateY(-1px);
      box-shadow: 0 12px 30px rgba(0,0,0,.28);
    }
    button:active{transform: translateY(0)}
    .btn-primary{
      background: linear-gradient(135deg, rgba(56,213,200,.28), rgba(246,199,111,.18));
      border-color: rgba(56,213,200,.46);
      font-weight:600;
      box-shadow: 0 14px 36px rgba(0,0,0,.34), 0 0 0 1px rgba(255,255,255,.04) inset;
    }
    .btn-primary:hover{
      background: linear-gradient(135deg, rgba(56,213,200,.36), rgba(246,199,111,.24));
      border-color: rgba(125,244,231,.64);
      box-shadow: 0 18px 42px rgba(0,0,0,.42), 0 0 24px rgba(56,213,200,.10);
      transform: translateY(-2px);
    }
    .btn-ghost{background: rgba(255,255,255,.04)}
    .danger{
      border-color: rgba(239,68,68,.50);
      background: rgba(239,68,68,.12);
    }
    .danger:hover{background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.60)}

    .muted{color:var(--muted)}
    .pill{
      display:inline-flex;align-items:center;gap:6px;
      padding:6px 10px;border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.065);
      color:#cfd4df;
      font-size:12px;
    }
    .kbd{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      padding:2px 8px;
      border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.04);
      color: var(--muted);
    }

    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .split{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start}

    .listItem{
      padding:12px 0;
      border-bottom:1px solid var(--border);
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      flex-wrap:wrap;
    }

    /* Inbox list */
    .mailItem{
      padding:12px 12px;
      border:1px solid var(--border);
      border-radius:16px;
      background: rgba(255,255,255,.03);
      margin-bottom:10px;
    }
    .mailSubject{font-weight:900; font-size:14.5px}
    .mailMeta{color:var(--muted); font-size:12.5px; margin-top:4px; line-height:1.35}
    .mailSnippet{
      color: rgba(238,242,255,.92);
      font-size: 13.5px;
      margin-top:10px;
      line-height:1.55;
      white-space:pre-wrap;
      word-break:break-word;
    }

    /* Viewer */
    .viewerHead{
      display:flex;
      justify-content:space-between;
      gap:10px;
      align-items:flex-start;
      flex-wrap:wrap;
    }
    .paper{
      background: var(--paper);
      color: var(--paperText);
      border: 1px solid var(--paperBorder);
      border-radius: 16px;
      padding: 14px;
    }
    .mailFrame{
      width:100%;
      height: 70vh;
      border: 1px solid var(--paperBorder);
      border-radius: 16px;
      background: var(--paper);
    }
    .mailText{
      white-space:pre-wrap;
      word-break:break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 14px;
      line-height: 1.65;
      margin:0;
    }

    .hr{border:0;border-top:1px solid var(--border);margin:12px 0}

    /* Checkbox styling */
    .emailCheckbox{
      width:20px;
      height:20px;
      cursor:pointer;
      accent-color: var(--brand);
      flex-shrink:0;
    }
    .selectAllCheckbox{
      width:18px;
      height:18px;
      cursor:pointer;
      accent-color: var(--brand);
      margin-right:8px;
    }
    .mailItem.selected{
      background: rgba(59,130,246,.12);
      border-color: rgba(59,130,246,.45);
    }
    .bulkActions{
      display:flex;
      gap:10px;
      align-items:center;
      flex-wrap:wrap;
      padding:10px 12px;
      background: rgba(59,130,246,.08);
      border:1px solid rgba(59,130,246,.3);
      border-radius:12px;
      margin-bottom:10px;
    }

    @media (max-width: 860px){
      .split{grid-template-columns:1fr}
    }
    @media (max-width: 760px){
      .wrap{padding:14px}
      .hdr{flex-direction:column;align-items:flex-start}
      .row{grid-template-columns:1fr}
      .mailFrame{height: 58vh;}
      
      /* Admin page + Mail list mobile optimization */
      .listItem{
        flex-direction:column!important;
        align-items:flex-start!important;
        padding:12px!important;
        display:flex!important;
        width:100%!important;
      }
      .listItem > div{
        width:100%!important;
        min-width:0!important;
        display:block!important;
      }
      .listItem input{width:100%!important;max-width:none!important}
      .listItem button{
        flex:1;
        min-width:0;
        font-size:13px;
        padding:10px 12px;
        display:block!important;
        width:100%!important;
      }
      
      /* Mail list specific - ensure visibility with aggressive rules */
      #aliases{
        min-height:40px!important;
        display:block!important;
        visibility:visible!important;
        opacity:1!important;
        width:100%!important;
      }
      #aliases > div{
        display:block!important;
        visibility:visible!important;
        opacity:1!important;
        width:100%!important;
        margin-bottom:10px!important;
      }
      #aliases .listItem{
        display:flex!important;
        visibility:visible!important;
        opacity:1!important;
        width:100%!important;
        background:rgba(255,255,255,.03)!important;
        border:1px solid var(--border)!important;
        border-radius:12px!important;
        padding:12px!important;
        margin-bottom:8px!important;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
  </div>
</body>
</html>`;
}

// -------------------- Pages --------------------
const PAGES = {
  login() {
    return pageTemplate(
      "Login",
      `
      ${headerHtml({
        badge: "Login",
        subtitle: "Mail Portal • Kelola mail & inbox",
        rightHtml: `<a class="pill" href="/signup">Buat akun</a>`,
      })}

      <div class="card">
        <div class="row">
          <div>
            <label>Username / Email</label>
            <input id="id" placeholder="sipar / sipar@gmail.com" autocomplete="username" />
          </div>
          <div>
            <label>Password</label>
            <div class="pwWrap">
              <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password" />
              <button type="button" class="pwToggle" onclick="togglePw('pw', this)">Show</button>
            </div>
          </div>
        </div>

        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="login()">Login</button>
          <a href="/reset" class="muted">Lupa password?</a>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }
        async function login(){
          const id = document.getElementById('id').value.trim();
          const pw = document.getElementById('pw').value;
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/login',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({id,pw})
          });
          const j = await readJsonOrText(r);
          if(j.ok){ location.href='/app'; return; }
          out.textContent = j.error || 'gagal';
        }
      </script>
      `
    );
  },

  signup() {
    return pageTemplate(
      "Signup",
      `
      ${headerHtml({
        badge: "Signup",
        subtitle: "Buat akun baru",
        /*
        subtitle: "Buat akun • Pilih domain",
        */
        rightHtml: `<a class="pill" href="/login">Login</a>`,
      })}

      <div class="card">
        <div class="row">
          <div>
            <label>Username</label>
            <input id="u" placeholder="sipar" autocomplete="username" />
          </div>
          <div>
            <label>Email (untuk reset password)</label>
            <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
          </div>
        </div>

        <div class="row" style="margin-top:12px">
          <div>
            <label>Password</label>
            <div class="pwWrap">
              <input id="pw" type="password" placeholder="minimal 8 karakter" autocomplete="new-password" />
              <button type="button" class="pwToggle" onclick="togglePw('pw', this)">Show</button>
            </div>
          </div>
          <div>
            <label>Konfirmasi Password</label>
            <div class="pwWrap">
              <input id="pwConfirm" type="password" placeholder="ulangi password" autocomplete="new-password" />
              <button type="button" class="pwToggle" onclick="togglePw('pwConfirm', this)">Show</button>
            </div>
          </div>
        </div>

        <div style="margin-top:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="signup()">Buat Akun</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }
        async function signup(){
          const username = document.getElementById('u').value.trim();
          const email = document.getElementById('e').value.trim();
          const pw = document.getElementById('pw').value;
          const pwConfirm = document.getElementById('pwConfirm').value;
          const out = document.getElementById('out');
          if(pw !== pwConfirm){
            out.textContent = 'Konfirmasi password tidak cocok';
            return;
          }
          out.textContent = '...';
          const r = await fetch('/api/auth/signup',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({username,email,pw,pwConfirm})
          });
          const j = await readJsonOrText(r);
          if(j.ok){ location.href='/app'; return; }
          out.textContent = j.error || 'gagal';
        }
      </script>
      `
    );
  },

  reset() {
    return pageTemplate(
      "Reset Password",
      `
      ${headerHtml({
        badge: "Reset",
        subtitle: "Kirim token reset / set password baru",
        rightHtml: `<a class="pill" href="/login">Login</a>`,
      })}

      <div class="card">
        <label>Email akun</label>
        <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="reqReset()">Kirim Token</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <div class="card">
        <div class="muted">Punya token?</div>
        <div class="row" style="margin-top:10px">
          <div>
            <label>Token</label>
            <input id="t" placeholder="token dari email" />
          </div>
          <div>
            <label>Password baru</label>
            <div class="pwWrap">
              <input id="npw" type="password" placeholder="••••••••" autocomplete="new-password" />
              <button type="button" class="pwToggle" onclick="togglePw('npw', this)">Show</button>
            </div>
          </div>
        </div>
        <div style="margin-top:12px">
          <button class="btn-primary" onclick="confirmReset()">Set Password</button>
        </div>
        <pre id="out2" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }

        // autofill token from #token=...
        (function(){
          try{
            const h = location.hash || '';
            const m = h.match(/token=([^&]+)/);
            if(m && m[1]){
              document.getElementById('t').value = decodeURIComponent(m[1]);
            }
          }catch{}
        })();

        async function reqReset(){
          const email = document.getElementById('e').value.trim();
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/request',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({email})
          });
          const j = await readJsonOrText(r);
          out.textContent = j.ok ? 'Jika email terdaftar, token akan dikirim.' : (j.error || 'gagal');
        }

        async function confirmReset(){
          const token = document.getElementById('t').value.trim();
          const newPw = document.getElementById('npw').value;
          const out = document.getElementById('out2');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/confirm',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({token,newPw})
          });
          const j = await readJsonOrText(r);
          out.textContent = j.ok ? 'Password diubah. Silakan login.' : (j.error || 'gagal');
        }
      </script>
      `
    );
  },

  app(domains) {
    const domainOptions = domains.map(d => `<option value="${d}">${d}</option>`).join('');

    return pageTemplate(
      "Inbox",
      `
      ${headerHtml({
        badge: "Inbox",
        subtitle: "Kelola mail & baca inbox",
        rightHtml: `
          <a href="/admin" id="adminLink" class="pill" style="display:none">Admin</a>
          <button class="danger" onclick="logout()">Logout</button>
        `,
      })}

      <div class="card" id="accountPanel">
        <div class="row">
          <div>
            <div class="muted">Akun</div>
            <div id="me" style="margin-top:6px">...</div>
          </div>
          <div>
            <div class="muted">Buat mail baru</div>
            <div style="margin-top:10px">
              <div style="display:grid;grid-template-columns:1fr auto;gap:10px;margin-bottom:10px">
                <input id="alias" placeholder="contoh: sipar" />
                <button class="btn-primary" onclick="createAlias()">Create</button>
              </div>
              <select id="domainSelect" style="width:100%">
                ${domainOptions}
              </select>
            </div>
            <div id="aliasMsg" class="muted" style="margin-top:8px"></div>
          </div>
        </div>
      </div>

      <div class="card" id="globalSearchPanel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <b>Cari Pesan</b>
          <span class="muted">Semua mail</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr auto;gap:10px">
          <input id="globalEmailSearch" placeholder="Cari subject, pengirim, penerima, alias, atau isi pesan..." oninput="setGlobalSearchQuery(this.value)" onkeydown="if(event.key===&quot;Enter&quot;){event.preventDefault();setGlobalSearchQuery(this.value,true)}" />
          <button class="btn-ghost" onclick="clearGlobalEmailSearch()">Clear</button>
        </div>
        <div id="globalSearchResults" style="margin-top:12px"></div>
      </div>
      <div class="card" id="mailPanel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
          <b>Mail</b>
          <span class="muted" id="limitInfo"></span>
        </div>
        <div id="aliases" style="margin-top:10px"></div>
      </div>

      <div class="card" id="emailView" style="display:none"></div>

      <script>
        // Browser compatibility detection
        console.log('User Agent:', navigator.userAgent);
        console.log('Screen:', window.innerWidth + 'x' + window.innerHeight);
        console.log('Viewport:', document.documentElement.clientWidth + 'x' + document.documentElement.clientHeight);
        
        const DOMAINS = ${JSON.stringify(domains)};
        let ME=null;
        let SELECTED=null;
        let AUTO_REFRESH_INTERVAL=null;
        let SELECTED_EMAILS=[];
        let SEARCH_QUERY='';
        let SEARCH_TIMER=null;
        let GLOBAL_SEARCH_QUERY='';
        let GLOBAL_SEARCH_TIMER=null;

        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        function fmtDate(v){
          if(v===null || v===undefined || v==='') return '';
          try{
            // handle seconds epoch
            if(typeof v === 'number'){
              const ms = v < 1000000000000 ? (v*1000) : v;
              return new Date(ms).toLocaleString();
            }
            // if string numeric seconds
            const s = String(v);
            if(/^\\d{9,13}$/.test(s)){
              const n = Number(s);
              const ms = n < 1000000000000 ? (n*1000) : n;
              return new Date(ms).toLocaleString();
            }
            const d = new Date(v);
            if (Number.isNaN(d.getTime())) return String(v);
            return d.toLocaleString();
          }catch{ return String(v); }
        }

        // consistent builder for inbox DOM id to avoid mismatches
        function inboxDomId(local, domain){
          const safeDomain = String(domain||'').toLowerCase().replace(/[^a-z0-9]+/g,'_');
          return 'inbox_'+local+'_'+safeDomain;
        }

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          j.status = r.status;
          return j;
        }

        function setSearchQuery(value, immediate=false){
          SEARCH_QUERY = String(value || '').trim();
          SELECTED_EMAILS = [];
          if(SEARCH_TIMER) clearTimeout(SEARCH_TIMER);
          if(immediate){
            loadEmails();
            return;
          }
          SEARCH_TIMER = setTimeout(()=>loadEmails(true), 350);
        }

        function clearEmailSearch(){
          SEARCH_QUERY = '';
          SELECTED_EMAILS = [];
          if(SEARCH_TIMER) clearTimeout(SEARCH_TIMER);
          loadEmails();
        }

        function setGlobalSearchQuery(value, immediate=false){
          GLOBAL_SEARCH_QUERY = String(value || '').trim();
          if(GLOBAL_SEARCH_TIMER) clearTimeout(GLOBAL_SEARCH_TIMER);
          if(immediate){
            loadGlobalEmails();
            return;
          }
          GLOBAL_SEARCH_TIMER = setTimeout(()=>loadGlobalEmails(), 350);
        }

        function clearGlobalEmailSearch(){
          GLOBAL_SEARCH_QUERY = '';
          if(GLOBAL_SEARCH_TIMER) clearTimeout(GLOBAL_SEARCH_TIMER);
          const input = document.getElementById('globalEmailSearch');
          if(input) input.value = '';
          const box = document.getElementById('globalSearchResults');
          if(box) box.innerHTML = '';
        }

        async function loadGlobalEmails(){
          const box = document.getElementById('globalSearchResults');
          if(!box) return;
          const q = GLOBAL_SEARCH_QUERY;
          if(!q){
            box.innerHTML = '';
            return;
          }
          box.innerHTML = '<div class="muted">Mencari...</div>';
          try{
            const j = await api('/api/emails-search?q='+encodeURIComponent(q));
            if(!j.ok){
              box.innerHTML = '<div class="muted">Gagal mencari: '+esc(j.error||'gagal')+'</div>';
              return;
            }
            const emails = j.emails || [];
            if(!emails.length){
              box.innerHTML = '<div class="muted" style="padding:14px;border:1px dashed rgba(148,163,184,.3);border-radius:12px">Tidak ada pesan yang cocok.</div>';
              return;
            }
            let html = '<div class="muted" style="font-size:12px;margin-bottom:10px">Hasil pencarian: <span class="kbd">'+esc(q)+'</span></div>';
            for(const m of emails){
              const addr = (m.local_part || '') + (m.domain ? '@'+m.domain : '');
              html += '<div class="mailItem" onclick="openEmail(\\''+m.id+'\\')">'+
                '<div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap">'+
                  '<div style="flex:1;min-width:0">'+
                    '<div class="mailSubject">'+esc(m.subject||'(no subject)')+'</div>'+
                    '<div class="mailMeta">Mail: '+esc(addr)+'</div>'+
                    '<div class="mailMeta">From: '+esc(m.from_addr||'')+'</div>'+
                    '<div class="mailMeta">'+esc(fmtDate(m.date || m.created_at || ""))+'</div>'+
                    (m.snippet ? '<div class="mailSnippet">'+esc(m.snippet)+'</div>' : '')+
                  '</div>'+
                  '<button class="btn-primary" onclick="event.stopPropagation();openEmail(\\''+m.id+'\\')">View</button>'+
                '</div>'+
              '</div>';
            }
            box.innerHTML = html;
          }catch(e){
            box.innerHTML = '<div class="muted">Gagal mencari: '+esc(e && e.message ? e.message : String(e))+'</div>';
          }
        }

        async function loadMe(){
          const meBox = document.getElementById('me');
          try{
            const j = await api('/api/me');
            if(!j.ok){
              meBox.innerHTML = '<span class="muted">Session habis. Mengalihkan ke login...</span>';
              location.href='/login';
              return;
            }
            ME=j.user;
            meBox.innerHTML =
              '<div><b>'+esc(ME.username)+'</b> <span class="muted">('+esc(ME.email)+')</span></div>'+
              '<div class="muted" style="margin-top:4px">role: '+esc(ME.role)+'</div>';
            document.getElementById('limitInfo').textContent = 'limit: '+ME.alias_limit;
            if(ME.role==='admin') document.getElementById('adminLink').style.display='inline-flex';
          }catch(e){
            meBox.innerHTML =
              '<div style="color:#fca5a5;font-weight:700">Gagal load akun</div>'+
              '<div class="muted" style="margin-top:4px">'+esc(e && e.message ? e.message : String(e))+'</div>'+
              '<div style="margin-top:8px"><a class="pill" href="/login">Login ulang</a></div>';
            throw e;
          }
        }

        async function loadAliases(){
          const j = await api('/api/aliases');
          console.log('loadAliases response:', j); // DEBUG
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box = document.getElementById('aliases');
          console.log('aliases box element:', box); // DEBUG
          
          // Force clear and reset
          box.innerHTML='';
          box.style.display='block';
          box.style.visibility='visible';
          box.style.minHeight='40px';
          
          if(j.aliases.length===0){
            box.innerHTML='<div class="muted">Belum ada mail.</div>';
            return;
          }
          console.log('Number of aliases:', j.aliases.length); // DEBUG
          
          // Build HTML string instead of DOM manipulation for better compatibility
          var html = '';
          for(var i=0; i<j.aliases.length; i++){
            var a = j.aliases[i];
            var addr = a.local_part+'@'+a.domain;
            var isOpen = SELECTED===a.local_part+'@'+a.domain;
            var inboxId = inboxDomId(a.local_part, a.domain);
            
            html += '<div style="margin-bottom:10px;display:block;width:100%">'+
              '<div class="listItem" style="display:flex;flex-direction:column;width:100%;gap:10px">'+
                '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;width:100%">'+
                  '<button class="btn-primary" onclick="selectAlias(\\''+a.local_part+'\\',\\''+a.domain+'\\')">'+
                    (isOpen?'Close':'Open')+
                  '</button>'+
                  '<span style="flex:1"><b>'+esc(addr)+'</b></span>'+
                  (a.disabled?'<span class="pill">disabled</span>':'')+
                '</div>'+
                '<div style="width:100%"><button onclick="delAlias(\\''+a.local_part+'\\',\\''+a.domain+'\\')" class="danger" style="width:100%">Delete</button></div>'+
              '</div>'+
              '<div id="'+inboxId+'" style="display:'+(isOpen?'block':'none')+';margin-top:10px;padding-left:10px"></div>'+
            '</div>';
            
            console.log('Added alias:', addr); // DEBUG
          }
          
          box.innerHTML = html;
          
          if(SELECTED){ await loadEmails(); }
        }

        async function selectAlias(local, domain){
          const key = local+'@'+domain;
          const wasSelected = SELECTED===key;
          
          if(wasSelected){
            SELECTED=null;
            stopAutoRefresh();
          } else {
            SELECTED=key;
            SELECTED_EMAILS=[];
            startAutoRefresh();
          }
          
          await loadAliases();
          
          if(!wasSelected){
            const inbox = document.getElementById('inbox_'+local+'_'+domain.replace(/\./g,'_'));
            if(inbox) inbox.scrollIntoView({behavior:'smooth', block:'nearest'});
          }
        }

        async function loadEmails(silent=false){
          console.log('📧 === loadEmails START ===');
          console.log('📧 SELECTED:', SELECTED);
          if(!SELECTED) {
            console.log('⚠️ No SELECTED alias!');
            return;
          }
          
          const [local, domain] = SELECTED.split('@');
          const inboxId = inboxDomId(local, domain);
          console.log('📧 Looking for inbox ID:', inboxId);
          const box=document.getElementById(inboxId);
          console.log('📧 Inbox element found:', box);
          if(!box) {
            console.error('❌ Inbox container NOT FOUND! ID:', inboxId);
            return;
          }
          
          // FORCE VISIBILITY
          box.style.display = 'block';
          box.style.visibility = 'visible';
          box.style.opacity = '1';
          box.style.minHeight = '100px';
          box.style.background = 'rgba(59,130,246,0.05)';
          box.style.border = '2px solid rgba(59,130,246,0.3)';
          box.style.padding = '12px';
          box.style.borderRadius = '8px';
          console.log('✅ Forced visibility CSS applied to inbox container');
          
          try{
            console.log('📧 Fetching emails from API...');
            const searchParam = SEARCH_QUERY ? '&q='+encodeURIComponent(SEARCH_QUERY) : '';
            const j = await api('/api/emails?alias='+encodeURIComponent(local)+'&domain='+encodeURIComponent(domain)+searchParam);
            console.log('📧 API Response:', j);
            if(!j.ok){ 
              console.error('❌ API returned error:', j.error);
              if(!silent) alert(j.error||'gagal'); 
              return; 
            }
            console.log('✅ Number of emails:', j.emails ? j.emails.length : 0);
            
            const refreshInfo = silent ? '<span class="muted" style="font-size:11px;margin-left:8px">\ud83d\udd04 Auto (30s)</span>' : '';
            
            // Bulk actions bar - shown when emails exist
            let bulkActionsHtml = '';
            if(j.emails && j.emails.length > 0){
              const selectedCount = SELECTED_EMAILS.length;
              bulkActionsHtml = '<div class="bulkActions">'+
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:0">'+
                  '<input type="checkbox" class="selectAllCheckbox" id="selectAllCheck" onclick="toggleSelectAll()" />'+
                  '<span class="muted" style="font-size:13px">Select All</span>'+
                '</label>'+
                (selectedCount > 0 ? 
                  '<button class="danger" onclick="deleteSelectedEmails()" style="margin-left:auto">'+
                    'Delete Selected ('+selectedCount+')'+
                  '</button>' : '')+
              '</div>';
            }
            
            let html = '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">'+
              '<b>Inbox</b>'+refreshInfo+
              '<button class="btn-ghost" onclick="loadEmails()">Refresh</button>'+
              '</div>'+
              '<div style="display:grid;grid-template-columns:1fr auto;gap:10px;margin-bottom:10px">'+
                '<input id="emailSearch" placeholder="Cari subject, pengirim, atau isi pesan..." value="'+esc(SEARCH_QUERY)+'" oninput="setSearchQuery(this.value)" onkeydown="if(event.key===&quot;Enter&quot;){event.preventDefault();setSearchQuery(this.value,true)}" />'+
                '<button class="btn-ghost" onclick="clearEmailSearch()">Clear</button>'+
              '</div>'+
              (SEARCH_QUERY ? '<div class="muted" style="font-size:12px;margin-bottom:10px">Hasil pencarian: <span class="kbd">'+esc(SEARCH_QUERY)+'</span></div>' : '')+
              bulkActionsHtml;
            
            if(!j.emails || j.emails.length===0){
              html += '<div class="muted" style="padding:24px;text-align:center;background:rgba(255,255,255,0.03);border-radius:8px;border:1px dashed rgba(148,163,184,0.3)">'+
                (SEARCH_QUERY ? 'Tidak ada email yang cocok.' : '📪 Belum ada email masuk.')+
              '</div>';
              console.log('⚠️ No emails to display');
            } else {
              for(const m of j.emails){
                const isSelected = SELECTED_EMAILS.includes(m.id);
                html += '<div class="mailItem'+(isSelected?' selected':'')+'" id="mail_'+m.id+'" onclick="openEmail(\\''+m.id+'\\')">'+
                  '<div style="display:flex;gap:12px;align-items:flex-start">'+
                    '<input type="checkbox" class="emailCheckbox" '+
                      'id="check_'+m.id+'" '+
                      (isSelected?'checked ':'')+
                      'onclick="event.stopPropagation();toggleEmailSelection(\\''+m.id+'\\')"/>'+
                    '<div style="flex:1;min-width:0">'+
                      '<div class="mailSubject">'+esc(m.subject||'(no subject)')+'</div>'+
                      '<div class="mailMeta">From: '+esc(m.from_addr||'')+'</div>'+
                      '<div class="mailMeta">'+esc(fmtDate(m.date || m.created_at || ""))+'</div>'+
                      (m.snippet ? '<div class="mailSnippet">'+esc(m.snippet)+'</div>' : '')+
                      '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">'+
                        '<button class="btn-primary" onclick="event.stopPropagation();openEmail(\\''+m.id+'\\')">View</button>'+
                        '<button onclick="event.stopPropagation();delEmail(\\''+m.id+'\\')" class="danger">Delete</button>'+
                      '</div>'+
                    '</div>'+
                  '</div>'+
                '</div>';
              }
            }
            
            console.log('📧 Setting innerHTML, HTML length:', html.length);
            box.innerHTML = html;
            console.log('✅ innerHTML SET! Inbox should be visible now.');
            console.log('📧 Final box styles:', {
              display: box.style.display,
              visibility: box.style.visibility,
              opacity: box.style.opacity
            });
          }catch(e){
            console.error('❌ Load emails error:', e);
            console.error('Error stack:', e.stack);
            if(!silent) console.error('Load emails error:', e);
          }
          console.log('📧 === loadEmails END ===');
        }

        function wrapEmailHtml(inner){
          // bikin email HTML kebaca jelas: background putih + text gelap
          return '<!doctype html><html><head><meta charset="utf-8">'+
            '<meta name="viewport" content="width=device-width,initial-scale=1">'+
            '<style>'+
              'html,body{margin:0;padding:0;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}' +
              'body{padding:16px;line-height:1.55;font-size:14px;}' +
              'img{max-width:100%;height:auto;}' +
              'table{max-width:100%;border-collapse:collapse;}' +
              'a{color:#2563eb;}' +
              'pre{white-space:pre-wrap;word-break:break-word;}' +
              'blockquote{margin:0;padding-left:12px;border-left:3px solid rgba(15,23,42,.2);color:rgba(15,23,42,.85)}' +
            '</style></head><body>'+ (inner || '') +'</body></html>';
        }

        function showEmailPanel(){
          const accountPanel = document.getElementById('accountPanel');
          const globalSearchPanel = document.getElementById('globalSearchPanel');
          const mailPanel = document.getElementById('mailPanel');
          const emailView = document.getElementById('emailView');
          if(accountPanel) accountPanel.style.display = 'none';
          if(globalSearchPanel) globalSearchPanel.style.display = 'none';
          if(mailPanel) mailPanel.style.display = 'none';
          if(emailView) emailView.style.display = 'block';
        }

        function showInboxPanel(){
          const accountPanel = document.getElementById('accountPanel');
          const globalSearchPanel = document.getElementById('globalSearchPanel');
          const mailPanel = document.getElementById('mailPanel');
          const emailView = document.getElementById('emailView');
          if(accountPanel) accountPanel.style.display = '';
          if(globalSearchPanel) globalSearchPanel.style.display = '';
          if(mailPanel) mailPanel.style.display = '';
          if(emailView){
            emailView.style.display = 'none';
            emailView.innerHTML = '';
          }
        }

        function renderAttachments(email, mount){
          const list = (email && email.attachments) || [];
          if(!list.length) return;

          const section = document.createElement('div');
          section.className = 'paper';
          section.style.marginTop = '12px';

          const title = document.createElement('div');
          title.style.fontWeight = '800';
          title.style.marginBottom = '10px';
          title.textContent = 'Lampiran';
          section.appendChild(title);

          for(const att of list){
            const row = document.createElement('div');
            row.style.marginTop = '10px';
            row.style.paddingTop = '10px';
            row.style.borderTop = '1px solid rgba(15,23,42,.12)';

            const meta = document.createElement('div');
            meta.style.fontSize = '13px';
            meta.style.marginBottom = '8px';
            meta.textContent = (att.filename || 'attachment') + ' (' + (att.mime_type || 'file') + ')';
            row.appendChild(meta);

            if(att.is_image && att.url){
              const img = document.createElement('img');
              img.src = att.url;
              img.alt = att.filename || 'attachment image';
              img.loading = 'lazy';
              img.style.maxWidth = '100%';
              img.style.height = 'auto';
              img.style.borderRadius = '12px';
              img.style.border = '1px solid rgba(15,23,42,.16)';
              row.appendChild(img);
            } else if(att.url) {
              const a = document.createElement('a');
              a.href = att.url;
              a.target = '_blank';
              a.rel = 'noreferrer';
              a.textContent = 'Buka lampiran';
              row.appendChild(a);
            }

            section.appendChild(row);
          }

          mount.appendChild(section);
        }

        async function openEmail(id){
          const j = await api('/api/emails/'+encodeURIComponent(id));
          if(!j.ok){ alert(j.error||'gagal'); return; }

          const v=document.getElementById('emailView');
          showEmailPanel();
          v.innerHTML =
            '<div class="viewerHead">'+
              '<div>'+
                '<div style="font-weight:900;font-size:16px">'+esc(j.email.subject||'(no subject)')+'</div>'+
                '<div class="muted" style="margin-top:6px">From: '+esc(j.email.from_addr||'')+'</div>'+
                '<div class="muted">To: '+esc(j.email.to_addr||'')+'</div>'+
                '<div class="muted">'+esc(fmtDate(j.email.date || j.email.created_at || ""))+'</div>'+
              '</div>'+
              '<button class="btn-ghost" onclick="showInboxPanel()">Kembali</button>'+
            '</div>'+
            '<hr class="hr" />'+
            '<div id="msgBody"></div>';

          const body = document.getElementById('msgBody');

          if (j.email.html) {
            const iframe = document.createElement('iframe');
            iframe.className = 'mailFrame';
            iframe.setAttribute('sandbox','allow-same-origin'); // no scripts
            iframe.setAttribute('referrerpolicy','no-referrer');
            iframe.srcdoc = wrapEmailHtml(j.email.html);
            body.appendChild(iframe);

            const note = document.createElement('div');
            note.className = 'muted';
            note.style.marginTop = '10px';
            note.textContent = 'HTML ditampilkan aman (sandbox).';
            body.appendChild(note);
          } else {
            const box = document.createElement('div');
            box.className = 'paper';
            const pre = document.createElement('pre');
            pre.className = 'mailText';
            pre.textContent = j.email.text || '';
            box.appendChild(pre);
            body.appendChild(box);
          }

          renderAttachments(j.email, body);

          v.scrollIntoView({behavior:'smooth'});
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const domain = document.getElementById('domainSelect').value;
          const msg=document.getElementById('aliasMsg');
          msg.textContent='...';
          try{
            const j = await api('/api/aliases', {
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({local, domain})
            });
            msg.textContent = j.ok ? 'Mail dibuat.' : (j.error||'gagal');
            if(j.ok){
              document.getElementById('alias').value='';
              await loadMe();
              await loadAliases();
            }
          }catch(e){
            msg.textContent = 'Gagal create: ' + (e && e.message ? e.message : String(e));
          }
        }

        async function delAlias(local, domain){
          const addr = local+'@'+domain;
          if(!confirm('Hapus mail '+addr+' ?')) return;
          const j = await api('/api/aliases/'+encodeURIComponent(local)+'?domain='+encodeURIComponent(domain), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          if(SELECTED===addr){
            SELECTED=null;
            stopAutoRefresh();
          }
          showInboxPanel();
          await loadMe();
          await loadAliases();
        }

        async function delEmail(id){
          if(!confirm('Hapus email ini?')) return;
          const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          // Remove from selection if it was selected
          const idx = SELECTED_EMAILS.indexOf(id);
          if(idx !== -1) SELECTED_EMAILS.splice(idx, 1);
          showInboxPanel();
          await loadEmails();
        }

        function toggleEmailSelection(id){
          const idx = SELECTED_EMAILS.indexOf(id);
          if(idx === -1){
            SELECTED_EMAILS.push(id);
          } else {
            SELECTED_EMAILS.splice(idx, 1);
          }
          loadEmails();
        }

        function toggleSelectAll(){
          // Get all visible email IDs from the current inbox
          const checkboxes = document.querySelectorAll('.emailCheckbox');
          if(checkboxes.length === 0) return;
          
          // Check if all are selected
          const allEmailIds = Array.from(checkboxes).map(cb => cb.id.replace('check_', ''));
          const allSelected = allEmailIds.every(id => SELECTED_EMAILS.includes(id));
          
          if(allSelected){
            // Deselect all
            SELECTED_EMAILS = SELECTED_EMAILS.filter(id => !allEmailIds.includes(id));
          } else {
            // Select all
            allEmailIds.forEach(id => {
              if(!SELECTED_EMAILS.includes(id)){
                SELECTED_EMAILS.push(id);
              }
            });
          }
          
          loadEmails();
        }

        async function deleteSelectedEmails(){
          if(SELECTED_EMAILS.length === 0){
            alert('Tidak ada email yang dipilih.');
            return;
          }
          
          const count = SELECTED_EMAILS.length;
          if(!confirm('Hapus '+count+' email yang dipilih?')) return;
          
          // Delete all selected emails
          let successCount = 0;
          let failCount = 0;
          
          for(const id of SELECTED_EMAILS){
            try{
              const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
              if(j.ok) successCount++;
              else failCount++;
            } catch(e){
              console.error('Failed to delete email:', id, e);
              failCount++;
            }
          }
          
          // Clear selection
          SELECTED_EMAILS = [];
          
          // Show result
          if(failCount > 0){
            alert('Berhasil hapus '+successCount+' email. Gagal: '+failCount);
          } else {
            alert('Berhasil hapus '+successCount+' email.');
          }
          
          // Refresh inbox
          showInboxPanel();
          await loadEmails();
        }

        function startAutoRefresh(){
          stopAutoRefresh();
          AUTO_REFRESH_INTERVAL = setInterval(()=>{
            loadEmails(true);
          }, 30000);
        }

        function stopAutoRefresh(){
          if(AUTO_REFRESH_INTERVAL){
            clearInterval(AUTO_REFRESH_INTERVAL);
            AUTO_REFRESH_INTERVAL = null;
          }
        }

        async function logout(){
          stopAutoRefresh();
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        // expose functions for inline handlers
        window.createAlias = createAlias;
        window.selectAlias = selectAlias;
        window.delAlias = delAlias;
        window.openEmail = openEmail;
        window.showInboxPanel = showInboxPanel;
        window.delEmail = delEmail;
        window.toggleEmailSelection = toggleEmailSelection;
        window.toggleSelectAll = toggleSelectAll;
        window.deleteSelectedEmails = deleteSelectedEmails;
        window.setSearchQuery = setSearchQuery;
        window.clearEmailSearch = clearEmailSearch;
        window.setGlobalSearchQuery = setGlobalSearchQuery;
        window.clearGlobalEmailSearch = clearGlobalEmailSearch;
        window.logout = logout;

        (async ()=>{
          try{
            await loadMe();
            await loadAliases();
          }catch(e){
            const msg = String(e && e.message ? e.message : e);
            const aliasesBox = document.getElementById('aliases');
            if(aliasesBox) aliasesBox.innerHTML = '<div class="muted">Gagal memuat halaman: '+esc(msg)+'</div>';
            console.error('App init error:', e);
          }
        })();
      </script>
      `
    );
  },

  admin(domains) {
    const domainsDisplay = domains.join(', ');

    return pageTemplate(
      "Admin Panel",
      `
      <style>
        .adminLayout{
          display:grid;
          grid-template-columns:280px 1fr;
          gap:0;
          min-height:calc(100vh - 40px);
          margin:-18px;
        }
        .adminSidebar{
          background:
            linear-gradient(180deg, rgba(255,255,255,.04), transparent 40%),
            var(--card);
          border-right:1px solid var(--border);
          padding:20px 0;
          position:sticky;
          top:0;
          height:100vh;
          overflow-y:auto;
        }
        .adminContent{
          padding:20px 24px;
          overflow-y:auto;
        }
        .sidebarBrand{
          padding:0 20px 20px;
          border-bottom:1px solid var(--border);
          margin-bottom:12px;
        }
        .sidebarBrandTitle{
          display:flex;
          align-items:center;
          gap:10px;
          font-weight:900;
          font-size:16px;
          margin-bottom:4px;
        }
        .sidebarBrandSub{
          color:var(--muted);
          font-size:12px;
        }
        .sidebarNav{
          padding:0 12px;
        }
        .sidebarItem{
          display:flex;
          align-items:center;
          gap:12px;
          padding:12px 12px;
          margin:4px 0;
          border-radius:12px;
          color:var(--text);
          text-decoration:none;
          cursor:pointer;
          transition:all .2s ease;
          border:1px solid transparent;
        }
        .sidebarItem:hover{
          background:rgba(59,130,246,.08);
          border-color:rgba(59,130,246,.2);
          text-decoration:none;
        }
        .sidebarItem.active{
          background:rgba(59,130,246,.15);
          border-color:rgba(59,130,246,.35);
          font-weight:600;
        }
        .sidebarIcon{
          font-size:18px;
          width:20px;
          text-align:center;
        }
        .sidebarLogout{
          margin-top:auto;
          padding:12px;
          border-top:1px solid var(--border);
        }
        .contentHeader{
          margin-bottom:20px;
        }
        .contentTitle{
          font-size:24px;
          font-weight:900;
          margin-bottom:6px;
        }
        .contentSubtitle{
          color:var(--muted);
          font-size:13px;
        }
        .userCard{
          background:
            linear-gradient(180deg, rgba(255,255,255,.04), transparent 50%),
            var(--card);
          border:1px solid var(--border);
          border-radius:16px;
          padding:18px;
          margin-bottom:12px;
          transition:all .2s ease;
        }
        .userCard:hover{
          border-color:rgba(96,165,250,.35);
          transform:translateY(-1px);
          box-shadow:0 4px 16px rgba(0,0,0,.3);
        }
        .userHeader{
          display:flex;
          justify-content:space-between;
          align-items:flex-start;
          gap:12px;
          flex-wrap:wrap;
          margin-bottom:12px;
        }
        .userInfo{
          flex:1;
          min-width:200px;
        }
        .userName{
          font-weight:700;
          font-size:15px;
          margin-bottom:4px;
        }
        .userEmail{
          color:var(--muted);
          font-size:13px;
        }
        .userBadges{
          display:flex;
          gap:6px;
          flex-wrap:wrap;
          margin-top:8px;
        }
        .userActions{
          display:grid;
          grid-template-columns:1fr 1fr;
          gap:10px;
          margin-top:12px;
        }
        .limitInput{
          display:flex;
          gap:8px;
          align-items:center;
          grid-column:1/-1;
        }
        .limitInput input{
          width:100px;
          padding:8px 10px;
        }
        @media (max-width: 860px){
          .adminLayout{
            grid-template-columns:1fr;
          }
          .adminSidebar{
            display:none;
          }
          .adminContent{
            padding:14px;
          }
          .userActions{
            grid-template-columns:1fr;
          }
        }
      </style>

      <div class="adminLayout">
        <!-- Sidebar -->
        <div class="adminSidebar">
          <div class="sidebarBrand">
            <div class="sidebarBrandTitle">
              ${LOGO_SVG}
              <span>Admin Panel</span>
            </div>
            <div class="sidebarBrandSub">Email Management</div>
          </div>
          
          <div class="sidebarNav">
            <a href="/app" class="sidebarItem">
              <span class="sidebarIcon">📥</span>
              <span>Inbox</span>
            </a>
            <div class="sidebarItem" id="navUsers" data-section="users" onclick="showSection('users')" role="button" tabindex="0">
              <span class="sidebarIcon">👥</span>
              <span>Users</span>
            </div>
            <div class="sidebarItem" id="navMessages" data-section="messages" onclick="showSection('messages')" role="button" tabindex="0">
              <span class="sidebarIcon">📨</span>
              <span>Pesan User</span>
            </div>
            <div class="sidebarItem" id="navDomains" data-section="domains" onclick="showSection('domains')" role="button" tabindex="0">
              <span class="sidebarIcon">@</span>
              <span>Domain Settings</span>
            </div>
          </div>

          <div class="sidebarLogout">
            <button class="danger" onclick="logout()" style="width:100%">
              <span style="margin-right:6px">🚪</span>
              Logout
            </button>
          </div>
        </div>

        <!-- Main Content -->
        <div class="adminContent">
          <!-- Users Section -->
          <div id="sectionUsers">
            <div class="contentHeader">
              <div class="contentTitle">User Management</div>
              <div class="contentSubtitle">
                <span class="muted">Domains: <span class="kbd">${domainsDisplay}</span></span>
              </div>
            </div>
            <div id="users"></div>
          </div>

          <!-- Messages Section -->
          <div id="sectionMessages" style="display:none">
            <div class="contentHeader">
              <div class="contentTitle">Pesan User</div>
              <div class="contentSubtitle">
                <span class="muted">Lihat dan baca pesan masuk dari semua user</span>
              </div>
            </div>
            
            <div style="margin-bottom:16px">
              <input id="searchUser" placeholder="Filter by user email..." style="max-width:400px" oninput="filterMessages(this.value)" />
            </div>
            
            <div id="messagesList"></div>
            <div id="emailViewer" style="display:none;margin-top:20px"></div>
          </div>

          <!-- Domains Section -->
          <div id="sectionDomains" style="display:none">
            <div class="contentHeader">
              <div class="contentTitle">Domain Settings</div>
              <div class="contentSubtitle">
                <span class="muted">Tambah domain yang sudah di-onboard dan diarahkan ke Worker di Cloudflare.</span>
              </div>
            </div>

            <div class="userCard">
              <div style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:end">
                <div>
                  <label>Domain baru</label>
                  <input id="newDomain" placeholder="contoh: domainbaru.com" onkeydown="if(event.key==='Enter'){event.preventDefault();addDomain()}" />
                </div>
                <button class="btn-primary" onclick="addDomain()">Tambah</button>
              </div>
              <div class="muted" style="margin-top:10px;font-size:12px">
                Setelah ditambah di sini, pastikan domain juga sudah aktif di Cloudflare Email Routing dengan catch-all ke Worker ini.
              </div>
              <div id="domainMsg" class="muted" style="margin-top:10px"></div>
            </div>

            <div id="domainsList"></div>
          </div>
        </div>
      </div>

      <script>
        const DEFAULT_DOMAIN = ${JSON.stringify(domains[0] || "")};
        let CURRENT_SECTION = 'users';
        let ALL_MESSAGES = [];
        let FILTERED_MESSAGES = [];
        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        function bindNavigation(){
          const items = document.querySelectorAll('.sidebarItem[data-section]');
          if(!items.length){
            console.warn('Navigation items not found');
            return;
          }
          items.forEach(el => {
            const section = el.getAttribute('data-section');
            el.addEventListener('click', () => {
              if(typeof showSection === 'function'){
                showSection(section);
              } else {
                console.error('showSection unavailable when clicking nav');
              }
            });
          });
        }

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          j.status = r.status;
          return j;
        }

        async function loadUsers(){
          const j = await api('/api/admin/users');
          if(!j.ok){
            alert(j.error||'gagal');
            if(j.error==='Forbidden') location.href='/app';
            return;
          }
          const box=document.getElementById('users');
          box.innerHTML='';
          
          for(const u of j.users){
            const card = document.createElement('div');
            card.className = 'userCard';
            card.innerHTML = 
              '<div class="userHeader">'+
                '<div class="userInfo">'+
                  '<div class="userName">'+esc(u.username)+'</div>'+
                  '<div class="userEmail">'+esc(u.email)+'</div>'+
                  '<div class="userBadges">'+
                    (u.role==='admin' ? '<span class="pill" style="background:rgba(59,130,246,.15);border-color:rgba(59,130,246,.4)">admin</span>' : '<span class="pill">user</span>')+
                    (u.disabled ? '<span class="pill" style="background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.4)">disabled</span>' : '')+
                    '<span class="pill">'+u.alias_count+' mail</span>'+
                  '</div>'+
                '</div>'+
              '</div>'+
              '<div class="userActions">'+
                '<div class="limitInput">'+
                  '<label style="font-size:12px;color:var(--muted);white-space:nowrap">Mail Limit:</label>'+
                  '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" type="number" />'+
                  '<button class="btn-primary" onclick="setLimit(\\''+esc(u.id)+'\\')">Update</button>'+
                '</div>'+
                '<button onclick="toggleAliases(\\''+esc(u.id)+'\\')" class="btn-ghost">📧 Lihat Mail</button>'+
                '<button onclick="toggleUser(\\''+esc(u.id)+'\\','+(u.disabled?0:1)+')" class="'+(u.disabled?'btn-primary':'danger')+'">'+(u.disabled?'✓ Enable':'✕ Disable')+'</button>'+
                '<button onclick="delUser(\\''+encodeURIComponent(u.id)+'\\')" class="danger">🗑 Delete</button>'+
              '</div>'+
              '<div id="aliases_'+esc(u.id)+'" style="display:none;margin-top:14px"></div>';
            box.appendChild(card);
          }
        }

        async function toggleAliases(userId){
          const aliasBox = document.getElementById('aliases_'+userId);
          if(!aliasBox) return;

          if(aliasBox.style.display !== 'none' && aliasBox.innerHTML !== ''){
            aliasBox.style.display = 'none';
            return;
          }

          aliasBox.innerHTML = '<div class="muted">Loading...</div>';
          aliasBox.style.display = 'block';

          const j = await api('/api/admin/users/'+encodeURIComponent(userId)+'/aliases');
          if(!j.ok){
            aliasBox.innerHTML = '<div class="muted">Error: '+esc(j.error||'gagal')+'</div>';
            return;
          }

          if(j.aliases.length === 0){
            aliasBox.innerHTML = '<div class="muted" style="padding:12px;background:rgba(255,255,255,.02);border-radius:12px;border:1px solid var(--border)">User ini belum membuat mail.</div>';
            return;
          }

          let html = '<div style="padding:14px;background:rgba(255,255,255,.02);border-radius:12px;border:1px solid var(--border)">';
          html += '<div class="muted" style="margin-bottom:12px;font-size:13px;font-weight:600">📧 Daftar Mail:</div>';
          for(const a of j.aliases){
            const aliasDomain = a.domain || DEFAULT_DOMAIN;
            html += '<div style="padding:10px 0;border-bottom:1px solid rgba(71,85,105,.2);display:flex;justify-content:space-between;align-items:center;gap:10px">'+
              '<div style="flex:1;min-width:0">'+
                '<div style="font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;font-weight:600">'+esc(a.local_part)+'@'+esc(aliasDomain)+'</div>'+
                '<div class="muted" style="font-size:11px;margin-top:2px">'+new Date(a.created_at*1000).toLocaleDateString('id-ID', {day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit'})+'</div>'+
              '</div>'+
              '<div>'+
                (a.disabled ? '<span class="pill" style="background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.4);font-size:11px">disabled</span>' : '<span class="pill" style="background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.4);font-size:11px">active</span>')+
              '</div>'+
            '</div>';
          }
          html += '</div>';
          aliasBox.innerHTML = html;
        }

        async function setLimit(id){
          const v = document.getElementById('lim_'+id).value;
          const lim = parseInt(v,10);
          if(isNaN(lim) || lim < 0){
            alert('Limit harus angka positif');
            return;
          }
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({alias_limit:lim})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          alert('Limit berhasil diupdate!');
          await loadUsers();
        }

        async function toggleUser(id, disabled){
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({disabled})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function delUser(encId){
          const id = decodeURIComponent(encId);
          if(!confirm('⚠️ Hapus user ini?\\n\\nID: '+id+'\\n\\nAksi ini akan menghapus:\\n• Sessions\\n• Reset tokens\\n• Mail aliases\\n• Emails (dan raw di R2 jika ada)\\n\\nAksi ini TIDAK BISA dibatalkan!')) return;

          const j = await api('/api/admin/users/'+encodeURIComponent(id), { method:'DELETE' });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          alert('User berhasil dihapus!');
          await loadUsers();
        }

        function showSection(section){
          console.log('showSection called with:', section);
          CURRENT_SECTION = section;
          
          const navUsers = document.getElementById('navUsers');
          const navMessages = document.getElementById('navMessages');
          const navDomains = document.getElementById('navDomains');
          const sectionUsers = document.getElementById('sectionUsers');
          const sectionMessages = document.getElementById('sectionMessages');
          const sectionDomains = document.getElementById('sectionDomains');
          
          if(!navUsers || !navMessages || !navDomains || !sectionUsers || !sectionMessages || !sectionDomains){
            console.error('Missing elements:', {navUsers, navMessages, navDomains, sectionUsers, sectionMessages, sectionDomains});
            return;
          }
          
          navUsers.classList.remove('active');
          navMessages.classList.remove('active');
          navDomains.classList.remove('active');
          sectionUsers.style.display = 'none';
          sectionMessages.style.display = 'none';
          sectionDomains.style.display = 'none';
          
          if(section === 'users'){
            navUsers.classList.add('active');
            sectionUsers.style.display = 'block';
          } else if(section === 'messages'){
            navMessages.classList.add('active');
            sectionMessages.style.display = 'block';
            loadAllMessages();
          } else if(section === 'domains'){
            navDomains.classList.add('active');
            sectionDomains.style.display = 'block';
            loadDomains();
          }
        }
        
        async function loadAllMessages(){
          const box = document.getElementById('messagesList');
          box.innerHTML = '<div class="muted">Loading...</div>';
          
          try{
            const j = await api('/api/admin/emails');
            if(!j.ok){
              box.innerHTML = '<div class="muted">Error: '+esc(j.error||'gagal')+'</div>';
              return;
            }
            
            ALL_MESSAGES = j.emails || [];
            FILTERED_MESSAGES = ALL_MESSAGES;
            renderMessages();
          } catch(e){
            box.innerHTML = '<div class="muted">Error loading messages</div>';
          }
        }
        
        function filterMessages(query){
          const q = query.toLowerCase().trim();
          if(!q){
            FILTERED_MESSAGES = ALL_MESSAGES;
          } else {
            FILTERED_MESSAGES = ALL_MESSAGES.filter(m => 
              (m.user_email||'').toLowerCase().includes(q) ||
              (m.username||'').toLowerCase().includes(q)
            );
          }
          renderMessages();
        }
        
        function renderMessages(){
          const box = document.getElementById('messagesList');
          if(!box){
            console.error('messagesList not found');
            return;
          }
          
          if(FILTERED_MESSAGES.length === 0){
            box.innerHTML = '<div class="muted">Tidak ada pesan.</div>';
            return;
          }
          
          let html = '';
          for(const m of FILTERED_MESSAGES){
            const userInfo = esc((m.username||'unknown')+' ('+m.user_email+')');
            const fromAddr = esc(m.from_addr||'');
            const subject = esc(m.subject||'(no subject)');
            const snippet = esc((m.snippet||'').substring(0,120));
            const date = new Date(m.created_at*1000).toLocaleDateString('id-ID', {day:'numeric', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit'});
            
            html += '<div class="userCard" style="cursor:pointer" data-msg-id="'+esc(m.id)+'">'+
              '<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">'+
                '<div style="flex:1;min-width:0">'+
                  '<div style="font-size:13px;color:var(--muted);margin-bottom:4px">👤 '+userInfo+'</div>'+
                  '<div style="font-weight:700;font-size:14px;margin-bottom:4px">'+subject+'</div>'+
                  '<div style="font-size:12px;color:var(--muted)">From: '+fromAddr+'</div>'+
                  '<div style="margin-top:6px;font-size:13px;color:var(--text);opacity:0.85">'+snippet+'...</div>'+
                '</div>'+
                '<div style="text-align:right">'+
                  '<div class="pill" style="font-size:11px">'+date+'</div>'+
                  '<button class="btn-ghost" style="margin-top:8px;padding:6px 10px" data-action="open" data-msg-id="'+esc(m.id)+'">Baca</button>'+
                '</div>'+
              '</div>'+
            '</div>';
          }
          
          box.innerHTML = html;

          // attach click handlers after render
          box.querySelectorAll('[data-action="open"]').forEach(btn => {
            btn.addEventListener('click', (e) => {
              e.stopPropagation();
              viewMessage(btn.getAttribute('data-msg-id'));
            });
          });
          box.querySelectorAll('.userCard[data-msg-id]').forEach(card => {
            card.addEventListener('click', () => {
              viewMessage(card.getAttribute('data-msg-id'));
            });
          });
        }
        
        function adminAttachmentHtml(email){
          const list = (email && email.attachments) || [];
          if(!list.length) return '';
          let html = '<div class="paper" style="margin-top:12px"><div style="font-weight:800;margin-bottom:10px">Lampiran</div>';
          for(const att of list){
            html += '<div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(15,23,42,.12)">'+
              '<div style="font-size:13px;margin-bottom:8px">'+esc(att.filename||'attachment')+' ('+esc(att.mime_type||'file')+')</div>'+
              (att.is_image && att.url
                ? '<img src="'+esc(att.url)+'" alt="'+esc(att.filename||'attachment image')+'" loading="lazy" style="max-width:100%;height:auto;border-radius:12px;border:1px solid rgba(15,23,42,.16)" />'
                : (att.url ? '<a href="'+esc(att.url)+'" target="_blank" rel="noreferrer">Buka lampiran</a>' : ''))+
            '</div>';
          }
          return html + '</div>';
        }

        function adminWrapEmailHtml(inner){
          return '<!doctype html><html><head><meta charset="utf-8">'+
            '<meta name="viewport" content="width=device-width,initial-scale=1">'+
            '<style>html,body{margin:0;padding:0;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}body{padding:16px;line-height:1.55;font-size:14px}img{max-width:100%;height:auto}table{max-width:100%;border-collapse:collapse}pre{white-space:pre-wrap;word-break:break-word}</style>'+
            '</head><body>'+(inner||'')+'</body></html>';
        }

        async function viewMessage(id){
          const viewer = document.getElementById('emailViewer');
          viewer.innerHTML = '<div class="muted">Loading...</div>';
          viewer.style.display = 'block';
          
          try{
            const j = await api('/api/admin/emails/'+encodeURIComponent(id));
            if(!j.ok){
              viewer.innerHTML = '<div class="muted">Error: '+esc(j.error||'gagal')+'</div>';
              return;
            }
            
            const e = j.email;
            const userInfo = esc((e.username||'unknown')+' ('+e.user_email+')');
            
            viewer.innerHTML = 
              '<div class="card">'+
                '<div style="display:flex;justify-content:space-between;margin-bottom:16px">'+
                  '<button onclick="closeMessageViewer()" class="btn-ghost">← Back</button>'+
                '</div>'+
                '<div class="paper" style="margin-bottom:12px">'+
                  '<div style="margin-bottom:8px"><b>User:</b> '+userInfo+'</div>'+
                  '<div style="margin-bottom:8px"><b>From:</b> '+esc(e.from_addr||'')+'</div>'+
                  '<div style="margin-bottom:8px"><b>To:</b> '+esc(e.to_addr||'')+'</div>'+
                  '<div style="margin-bottom:8px"><b>Subject:</b> '+esc(e.subject||'')+'</div>'+
                  '<div style="margin-bottom:8px"><b>Date:</b> '+esc(e.date||'')+'</div>'+
                '</div>'+
                (e.html ? '<iframe class="mailFrame" sandbox="allow-same-origin" referrerpolicy="no-referrer" srcdoc="'+esc(adminWrapEmailHtml(e.html))+'"></iframe>' : 
                         '<div class="paper"><pre class="mailText">'+esc(e.text||'')+'</pre></div>')+
                adminAttachmentHtml(e)+
              '</div>';
          } catch(e){
            viewer.innerHTML = '<div class="muted">Error loading email</div>';
          }
        }
        
        function closeMessageViewer(){
          document.getElementById('emailViewer').style.display = 'none';
        }

        async function loadDomains(){
          const box = document.getElementById('domainsList');
          if(!box) return;
          box.innerHTML = '<div class="muted">Loading...</div>';
          try{
            const j = await api('/api/admin/domains');
            if(!j.ok){
              box.innerHTML = '<div class="muted">Error: '+esc(j.error||'gagal')+'</div>';
              return;
            }
            renderDomains(j.domains || []);
          }catch(e){
            box.innerHTML = '<div class="muted">Error loading domains</div>';
          }
        }

        function renderDomains(domains){
          const box = document.getElementById('domainsList');
          if(!box) return;
          if(!domains.length){
            box.innerHTML = '<div class="userCard"><div class="muted">Belum ada domain aktif.</div></div>';
            return;
          }

          let html = '';
          for(const d of domains){
            html += '<div class="userCard">'+
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">'+
                '<div style="flex:1;min-width:220px">'+
                  '<div style="font-family:ui-monospace,monospace;font-weight:800;word-break:break-all">'+esc(d.domain)+'</div>'+
                  '<div class="muted" style="font-size:12px;margin-top:4px">source: '+esc(d.source||'admin')+'</div>'+
                '</div>'+
                '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
                  '<span class="pill">'+(d.can_delete ? 'dashboard' : 'env')+'</span>'+
                  (d.can_delete ? '<button class="danger" onclick="deleteDomain(\\''+encodeURIComponent(d.domain)+'\\')">Delete</button>' : '<span class="muted" style="font-size:12px">ubah lewat wrangler.toml</span>')+
                '</div>'+
              '</div>'+
            '</div>';
          }
          box.innerHTML = html;
        }

        async function addDomain(){
          const input = document.getElementById('newDomain');
          const msg = document.getElementById('domainMsg');
          const domain = (input && input.value ? input.value : '').trim().toLowerCase();
          if(msg) msg.textContent = '...';
          const j = await api('/api/admin/domains', {
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({domain})
          });
          if(!j.ok){
            if(msg) msg.textContent = j.error || 'gagal';
            return;
          }
          if(input) input.value = '';
          if(msg) msg.textContent = 'Domain ditambahkan.';
          await loadDomains();
        }

        async function deleteDomain(encDomain){
          const domain = decodeURIComponent(encDomain);
          if(!confirm('Hapus domain '+domain+' dari dashboard? Domain hanya bisa dihapus kalau belum dipakai alias.')) return;
          const j = await api('/api/admin/domains/'+encodeURIComponent(domain), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadDomains();
        }
        
        function showSettings(){
          console.log('showSettings called');
          alert('⚙️ Settings\\n\\nDomains: ${domainsDisplay}\\n\\n⚠️ Delete user akan menghapus semua data terkait (sessions, tokens, aliases, emails + raw di R2 jika ada).');
        }

        async function logout(){
          console.log('logout called');
          if(confirm('Logout dari admin panel?')){
            await fetch('/api/auth/logout',{method:'POST'});
            location.href='/login';
          }
        }

        // Expose functions for inline handlers - MUST BE BEFORE INIT
        window.showSection = showSection;
        window.showSettings = showSettings;
        window.logout = logout;
        window.setLimit = setLimit;
        window.toggleUser = toggleUser;
        window.delUser = delUser;
        window.toggleAliases = toggleAliases;
        window.loadAllMessages = loadAllMessages;
        window.loadDomains = loadDomains;
        window.addDomain = addDomain;
        window.deleteDomain = deleteDomain;
        window.filterMessages = filterMessages;
        window.viewMessage = viewMessage;
        window.closeMessageViewer = closeMessageViewer;

        // Initialize
        console.log('Admin panel initializing...');
        console.log('Functions available:', {
          showSection: typeof showSection,
          showSettings: typeof showSettings,
          logout: typeof logout
        });
        document.addEventListener('DOMContentLoaded', bindNavigation);
        bindNavigation();
        showSection('users');
        loadUsers().catch(e=>alert(String(e && e.message ? e.message : e)));
      </script>
      `
    );
  },
};

// -------------------- Auth/session helpers --------------------
async function getUserBySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const row = await env.DB.prepare(
    `SELECT s.user_id as user_id, u.id as id, u.username as username, u.email as email,
            u.role as role, u.alias_limit as alias_limit, u.disabled as disabled
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  )
    .bind(tokenHash, nowSec())
    .first();

  if (!row) return null;
  if (row.disabled) return null;
  return row;
}

async function createSession(env, userId, ttlSeconds) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const t = nowSec();

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(tokenHash, userId, t + ttlSeconds, t)
    .run();

  return token;
}

async function destroySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
}

async function cleanupExpired(env) {
  const t = nowSec();
  try {
    await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).bind(t).run();
  } catch { }
  try {
    await env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at <= ?`).bind(t).run();
  } catch { }
}

// NEW: delete user (cascade + R2 cleanup)
async function deleteUserCascade(env, userId, ctx) {
  // ambil raw_key dulu sebelum email dihapus
  let rawKeys = [];
  try {
    const r = await env.DB.prepare(
      `SELECT raw_key FROM emails WHERE user_id = ? AND raw_key IS NOT NULL`
    )
      .bind(userId)
      .all();
    rawKeys = (r.results || []).map((x) => x?.raw_key).filter(Boolean);
  } catch { }

  try {
    await ensureAttachmentsSchema(env);
    const r = await env.DB.prepare(
      `SELECT r2_key FROM email_attachments WHERE user_id = ? AND r2_key IS NOT NULL`
    )
      .bind(userId)
      .all();
    rawKeys.push(...(r.results || []).map((x) => x?.r2_key).filter(Boolean));
  } catch { }

  // hapus data turunan dulu
  await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
  await env.DB.prepare(`DELETE FROM reset_tokens WHERE user_id = ?`).bind(userId).run();
  try {
    await env.DB.prepare(`DELETE FROM email_attachments WHERE user_id = ?`).bind(userId).run();
  } catch { }
  await env.DB.prepare(`DELETE FROM emails WHERE user_id = ?`).bind(userId).run();
  await env.DB.prepare(`DELETE FROM aliases WHERE user_id = ?`).bind(userId).run();

  // hapus user
  await env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();

  // hapus raw eml dari R2 (kalau ada)
  if (env.MAIL_R2 && rawKeys.length) {
    for (let i = 0; i < rawKeys.length; i += 1000) {
      const chunk = rawKeys.slice(i, i + 1000);
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(env.MAIL_R2.delete(chunk));
      } else {
        // fallback sync (harusnya fetch selalu punya ctx)
        await env.MAIL_R2.delete(chunk);
      }
    }
  }
}

async function deleteEmailCascade(env, emailId, userId, ctx) {
  await ensureAttachmentsSchema(env);
  const row = await env.DB.prepare(`SELECT raw_key FROM emails WHERE id = ? AND user_id = ?`)
    .bind(emailId, userId)
    .first();

  if (!row) return false;

  const attachmentRows = await env.DB.prepare(
    `SELECT r2_key FROM email_attachments WHERE email_id = ? AND user_id = ? AND r2_key IS NOT NULL`
  )
    .bind(emailId, userId)
    .all();

  await env.DB.prepare(`DELETE FROM email_attachments WHERE email_id = ? AND user_id = ?`)
    .bind(emailId, userId)
    .run();
  await env.DB.prepare(`DELETE FROM emails WHERE id = ? AND user_id = ?`)
    .bind(emailId, userId)
    .run();

  const keys = (attachmentRows.results || []).map((x) => x?.r2_key).filter(Boolean);
  if (row.raw_key) keys.push(row.raw_key);
  if (keys.length && env.MAIL_R2) {
    ctx.waitUntil(env.MAIL_R2.delete(keys));
  }
  return true;
}

async function serveEmailAttachment(env, me, emailId, attachmentId) {
  await ensureAttachmentsSchema(env);
  const row = await env.DB.prepare(
    `SELECT a.filename, a.mime_type, a.size, a.r2_key, a.user_id
     FROM email_attachments a
     JOIN emails e ON e.id = a.email_id
     WHERE a.email_id = ? AND a.id = ?`
  )
    .bind(emailId, attachmentId)
    .first();

  if (!row) return notFound();
  if (me.role !== "admin" && row.user_id !== me.id) return forbidden("Forbidden");
  if (!env.MAIL_R2 || !row.r2_key) return notFound();

  const obj = await env.MAIL_R2.get(row.r2_key);
  if (!obj) return notFound();

  const headers = {
    "content-type": row.mime_type || "application/octet-stream",
    "cache-control": "private, max-age=3600",
    "x-content-type-options": "nosniff",
    "content-disposition": `inline; filename="${safeFileName(row.filename || "attachment")}"`,
  };
  const len = row.size || obj.size;
  if (len) headers["content-length"] = String(len);

  return new Response(obj.body, { headers });
}

async function storeEmailAttachments(env, emailId, userId, parsed, htmlValue, t) {
  const attachments = Array.isArray(parsed?.attachments) ? parsed.attachments : [];
  if (!attachments.length) return { html: htmlValue || "", count: 0 };

  await ensureAttachmentsSchema(env);

  const cidToUrl = new Map();
  const prepared = [];
  const inlineDbMax = safeInt(env.INLINE_ATTACHMENT_DB_BYTES, 65536);
  let rewrittenHtml = htmlValue || "";

  for (const att of attachments) {
    const bytes = attachmentBytes(att);
    if (!bytes.length) continue;

    const mime = attachmentMime(att);
    const contentId = cleanContentId(att.contentId || att.cid || att.contentID || "");
    const disposition = String(att.disposition || att.contentDisposition || "").toLowerCase();
    const inline = contentId || disposition === "inline" || att.related ? 1 : 0;

    if (!env.MAIL_R2 && contentId) {
      const dataUrl = dataUrlForAttachment(att, inlineDbMax);
      if (dataUrl) cidToUrl.set(contentId, dataUrl);
      continue;
    }

    if (!env.MAIL_R2) continue;

    const id = crypto.randomUUID();
    const filename = safeFileName(att.filename || att.name || (isDisplayableImage(mime) ? "image" : "attachment"));
    const r2Key = `emails/${emailId}/attachments/${id}-${filename}`;
    const url = `/api/email-attachments/${encodeURIComponent(emailId)}/${encodeURIComponent(id)}`;

    if (contentId) cidToUrl.set(contentId, url);
    prepared.push({ id, filename, mime, contentId, disposition, inline, size: bytes.byteLength, r2Key, bytes });
  }

  rewrittenHtml = replaceCidRefs(rewrittenHtml, cidToUrl);

  for (const item of prepared) {
    await env.MAIL_R2.put(item.r2Key, item.bytes, {
      httpMetadata: { contentType: item.mime },
    });
    await env.DB.prepare(
      `INSERT INTO email_attachments
       (id, email_id, user_id, filename, mime_type, content_id, disposition, inline, size, r2_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        item.id,
        emailId,
        userId,
        item.filename,
        item.mime,
        item.contentId || null,
        item.disposition || null,
        item.inline,
        item.size,
        item.r2Key,
        t
      )
      .run();
  }

  return { html: rewrittenHtml, count: prepared.length };
}

// -------------------- Reset email (Resend) --------------------
async function sendResetEmail(env, toEmail, token) {
  if (!env.RESEND_API_KEY) {
    console.log("reset email: RESEND_API_KEY not set -> skipping send");
    return;
  }

  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";

  const subject = "Reset password";
  const bodyHtml = `
    <div style="font-family:Arial,sans-serif">
      <h3 style="margin:0 0 10px">Reset Password</h3>
      <p>Gunakan token berikut untuk reset password:</p>
      <p style="font-size:16px"><b>${token}</b></p>
      ${link ? `<p>Atau klik link: <a href="${link}">${link}</a></p>` : ""}
      <p style="color:#64748b">Jika bukan kamu, abaikan email ini.</p>
    </div>
  `;

  const from = env.RESET_FROM || `N_MAZY <no-reply@${env.DOMAIN}>`;

  console.log("reset email: sending...", { toEmail, from });

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject,
      html: bodyHtml,
    }),
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.log("reset email: failed", r.status, txt.slice(0, 800));
    return;
  }

  const okTxt = await r.text().catch(() => "");
  console.log("reset email: sent ok", okTxt.slice(0, 300));
}

// -------------------- Worker entry --------------------
export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));

    const url = new URL(request.url);
    const path = url.pathname;
    const cookieSecure = url.protocol === "https:";

    // Pages
    if (request.method === "GET") {
      const domains = await getAllowedDomains(env);
      if (path === "/" || path === "/login") return html(PAGES.login());
      if (path === "/signup") return html(PAGES.signup());
      if (path === "/reset") return html(PAGES.reset());
      if (path === "/app") return html(PAGES.app(domains));
      if (path === "/admin") return html(PAGES.admin(domains));
    }

    // API
    if (path.startsWith("/api/")) {
      try {
        // Signup
        if (path === "/api/auth/signup" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const username = String(body.username || "").trim().toLowerCase();
          const email = String(body.email || "").trim().toLowerCase();
          const pw = String(body.pw || "");
          const pwConfirm = String(body.pwConfirm || "");

          if (!/^[a-z0-9_]{3,24}$/.test(username)) return badRequest("Username 3-24, a-z0-9_");
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return badRequest("Email tidak valid");
          if (pw.length < 8) return badRequest("Password minimal 8 karakter");
          if (!pwConfirm) return badRequest("Konfirmasi password wajib");
          if (pw !== pwConfirm) return badRequest("Konfirmasi password tidak cocok");

          const iters = pbkdf2Iters(env);
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(pw, salt, iters);

          const t = nowSec();
          const id = crypto.randomUUID();

          const c = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first();
          const count = Number(c?.c ?? 0);
          const role = count === 0 ? "admin" : "user";
          const aliasLimit = safeInt(env.DEFAULT_ALIAS_LIMIT, 3);

          try {
            const hasIters = await usersHasPassIters(env);
            if (hasIters) {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, iters, role, aliasLimit, t)
                .run();
            } else {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, role, aliasLimit, t)
                .run();
            }
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Username/email sudah dipakai");
            console.log("signup db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          // Auto-create initial alias with username@domain
          let domain = String(body.domain || "").trim().toLowerCase();
          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";
          const hasDomain = await aliasesHasDomain(env);

          if (!domain) domain = fallbackDomain;
          const selectedDomain = allowedDomains.includes(domain) ? domain : fallbackDomain;

          try {
            if (hasDomain) {
              await env.DB.prepare(
                `INSERT INTO aliases (local_part, domain, user_id, disabled, created_at)
                 VALUES (?, ?, ?, 0, ?)`
              )
                .bind(username, selectedDomain, id, t)
                .run();
            } else {
              await env.DB.prepare(
                `INSERT INTO aliases (local_part, user_id, disabled, created_at)
                 VALUES (?, ?, 0, ?)`
              )
                .bind(username, id, t)
                .run();
            }
          } catch (e) {
            console.log("auto-create alias error:", e);
            // Continue even if alias creation fails
          }

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, id, ttl);

          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }),
          });
        }

        // Login
        if (path === "/api/auth/login" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const id = String(body.id || "").trim().toLowerCase();
          const pw = String(body.pw || "");
          if (!id || !pw) return badRequest("Lengkapi data");

          const hasIters = await usersHasPassIters(env);

          const user = hasIters
            ? await env.DB.prepare(
              `SELECT id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
            )
              .bind(id, id)
              .first()
            : await env.DB.prepare(
              `SELECT id, username, email, pass_salt, pass_hash, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
            )
              .bind(id, id)
              .first();

          if (!user || user.disabled) return unauthorized("Login gagal");

          const saltBytes = base64UrlToBytes(user.pass_salt);
          const iters = hasIters ? safeInt(user.pass_iters, pbkdf2Iters(env)) : pbkdf2Iters(env);

          if (iters > PBKDF2_MAX_ITERS) {
            return unauthorized("Hash password lama tidak didukung. Silakan reset password.");
          }

          let hash;
          try {
            hash = await pbkdf2HashBase64Url(pw, saltBytes, iters);
          } catch (e) {
            if ((e?.name || "") === "NotSupportedError") {
              return unauthorized("Parameter hash tidak didukung. Silakan reset password.");
            }
            throw e;
          }

          if (hash !== user.pass_hash) return unauthorized("Login gagal");

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, user.id, ttl);

          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }),
          });
        }

        // Logout
        if (path === "/api/auth/logout" && request.method === "POST") {
          await destroySession(request, env);
          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", "", { maxAge: 0, secure: cookieSecure }),
          });
        }

        // Reset request
        if (path === "/api/auth/reset/request" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const email = String(body.email || "").trim().toLowerCase();
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return badRequest("Email tidak valid");

          const user = await env.DB.prepare(`SELECT id, disabled FROM users WHERE email = ?`)
            .bind(email)
            .first();

          // anti user-enumeration
          if (!user || user.disabled) return json({ ok: true });

          const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
          const token = base64Url(tokenBytes);
          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const t = nowSec();
          const ttl = safeInt(env.RESET_TTL_SECONDS, 3600);

          await env.DB.prepare(
            `INSERT INTO reset_tokens (token_hash, user_id, expires_at, created_at)
             VALUES (?, ?, ?, ?)`
          )
            .bind(tokenHash, user.id, t + ttl, t)
            .run();

          ctx.waitUntil(sendResetEmail(env, email, token));
          return json({ ok: true });
        }

        // Reset confirm
        if (path === "/api/auth/reset/confirm" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const token = String(body.token || "").trim();
          const newPw = String(body.newPw || "");

          if (!token) return badRequest("Token wajib");
          if (newPw.length < 8) return badRequest("Password minimal 8 karakter");

          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const rt = await env.DB.prepare(
            `SELECT user_id, expires_at FROM reset_tokens WHERE token_hash = ?`
          )
            .bind(tokenHash)
            .first();

          if (!rt || rt.expires_at <= nowSec()) return badRequest("Token invalid/expired");

          const iters = pbkdf2Iters(env);
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(newPw, salt, iters);

          const hasIters = await usersHasPassIters(env);
          if (hasIters) {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=?, pass_iters=? WHERE id=?`)
              .bind(pass_salt, pass_hash, iters, rt.user_id)
              .run();
          } else {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?`)
              .bind(pass_salt, pass_hash, rt.user_id)
              .run();
          }

          await env.DB.prepare(`DELETE FROM reset_tokens WHERE token_hash=?`).bind(tokenHash).run();
          return json({ ok: true });
        }

        // Auth required below
        const me = await getUserBySession(request, env);
        if (!me) return unauthorized();

        if (path.startsWith("/api/email-attachments/") && request.method === "GET") {
          const parts = path.slice("/api/email-attachments/".length).split("/");
          if (parts.length !== 2) return notFound();
          const emailId = decodeURIComponent(parts[0] || "");
          const attachmentId = decodeURIComponent(parts[1] || "");
          if (!emailId || !attachmentId) return notFound();
          return serveEmailAttachment(env, me, emailId, attachmentId);
        }

        if (path === "/api/me" && request.method === "GET") {
          return json({
            ok: true,
            user: {
              id: me.id,
              username: me.username,
              email: me.email,
              role: me.role,
              alias_limit: me.alias_limit,
            },
          });
        }

        // Mail (aliases)
        if (path === "/api/aliases" && request.method === "GET") {
          const hasDomain = await aliasesHasDomain(env);
          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";

          const rows = hasDomain
            ? await env.DB.prepare(
              `SELECT local_part, domain, disabled, created_at
               FROM aliases WHERE user_id = ? ORDER BY created_at DESC`
            )
              .bind(me.id)
              .all()
            : await env.DB.prepare(
              `SELECT local_part, ? as domain, disabled, created_at
               FROM aliases WHERE user_id = ? ORDER BY created_at DESC`
            )
              .bind(fallbackDomain, me.id)
              .all();

          return json({ ok: true, aliases: rows.results || [] });
        }

        if (path === "/api/aliases" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const local = String(body.local || "").trim().toLowerCase();
          let domain = String(body.domain || "").trim().toLowerCase();

          if (!validLocalPart(local)) return badRequest("Mail tidak valid (a-z0-9._+- max 64)");

          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";
          const hasDomain = await aliasesHasDomain(env);

          if (!fallbackDomain && !hasDomain) return badRequest("Domain belum dikonfigurasi");

          if (hasDomain) {
            if (!domain) domain = fallbackDomain;
            if (allowedDomains.length > 0) {
              if (!allowedDomains.includes(domain)) return badRequest("Domain tidak diizinkan");
            } else if (fallbackDomain) {
              if (domain !== fallbackDomain) return badRequest("Domain tidak diizinkan");
            } else {
              return badRequest("Domain belum dikonfigurasi");
            }
          } else {
            if (domain && domain !== fallbackDomain) return badRequest("Domain tidak diizinkan");
            domain = fallbackDomain;
          }

          const cnt = await env.DB.prepare(
            `SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND disabled = 0`
          )
            .bind(me.id)
            .first();

          if (Number(cnt?.c ?? 0) >= me.alias_limit) return forbidden("Limit mail tercapai");

          const t = nowSec();
          try {
            if (hasDomain) {
              await env.DB.prepare(
                `INSERT INTO aliases (local_part, domain, user_id, disabled, created_at)
                 VALUES (?, ?, ?, 0, ?)`
              )
                .bind(local, domain, me.id, t)
                .run();
            } else {
              await env.DB.prepare(
                `INSERT INTO aliases (local_part, user_id, disabled, created_at)
                 VALUES (?, ?, 0, ?)`
              )
                .bind(local, me.id, t)
                .run();
            }
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Mail sudah dipakai");
            console.log("alias db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          return json({ ok: true });
        }

        if (path.startsWith("/api/aliases/") && request.method === "DELETE") {
          const local = decodeURIComponent(path.slice("/api/aliases/".length)).toLowerCase();
          const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();

          if (!validLocalPart(local)) return badRequest("Mail invalid");

          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";
          const hasDomain = await aliasesHasDomain(env);

          if (hasDomain) {
            if (!domain) return badRequest("Domain required");

            const own = await env.DB.prepare(
              `SELECT local_part FROM aliases WHERE local_part = ? AND domain = ? AND user_id = ?`
            )
              .bind(local, domain, me.id)
              .first();

            if (!own) return notFound();

            await env.DB.prepare(`DELETE FROM aliases WHERE local_part = ? AND domain = ? AND user_id = ?`)
              .bind(local, domain, me.id)
              .run();
          } else {
            if (domain && fallbackDomain && domain !== fallbackDomain) return badRequest("Domain tidak diizinkan");

            const own = await env.DB.prepare(
              `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ?`
            )
              .bind(local, me.id)
              .first();

            if (!own) return notFound();

            await env.DB.prepare(`DELETE FROM aliases WHERE local_part = ? AND user_id = ?`)
              .bind(local, me.id)
              .run();
          }

          return json({ ok: true });
        }

        // Emails
        if (path === "/api/emails" && request.method === "GET") {
          const alias = (url.searchParams.get("alias") || "").trim().toLowerCase();
          let domainParam = (url.searchParams.get("domain") || "").trim().toLowerCase();
          const searchPattern = sqlLikePattern(url.searchParams.get("q") || "");
          const hasSearch = !!searchPattern;

          if (!alias || !validLocalPart(alias)) return badRequest("alias required");

          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";
          const aliasesDomain = await aliasesHasDomain(env);
          const emailsDomain = await emailsHasDomain(env);

          // Resolve ownership and canonical domain (if the aliases table has a domain column)
          let domain = domainParam;
          if (aliasesDomain) {
            if (domain) {
              const owned = await env.DB.prepare(
                `SELECT domain FROM aliases WHERE local_part = ? AND domain = ? AND user_id = ? AND disabled = 0`
              )
                .bind(alias, domain, me.id)
                .first();

              if (!owned) return forbidden("Mail bukan milikmu / disabled");
              domain = owned.domain;
            } else {
              const ownedRows = await env.DB.prepare(
                `SELECT domain FROM aliases WHERE local_part = ? AND user_id = ? AND disabled = 0`
              )
                .bind(alias, me.id)
                .all();

              const list = ownedRows.results || [];
              if (list.length === 0) return forbidden("Mail bukan milikmu / disabled");
              if (list.length > 1) return badRequest("domain required");
              domain = list[0].domain;
            }
          } else {
            const owned = await env.DB.prepare(
              `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ? AND disabled = 0`
            )
              .bind(alias, me.id)
              .first();

            if (!owned) return forbidden("Mail bukan milikmu / disabled");
          }

          // Pick domain for the emails query when the emails table supports it
          let domainForEmails = domain || fallbackDomain;
          const searchWhere = hasSearch
            ? ` AND (
                lower(COALESCE(from_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(to_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(subject,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(text,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(html,'')) LIKE ? ESCAPE '\\'
              )`
            : "";
          const searchBinds = hasSearch
            ? [searchPattern, searchPattern, searchPattern, searchPattern, searchPattern]
            : [];

          let rows;
          if (emailsDomain) {
            const primary = await env.DB.prepare(
              `SELECT id, from_addr, to_addr, subject, date, created_at,
                      substr(COALESCE(text,''), 1, 220) as snippet
               FROM emails
               WHERE user_id = ? AND local_part = ? AND domain = ?${searchWhere}
               ORDER BY created_at DESC
               LIMIT 50`
            )
              .bind(me.id, alias, domainForEmails, ...searchBinds)
              .all();

            // Fallback: if nothing found with domain filter (mismatch/legacy data), try without domain.
            // Skip this while searching so another domain with the same local part is not mixed in.
            if (!hasSearch && (!primary.results || primary.results.length === 0)) {
              const alt = await env.DB.prepare(
                `SELECT id, from_addr, to_addr, subject, date, created_at,
                        substr(COALESCE(text,''), 1, 220) as snippet
                 FROM emails
                 WHERE user_id = ? AND local_part = ?
                 ORDER BY created_at DESC
                 LIMIT 50`
              )
                .bind(me.id, alias)
                .all();

              rows = alt;
            } else {
              rows = primary;
            }
          } else {
            rows = await env.DB.prepare(
              `SELECT id, from_addr, to_addr, subject, date, created_at,
                      substr(COALESCE(text,''), 1, 220) as snippet
               FROM emails
               WHERE user_id = ? AND local_part = ?${searchWhere}
               ORDER BY created_at DESC
               LIMIT 50`
            )
              .bind(me.id, alias, ...searchBinds)
              .all();
          }

          return json({ ok: true, emails: rows.results || [] });
        }

        if (path === "/api/emails-search" && request.method === "GET") {
          const searchPattern = sqlLikePattern(url.searchParams.get("q") || "");
          if (!searchPattern) return json({ ok: true, emails: [] });

          const emailsDomain = await emailsHasDomain(env);
          const searchWhere = emailsDomain
            ? `(
                lower(COALESCE(e.from_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.to_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.subject,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.text,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.html,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.local_part,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.domain,'')) LIKE ? ESCAPE '\\'
              )`
            : `(
                lower(COALESCE(e.from_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.to_addr,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.subject,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.text,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.html,'')) LIKE ? ESCAPE '\\' OR
                lower(COALESCE(e.local_part,'')) LIKE ? ESCAPE '\\'
              )`;
          const searchBinds = emailsDomain
            ? [searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern]
            : [searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern];

          const rows = emailsDomain
            ? await env.DB.prepare(
              `SELECT e.id, e.local_part, e.domain, e.from_addr, e.to_addr, e.subject, e.date, e.created_at,
                      substr(COALESCE(e.text,''), 1, 220) as snippet
               FROM emails e
               WHERE e.user_id = ? AND ${searchWhere}
               ORDER BY e.created_at DESC
               LIMIT 50`
            )
              .bind(me.id, ...searchBinds)
              .all()
            : await env.DB.prepare(
              `SELECT e.id, e.local_part, '' as domain, e.from_addr, e.to_addr, e.subject, e.date, e.created_at,
                      substr(COALESCE(e.text,''), 1, 220) as snippet
               FROM emails e
               WHERE e.user_id = ? AND ${searchWhere}
               ORDER BY e.created_at DESC
               LIMIT 50`
            )
              .bind(me.id, ...searchBinds)
              .all();

          return json({ ok: true, emails: rows.results || [] });
        }
        if (path.startsWith("/api/emails/") && request.method === "GET") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const row = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, text, html, raw_key, created_at
             FROM emails WHERE id = ? AND user_id = ?`
          )
            .bind(id, me.id)
            .first();

          if (!row) return notFound();
          row.attachments = await getEmailAttachments(env, row.id, me.id);
          return json({ ok: true, email: row });
        }

        if (path.startsWith("/api/emails/") && request.method === "DELETE") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const deleted = await deleteEmailCascade(env, id, me.id, ctx);
          if (!deleted) return notFound();
          return json({ ok: true });
        }

        // Admin endpoints
        if (path === "/api/admin/domains" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");
          const domains = await getDomainSettings(env);
          return json({ ok: true, domains });
        }

        if (path === "/api/admin/domains" && request.method === "POST") {
          if (me.role !== "admin") return forbidden("Forbidden");
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const domain = String(body.domain || "").trim().toLowerCase();
          if (!validDomainName(domain)) return badRequest("Domain tidak valid");

          const allowedDomains = await getAllowedDomains(env);
          if (!allowedDomains.includes(domain)) {
            await ensureDomainsSchema(env);
            await env.DB.prepare(
              `INSERT OR IGNORE INTO allowed_domains (domain, created_at) VALUES (?, ?)`
            )
              .bind(domain, nowSec())
              .run();
          }

          return json({ ok: true, domains: await getDomainSettings(env) });
        }

        if (path.startsWith("/api/admin/domains/") && request.method === "DELETE") {
          if (me.role !== "admin") return forbidden("Forbidden");
          const domain = decodeURIComponent(path.slice("/api/admin/domains/".length)).trim().toLowerCase();
          if (!validDomainName(domain)) return badRequest("Domain tidak valid");
          if (envAllowedDomains(env).includes(domain)) {
            return badRequest("Domain dari wrangler.toml tidak bisa dihapus dari dashboard");
          }

          await ensureDomainsSchema(env);
          const existing = await env.DB.prepare(`SELECT domain FROM allowed_domains WHERE domain = ?`)
            .bind(domain)
            .first();
          if (!existing) return notFound();

          const aliasesDomain = await aliasesHasDomain(env);
          if (aliasesDomain) {
            const used = await env.DB.prepare(`SELECT COUNT(*) as c FROM aliases WHERE domain = ?`)
              .bind(domain)
              .first();
            if (Number(used?.c || 0) > 0) {
              return badRequest("Domain masih dipakai oleh alias. Hapus aliasnya dulu.");
            }
          }

          await env.DB.prepare(`DELETE FROM allowed_domains WHERE domain = ?`).bind(domain).run();
          return json({ ok: true, domains: await getDomainSettings(env) });
        }

        if (path === "/api/admin/users" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const rows = await env.DB.prepare(
            `SELECT u.id, u.username, u.email, u.role, u.alias_limit, u.disabled, u.created_at,
                    COUNT(a.local_part) as alias_count
             FROM users u
             LEFT JOIN aliases a ON a.user_id = u.id
             GROUP BY u.id
             ORDER BY u.created_at DESC LIMIT 200`
          ).all();

          const users = (rows.results || []).map((u) => ({
            ...u,
            created_at: new Date(u.created_at * 1000).toISOString(),
            alias_count: Number(u.alias_count || 0),
          }));

          return json({ ok: true, users });
        }

        // NEW: Admin - Get all emails from all users
        if (path === "/api/admin/emails" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const rows = await env.DB.prepare(
            `SELECT e.id, e.from_addr, e.to_addr, e.subject, e.date, e.created_at,
                    substr(COALESCE(e.text,''), 1, 180) as snippet,
                    u.username, u.email as user_email
             FROM emails e
             JOIN users u ON u.id = e.user_id
             ORDER BY e.created_at DESC
             LIMIT 200`
          ).all();

          return json({ ok: true, emails: rows.results || [] });
        }

        // NEW: Admin - Get specific email with full content
        if (path.startsWith("/api/admin/emails/") && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const id = decodeURIComponent(path.slice("/api/admin/emails/".length));
          const row = await env.DB.prepare(
            `SELECT e.id, e.from_addr, e.to_addr, e.subject, e.date, e.text, e.html, e.raw_key, e.created_at,
                    u.username, u.email as user_email
             FROM emails e
             JOIN users u ON u.id = e.user_id
             WHERE e.id = ?`
          )
            .bind(id)
            .first();

          if (!row) return notFound();
          row.attachments = await getEmailAttachments(env, row.id);
          return json({ ok: true, email: row });
        }

        if (path.startsWith("/api/admin/users/") && path.endsWith("/aliases") && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const userId = decodeURIComponent(path.slice("/api/admin/users/".length, path.length - "/aliases".length));
          const hasDomain = await aliasesHasDomain(env);
          const allowedDomains = await getAllowedDomains(env);
          const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";

          const rows = hasDomain
            ? await env.DB.prepare(
              `SELECT local_part, domain, disabled, created_at
               FROM aliases
               WHERE user_id = ?
               ORDER BY created_at DESC`
            )
              .bind(userId)
              .all()
            : await env.DB.prepare(
              `SELECT local_part, disabled, created_at
               FROM aliases
               WHERE user_id = ?
               ORDER BY created_at DESC`
            )
              .bind(userId)
              .all();

          const aliases = (rows.results || []).map((a) => ({
            ...a,
            domain: a.domain || fallbackDomain,
            created_at: new Date(a.created_at * 1000).toISOString(),
          }));

          return json({ ok: true, aliases });
        }

        if (path.startsWith("/api/admin/users/") && request.method === "PATCH") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const userId = decodeURIComponent(path.slice("/api/admin/users/".length));
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const alias_limit =
            body.alias_limit !== undefined ? safeInt(body.alias_limit, NaN) : undefined;
          const disabled = body.disabled !== undefined ? safeInt(body.disabled, NaN) : undefined;

          if (
            alias_limit !== undefined &&
            (!Number.isFinite(alias_limit) || alias_limit < 0 || alias_limit > 1000)
          ) {
            return badRequest("alias_limit invalid");
          }
          if (disabled !== undefined && !(disabled === 0 || disabled === 1)) {
            return badRequest("disabled invalid");
          }

          const sets = [];
          const binds = [];
          if (alias_limit !== undefined) {
            sets.push("alias_limit = ?");
            binds.push(alias_limit);
          }
          if (disabled !== undefined) {
            sets.push("disabled = ?");
            binds.push(disabled);
          }
          if (sets.length === 0) return badRequest("No fields");

          binds.push(userId);
          await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`)
            .bind(...binds)
            .run();
          return json({ ok: true });
        }

        // NEW: delete user (admin)
        if (path.startsWith("/api/admin/users/") && request.method === "DELETE") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const userId = decodeURIComponent(path.slice("/api/admin/users/".length));

          // jangan hapus diri sendiri biar gak ngunci admin
          if (userId === me.id) return badRequest("Tidak bisa menghapus akun sendiri");

          const u = await env.DB.prepare(`SELECT id, role FROM users WHERE id = ?`).bind(userId).first();
          if (!u) return notFound();

          // safety: jangan hapus admin terakhir
          if (u.role === "admin") {
            const c = await env.DB.prepare(`SELECT COUNT(*) as c FROM users WHERE role = 'admin'`).first();
            const adminCount = Number(c?.c ?? 0);
            if (adminCount <= 1) return badRequest("Tidak bisa menghapus admin terakhir");
          }

          await deleteUserCascade(env, userId, ctx);
          return json({ ok: true });
        }

        return notFound();
      } catch (e) {
        console.log("API ERROR:", e && e.stack ? e.stack : e);
        return json({ ok: false, error: "Server error" }, 500);
      }
    }

    return notFound();
  },

  async email(message, env, ctx) {
    try {
      const allowedDomains = await getAllowedDomains(env);
      const hasAliasDomain = await aliasesHasDomain(env);
      const hasEmailDomain = await emailsHasDomain(env);
      const fallbackDomain = allowedDomains[0] || env.DOMAIN || "";
      const to = String(message.to || "").toLowerCase();
      const [local, toDomain] = to.split("@");

      if (!local || !toDomain || !allowedDomains.includes(toDomain)) {
        message.setReject("Bad recipient");
        return;
      }

      if (!hasAliasDomain && fallbackDomain && toDomain !== fallbackDomain) {
        message.setReject("Bad recipient");
        return;
      }

      const row = hasAliasDomain
        ? await env.DB.prepare(
          `SELECT a.local_part as local_part, a.domain as domain, a.user_id as user_id, a.disabled as alias_disabled,
                  u.disabled as user_disabled
           FROM aliases a
           JOIN users u ON u.id = a.user_id
           WHERE a.local_part = ? AND a.domain = ?`
        )
          .bind(local, toDomain)
          .first()
        : await env.DB.prepare(
          `SELECT a.local_part as local_part, a.user_id as user_id, a.disabled as alias_disabled,
                  u.disabled as user_disabled
           FROM aliases a
           JOIN users u ON u.id = a.user_id
           WHERE a.local_part = ?`
        )
          .bind(local)
          .first();

      if (!row || row.alias_disabled || row.user_disabled) {
        message.setReject("Unknown recipient");
        return;
      }

      const maxStore = safeInt(env.MAX_STORE_BYTES, 10485760);
      if (message.rawSize && message.rawSize > maxStore) {
        message.setReject("Message too large");
        return;
      }

      const ab = await new Response(message.raw).arrayBuffer();

      const parser = new PostalMime();
      const parsed = await parser.parse(ab);

      const id = crypto.randomUUID();
      const t = nowSec();

      const subject = parsed.subject || "";
      const date = parsed.date ? new Date(parsed.date).toISOString() : "";
      const fromAddr =
        parsed.from && parsed.from.address ? parsed.from.address : message.from || "";
      const toAddr = message.to || "";

      const maxTextChars = safeInt(env.MAX_TEXT_CHARS, 200000);
      const text = (parsed.text || "").slice(0, maxTextChars);
      let htmlPart = (parsed.html || "").slice(0, maxTextChars);

      let raw_key = null;
      if (env.MAIL_R2 && envFlag(env.STORE_RAW_EMAILS, false)) {
        raw_key = `emails/${id}.eml`;
        ctx.waitUntil(
          env.MAIL_R2.put(raw_key, ab, { httpMetadata: { contentType: "message/rfc822" } })
        );
      }

      if (hasEmailDomain) {
        const storeDomain = row.domain || toDomain || fallbackDomain;
        await env.DB.prepare(
          `INSERT INTO emails
           (id, local_part, domain, user_id, from_addr, to_addr, subject, date, text, html, raw_key, size, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            row.local_part,
            storeDomain,
            row.user_id,
            fromAddr,
            toAddr,
            subject,
            date,
            text,
            htmlPart,
            raw_key,
            ab.byteLength || message.rawSize || 0,
            t
          )
          .run();
      } else {
        await env.DB.prepare(
          `INSERT INTO emails
           (id, local_part, user_id, from_addr, to_addr, subject, date, text, html, raw_key, size, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            row.local_part,
            row.user_id,
            fromAddr,
            toAddr,
            subject,
            date,
            text,
            htmlPart,
            raw_key,
            ab.byteLength || message.rawSize || 0,
            t
          )
          .run();
      }

      const storedAttachments = await storeEmailAttachments(env, id, row.user_id, parsed, htmlPart, t);
      if (storedAttachments.html !== htmlPart) {
        htmlPart = storedAttachments.html;
        await env.DB.prepare(`UPDATE emails SET html = ? WHERE id = ?`)
          .bind(htmlPart, id)
          .run();
      }
    } catch (e) {
      console.log("email handler error:", e && e.stack ? e.stack : e);
      message.setReject("Temporary processing error");
    }
  },
};
