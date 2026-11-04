// Edge Function "api" ของระบบพนักงาน (Supabase project แยกจากแอปเช็คสต็อก)
// ตอนนี้มีปฏิทินตารางงาน (หลายสาขา, หัวข้อเพิ่มเองได้) และคำแปลกลาง 6 ภาษา
// ระบบตอกบัตรจะเพิ่มเป็น action ใหม่ในไฟล์นี้ และใช้ staff / translations ร่วมกัน
//
// Deploy: Supabase Dashboard -> Edge Functions -> create function named "api" ->
// paste this file's contents -> Deploy.
//
// Secrets (Dashboard -> Edge Functions -> Secrets):
//   SCHEDULE_SHEET_ID            id ของชีท "ระบบคิดเงินเดือนพนักงาน"
//   GOOGLE_SERVICE_ACCOUNT_JSON  key ของ Google service account (ทั้งไฟล์ JSON)
//                                ต้องแชร์ชีทให้อีเมล client_email ในไฟล์นี้เป็น Editor
//   GEMINI_API_KEY               key ของ Gemini สำหรับแปลภาษา (ใช้ตัวเดียวกับแอปเช็คสต็อกได้)
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are auto-injected by the platform.
//
// Every request is a POST with a JSON body: { action: "...", ...params }.
// Every response is JSON with at least an `ok` boolean.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, authorization, apikey",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// ============================================================
// Small helpers
// ============================================================

async function logAdmin(action: string, details: Record<string, unknown> = {}) {
  await supabase.from("admin_log").insert({ action, details });
}

async function getSetting<T>(key: string, fallback: T): Promise<T> {
  const { data } = await supabase.from("app_settings").select("value").eq("key", key).maybeSingle();
  return (data?.value as T) ?? fallback;
}

async function setSetting(key: string, value: unknown) {
  await supabase.from("app_settings").upsert({ key, value, updated_at: new Date().toISOString() });
}

async function checkPassword(hash: string | null, plain: string): Promise<boolean> {
  if (!hash) return false;
  const { data, error } = await supabase.rpc("crypt_check", { plain, hash });
  if (error) { console.error("crypt_check error", error); return false; }
  return !!data;
}

async function hashPassword(plain: string): Promise<string> {
  const { data, error } = await supabase.rpc("crypt_hash", { plain });
  if (error) throw error;
  return data as string;
}

const ADMIN_PIN_KEY = "admin_pin_hash";

async function checkAdminPin(pin: string): Promise<boolean> {
  if (!pin) return false;
  return checkPassword(await getSetting<string | null>(ADMIN_PIN_KEY, null), pin);
}

function bangkokToday(): string {
  return new Date(Date.now() + 7 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function isIsoDate(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
}

function sheetBool(v: unknown): boolean {
  const s = String(v ?? "").trim().toUpperCase();
  return s === "TRUE" || s === "1";
}

// Sheet dates show up as "2026-11-05" or D/M/YYYY ("5/11/2026"); returns ISO or null.
function parseSheetDate(s: string): string | null {
  const t = s.trim();
  const dmy = /^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:\s|$)/.exec(t);
  if (dmy) return `${dmy[3]}-${dmy[2].padStart(2, "0")}-${dmy[1].padStart(2, "0")}`;
  const iso = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:\s|$)/.exec(t);
  if (iso) return `${iso[1]}-${iso[2].padStart(2, "0")}-${iso[3].padStart(2, "0")}`;
  return null;
}

// ============================================================
// Google Sheets (REST + service-account JWT; the edge runtime has no googleapis SDK)
// ============================================================

async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs = 20000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw new Error(`request_timed_out_after_${timeoutMs}ms: ${url.split("?")[0]}`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function base64url(bytes: Uint8Array | string): string {
  const arr = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let cachedGoogleToken: { token: string; exp: number } | null = null;

async function getGoogleAccessToken(): Promise<string> {
  if (cachedGoogleToken && cachedGoogleToken.exp > Date.now() / 1000 + 60) return cachedGoogleToken.token;
  const raw = Deno.env.get("GOOGLE_SERVICE_ACCOUNT_JSON");
  if (!raw) throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON not configured");
  const sa = JSON.parse(raw);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const signInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const pemBody = String(sa.private_key)
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8", der.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signInput));
  const jwt = `${signInput}.${base64url(new Uint8Array(sig))}`;

  const res = await fetchWithTimeout("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error_description || data?.error || `google_token_http_${res.status}`);
  cachedGoogleToken = { token: data.access_token, exp: now + (data.expires_in ?? 3600) };
  return data.access_token as string;
}

function scheduleSheetId(): string | null {
  return Deno.env.get("SCHEDULE_SHEET_ID") || null;
}

async function sheetsGetValues(spreadsheetId: string, range: string): Promise<string[][]> {
  const token = await getGoogleAccessToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(range)}`;
  const res = await fetchWithTimeout(url, { headers: { Authorization: `Bearer ${token}` } }, 30000);
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `sheets_get_http_${res.status}`);
  return data.values ?? [];
}

async function sheetsSetRow(spreadsheetId: string, range: string, row: unknown[]): Promise<void> {
  const token = await getGoogleAccessToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(range)}?valueInputOption=RAW`;
  const res = await fetchWithTimeout(url, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ values: [row] }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data?.error?.message || `sheets_set_http_${res.status}`);
  }
}

async function sheetsAppendRow(spreadsheetId: string, range: string, row: unknown[]): Promise<void> {
  const token = await getGoogleAccessToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${encodeURIComponent(range)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
  const res = await fetchWithTimeout(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ values: [row] }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data?.error?.message || `sheets_append_http_${res.status}`);
  }
}

// ============================================================
// Translations (shared by every app in this project: calendar now, time clock later)
// One row per text, one column per language. Pages load one language at a time.
// `edited` lists languages a person corrected by hand; AI never overwrites those.
// ============================================================

const LANGS = ["en", "my", "lo", "km", "vi"] as const;
const ALL_LANGS = ["th", ...LANGS] as const;
type Lang = typeof ALL_LANGS[number];
const LANG_NAMES: Record<string, string> = {
  en: "English", my: "Burmese (Myanmar language)", lo: "Lao", km: "Khmer", vi: "Vietnamese",
};
type TranslationRow = { key: string; th: string; en: string; my: string; lo: string; km: string; vi: string; edited: string[] };

function cleanLang(v: unknown): Lang {
  const s = String(v ?? "th");
  return (ALL_LANGS as readonly string[]).includes(s) ? s as Lang : "th";
}

async function getTranslations(keys?: string[], prefix?: string): Promise<TranslationRow[]> {
  let q = supabase.from("translations").select("key, th, en, my, lo, km, vi, edited");
  if (keys) q = q.in("key", keys);
  if (prefix) q = q.like("key", `${prefix}%`);
  const { data, error } = await q;
  if (error) throw new Error(error.message);
  return (data ?? []) as TranslationRow[];
}

// key -> text in `lang`, falling back to Thai when that language is still empty.
function dictFor(rows: TranslationRow[], lang: Lang): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) out[r.key] = (r[lang] || r.th || "").toString();
  return out;
}

const GEMINI_MODEL = "gemini-2.5-flash";

async function callGeminiJson(prompt: string): Promise<unknown> {
  const apiKey = Deno.env.get("GEMINI_API_KEY");
  if (!apiKey) throw new Error("GEMINI_API_KEY not configured");
  // Key in the header, never the URL, so it can't leak into an error message.
  const res = await fetchWithTimeout(
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: "application/json" } }),
    },
    90000,
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `gemini_http_${res.status}`);
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error("gemini_empty_response");
  return JSON.parse(text);
}

// Thai texts -> { key: { en, my, lo, km, vi } }. One AI call per 40 texts.
async function aiTranslate(texts: Record<string, string>): Promise<Record<string, Record<string, string>>> {
  const entries = Object.entries(texts).filter(([, th]) => th.trim());
  const out: Record<string, Record<string, string>> = {};
  for (let i = 0; i < entries.length; i += 40) {
    const chunk = Object.fromEntries(entries.slice(i, i + 40));
    const prompt = `You translate short messages for staff of a Thai restaurant (calendar, duty roster, time clock).
Translate every Thai value in this JSON into: ${LANGS.map((l) => `"${l}" = ${LANG_NAMES[l]}`).join(", ")}.
Keep placeholders like {name} exactly as they are. Keep it short, simple and friendly, the way a manager talks to staff.
Return ONLY a JSON object of the same keys, each value an object {"en":"...","my":"...","lo":"...","km":"...","vi":"..."}.

${JSON.stringify(chunk)}`;
    const result = await callGeminiJson(prompt) as Record<string, Record<string, unknown>>;
    for (const key of Object.keys(chunk)) {
      const r = result?.[key] ?? {};
      out[key] = Object.fromEntries(LANGS.map((l) => [l, String(r[l] ?? "").trim()]));
    }
  }
  return out;
}

// Admin: AI suggestions only, nothing saved. The page shows them in editable boxes first.
// texts: { key: thai }
async function handleAiTranslate(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const texts = (p.texts && typeof p.texts === "object") ? p.texts as Record<string, unknown> : {};
  const clean = Object.fromEntries(Object.entries(texts).map(([k, v]) => [k, String(v ?? "")]));
  if (Object.keys(clean).length > 200) return json({ ok: false, error: "too_many_texts" });
  try {
    return json({ ok: true, translations: await aiTranslate(clean) });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: list rows to review/edit (e.g. prefix "ui.cal.").
async function handleListTranslations(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  try {
    const rows = await getTranslations(undefined, String(p.prefix ?? ""));
    rows.sort((a, b) => a.key.localeCompare(b.key));
    return json({ ok: true, rows });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: save rows as typed. rows: [{ key, th?, en?, ..., edited?: [langs] }]
// Only the languages sent are changed; `edited` is merged in.
async function saveTranslationRows(rows: Array<Record<string, unknown>>) {
  const keys = rows.map((r) => String(r.key ?? "")).filter(Boolean);
  const existing = new Map((await getTranslations(keys)).map((r) => [r.key, r]));
  const upserts = rows.filter((r) => r.key).map((r) => {
    const key = String(r.key);
    const prev = existing.get(key);
    const row: Record<string, unknown> = { key, updated_at: new Date().toISOString() };
    for (const l of ALL_LANGS) if (r[l] !== undefined) row[l] = String(r[l] ?? "");
    for (const l of ALL_LANGS) if (row[l] === undefined) row[l] = prev?.[l] ?? "";
    const edited = new Set([...(prev?.edited ?? []), ...((r.edited as string[]) ?? [])]);
    for (const l of ((r.unedited as string[]) ?? [])) edited.delete(l);
    row.edited = [...edited].filter((l) => (LANGS as readonly string[]).includes(l));
    return row;
  });
  if (upserts.length) {
    const { error } = await supabase.from("translations").upsert(upserts);
    if (error) throw new Error(error.message);
  }
}

async function handleSaveTranslations(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  try {
    const rows = Array.isArray(p.rows) ? p.rows as Array<Record<string, unknown>> : [];
    await saveTranslationRows(rows);
    await logAdmin("save_translations", { keys: rows.map((r) => r.key) });
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// Admin: make sure every page text exists (Thai from the page), then fill the other languages
// with AI — skipping languages edited by hand, and (unless `all`) ones that already have text.
// texts: { key: thai } as written in the page source. include_topics: also every topic text.
async function handleTranslatePage(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const texts: Record<string, unknown> = { ...((p.texts && typeof p.texts === "object") ? p.texts as Record<string, unknown> : {}) };
  const all = !!p.all;
  try {
    // include_topics: also the texts of every calendar topic (Thai taken from what's saved)
    if (p.include_topics) {
      for (const r of await getTranslations(undefined, "topic.")) if (r.th.trim()) texts[r.key] = r.th;
    }
    const keys = Object.keys(texts);
    if (keys.length > 300) return json({ ok: false, error: "too_many_texts" });
    const existing = new Map((await getTranslations(keys)).map((r) => [r.key, r]));
    const todo: Record<string, string> = {};
    for (const key of keys) {
      const th = String(texts[key] ?? "");
      const prev = existing.get(key);
      const thChanged = !prev || prev.th !== th;
      const missing = LANGS.some((l) => !prev?.[l] && !(prev?.edited ?? []).includes(l));
      if (all || thChanged || missing) todo[key] = th;
    }
    const ai = await aiTranslate(todo);
    const rows = Object.entries(todo).map(([key, th]) => {
      const prev = existing.get(key);
      const thChanged = !prev || prev.th !== th;
      const row: Record<string, unknown> = { key, th };
      for (const l of LANGS) {
        const keep = (prev?.edited ?? []).includes(l) && !thChanged;
        if (!keep && ai[key]?.[l]) row[l] = ai[key][l];
      }
      // Thai source changed: earlier hand edits no longer match, so they're re-translated.
      if (thChanged) row.unedited = [...LANGS];
      return row;
    });
    await saveTranslationRows(rows);
    await logAdmin("translate_page", { count: rows.length, all });
    return json({ ok: true, translated: rows.length });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// ============================================================
// Branches, staff and admin PINs
// The central admin PIN (app_settings.admin_pin_hash) can do everything. A branch may also have
// its own PIN, which can only save that branch's calendar days.
// ============================================================

type Branch = { id: string; name: string; sort: number; admin_pin_hash: string | null; sync_sheet: boolean };

async function getBranch(id: string): Promise<Branch | null> {
  if (!id) return null;
  const { data } = await supabase.from("branches").select("*").eq("id", id).maybeSingle();
  return (data as Branch) ?? null;
}

async function canEditBranch(branch: Branch, pin: string): Promise<boolean> {
  if (await checkAdminPin(pin)) return true;
  return !!pin && checkPassword(branch.admin_pin_hash, pin);
}

function cleanId(s: string): string {
  return s.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

// Public, one request when a page opens: branches + staff, calendar topics, and every text in
// `lang` (page texts with `prefix`, default "ui.cal.", plus topic texts).
async function handleBootstrap(p: Record<string, unknown>) {
  const lang = cleanLang(p.lang);
  const prefix = String(p.prefix ?? "ui.cal.");
  const [{ data: branches, error }, { data: staff }, { data: topics }] = await Promise.all([
    supabase.from("branches").select("id, name, sort, sync_sheet").order("sort").order("name"),
    supabase.from("staff").select("branch_id, name, label, short, sort").eq("active", true).order("sort").order("name"),
    supabase.from("topics").select("id, color, kind, sort").eq("active", true).order("sort"),
  ]);
  if (error) return json({ ok: false, error: error.message });
  let dict: Record<string, string> = {};
  try {
    dict = dictFor([...await getTranslations(undefined, prefix), ...await getTranslations(undefined, "topic.")], lang);
  } catch (e) {
    console.error("bootstrap translations failed", e);
  }
  return json({
    ok: true,
    lang,
    branches: (branches ?? []).map((b) => ({
      ...b,
      staff: (staff ?? []).filter((s) => s.branch_id === b.id)
        .map((s) => ({ name: s.name, label: s.label || s.name, short: s.short || s.name })),
    })),
    topics: topics ?? [],
    dict,
  });
}

// Central admin only. Creates or updates a branch. `branch_pin`: "" leaves it, "-" clears it.
async function handleSaveBranch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const name = String(p.name ?? "").trim();
  const id = cleanId(String(p.id ?? "") || name);
  if (!name) return json({ ok: false, error: "missing_name" });
  if (!id) return json({ ok: false, error: "bad_branch_id" });
  const row: Record<string, unknown> = { id, name };
  if (p.sort !== undefined) row.sort = Number(p.sort) || 0;
  const pin = String(p.branch_pin ?? "").trim();
  if (pin === "-") row.admin_pin_hash = null;
  else if (pin) {
    if (pin.length < 4) return json({ ok: false, error: "pin_too_short" });
    row.admin_pin_hash = await hashPassword(pin);
  }
  const { error } = await supabase.from("branches").upsert(row);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("save_branch", { id, name, pin_changed: !!pin });
  return json({ ok: true, id });
}

// Central admin only. Deletes the branch and everything in it.
async function handleDeleteBranch(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const id = String(p.id ?? "");
  const { count } = await supabase.from("branches").select("id", { count: "exact", head: true });
  if ((count ?? 0) <= 1) return json({ ok: false, error: "last_branch" });
  const { error } = await supabase.from("branches").delete().eq("id", id);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("delete_branch", { id });
  return json({ ok: true });
}

// Central admin only. Replaces a branch's active staff list with `staff`: [{name, label, short}].
// People left out are set inactive (not deleted), so old calendar days keep their name.
async function handleSaveStaff(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const branch = await getBranch(String(p.branch_id ?? ""));
  if (!branch) return json({ ok: false, error: "unknown_branch" });
  const list = Array.isArray(p.staff) ? p.staff as Array<Record<string, unknown>> : [];
  const rows = list
    .map((s, i) => ({
      branch_id: branch.id,
      name: String(s.name ?? "").trim(),
      label: String(s.label ?? "").trim(),
      short: String(s.short ?? "").trim(),
      active: true,
      sort: i,
    }))
    .filter((s) => s.name);
  const names = rows.map((r) => r.name);
  if (new Set(names).size !== names.length) return json({ ok: false, error: "duplicate_name" });

  const { error: offErr } = await supabase.from("staff").update({ active: false }).eq("branch_id", branch.id);
  if (offErr) return json({ ok: false, error: offErr.message });
  if (rows.length) {
    const { error } = await supabase.from("staff").upsert(rows, { onConflict: "branch_id,name" });
    if (error) return json({ ok: false, error: error.message });
  }
  await logAdmin("save_staff", { branch_id: branch.id, names });
  return json({ ok: true });
}

async function handleChangeAdminPin(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const next = String(p.new_pin ?? "").trim();
  if (next.length < 4) return json({ ok: false, error: "pin_too_short" });
  await setSetting(ADMIN_PIN_KEY, await hashPassword(next));
  await logAdmin("change_admin_pin");
  return json({ ok: true });
}

// Lets a page check a PIN before showing its settings screen.
async function handleCheckAdminPin(p: Record<string, unknown>) {
  return json({ ok: await checkAdminPin(String(p.admin_pin ?? "")) });
}

// ============================================================
// Calendar topics (holiday, duty rosters, ...). Shared by all branches.
// Texts live in translations: topic.<id>.name / .short / .message
// ============================================================

const TOPIC_FIELDS = ["name", "short", "message"] as const;

// Central admin only. texts: { name: {th, en, ...}, short: {...}, message: {...} }
// edited: { name: [langs], ... } languages corrected by hand.
async function handleSaveTopic(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const texts = (p.texts ?? {}) as Record<string, Record<string, string>>;
  const edited = (p.edited ?? {}) as Record<string, string[]>;
  if (!String(texts.name?.th ?? "").trim()) return json({ ok: false, error: "missing_name" });
  let id = cleanId(String(p.id ?? ""));
  if (!id) id = "t" + Date.now().toString(36);
  const kind = p.kind === "person" ? "person" : "check";
  const color = /^#[0-9a-fA-F]{6}$/.test(String(p.color ?? "")) ? String(p.color) : "#8b5cf6";
  const topic: Record<string, unknown> = { id, kind, color, active: true, updated_at: new Date().toISOString() };
  if (p.sort !== undefined) topic.sort = Number(p.sort) || 0;
  else {
    const { data: existing } = await supabase.from("topics").select("id, sort").eq("id", id).maybeSingle();
    if (!existing) {
      const { data: all } = await supabase.from("topics").select("sort");
      topic.sort = Math.max(-1, ...(all ?? []).map((t) => t.sort ?? 0)) + 1;
    }
  }
  const { error } = await supabase.from("topics").upsert(topic);
  if (error) return json({ ok: false, error: error.message });
  try {
    await saveTranslationRows(TOPIC_FIELDS.map((f) => ({
      key: `topic.${id}.${f}`,
      ...Object.fromEntries(ALL_LANGS.map((l) => [l, String(texts[f]?.[l] ?? "")])),
      edited: edited[f] ?? [],
      unedited: LANGS.filter((l) => !(edited[f] ?? []).includes(l)),
    })));
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
  await logAdmin("save_topic", { id, kind });
  return json({ ok: true, id });
}

// Central admin only. Hides the topic (old calendar days keep it, just not shown).
async function handleDeleteTopic(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const id = String(p.id ?? "");
  const { error } = await supabase.from("topics").update({ active: false }).eq("id", id);
  if (error) return json({ ok: false, error: error.message });
  await logAdmin("delete_topic", { id });
  return json({ ok: true });
}

// Central admin only. Full topic texts (all languages) for the edit form.
async function handleGetTopicTexts(p: Record<string, unknown>) {
  if (!(await checkAdminPin(String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const id = String(p.id ?? "");
  try {
    const rows = await getTranslations(TOPIC_FIELDS.map((f) => `topic.${id}.${f}`));
    const texts: Record<string, unknown> = {};
    for (const f of TOPIC_FIELDS) texts[f] = rows.find((r) => r.key === `topic.${id}.${f}`) ?? { th: "", edited: [] };
    return json({ ok: true, texts });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// ============================================================
// Calendar days, per branch: which topics are on a date (and who, for person topics).
// For the branch marked sync_sheet, the 4 original topics are also mirrored into the
// SCHEDULE tab of the payroll sheet so anything reading it keeps working.
// ============================================================

const SCHEDULE_TAB = "SCHEDULE";
const SCHEDULE_TEXT_TAB = "SCHEDULE_TEXT";
const SHEET_TOPICS = ["holiday", "big_clean", "stock_check", "toilet_duty"]; // columns B..E

type Entry = { topic_id: string; person: string | null };

// Public read: anyone with the calendar link can see the month.
async function handleScheduleMonth(p: Record<string, unknown>) {
  const branchId = String(p.branch ?? "");
  const month = String(p.month ?? "");
  if (!branchId) return json({ ok: false, error: "missing_branch" });
  if (!/^\d{4}-\d{2}$/.test(month)) return json({ ok: false, error: "bad_month" });
  const [y, m] = month.split("-").map(Number);
  const next = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, "0")}-01`;
  const { data, error } = await supabase.from("schedule_entries")
    .select("date, topic_id, person")
    .eq("branch_id", branchId).gte("date", `${month}-01`).lt("date", next).order("date");
  if (error) return json({ ok: false, error: error.message });
  return json({ ok: true, entries: data ?? [] });
}

// Branch PIN or central PIN. entries: [{ topic_id, person }] = everything on that date.
async function handleSaveScheduleDay(p: Record<string, unknown>) {
  const branch = await getBranch(String(p.branch ?? ""));
  if (!branch) return json({ ok: false, error: "unknown_branch" });
  if (!(await canEditBranch(branch, String(p.admin_pin ?? "")))) return json({ ok: false, error: "wrong_admin_pin" });
  const date = String(p.date ?? "").trim();
  if (!isIsoDate(date)) return json({ ok: false, error: "bad_date" });
  const list = Array.isArray(p.entries) ? p.entries as Array<Record<string, unknown>> : [];
  const entries: Entry[] = [];
  for (const e of list) {
    const topic_id = String(e.topic_id ?? "");
    if (!topic_id || entries.some((x) => x.topic_id === topic_id)) continue;
    entries.push({ topic_id, person: String(e.person ?? "").trim() || null });
  }

  const { error: delErr } = await supabase.from("schedule_entries").delete().eq("branch_id", branch.id).eq("date", date);
  if (delErr) return json({ ok: false, error: delErr.message });
  if (entries.length) {
    const now = new Date().toISOString();
    const { error } = await supabase.from("schedule_entries")
      .insert(entries.map((e) => ({ ...e, branch_id: branch.id, date, updated_at: now })));
    if (error) return json({ ok: false, error: error.message });
  }
  await logAdmin("save_schedule_day", { branch_id: branch.id, date, entries });

  // Best effort: a sheet problem must not undo a save that already worked.
  let sheet_synced = false;
  let sheet_error: string | undefined;
  const sheetId = scheduleSheetId();
  if (sheetId && branch.sync_sheet) {
    try {
      await mirrorScheduleDayToSheet(sheetId, date, entries);
      sheet_synced = true;
    } catch (e) {
      sheet_error = String((e as Error)?.message ?? e);
      console.error("schedule sheet mirror failed", e);
    }
  }
  return json({ ok: true, sheet_synced, sheet_error });
}

async function mirrorScheduleDayToSheet(sheetId: string, date: string, entries: Entry[]) {
  const values = await sheetsGetValues(sheetId, `${SCHEDULE_TAB}!A:E`);
  const headerIdx = values.findIndex((r) => String(r[0] ?? "").trim() === "date");
  if (headerIdx >= 0 && String(values[headerIdx][4] ?? "").trim() !== "toilet_duty") {
    await sheetsSetRow(sheetId, `${SCHEDULE_TAB}!E${headerIdx + 1}`, ["toilet_duty"]);
  }
  let target = -1; // last matching row wins, same as the old Apps Script read
  values.forEach((r, i) => { if (parseSheetDate(String(r[0] ?? "")) === date) target = i; });
  const has = (id: string) => entries.some((e) => e.topic_id === id);
  const out = [date, has("holiday"), has("big_clean"), has("stock_check"),
    entries.find((e) => e.topic_id === "toilet_duty")?.person ?? ""];
  if (target >= 0) await sheetsSetRow(sheetId, `${SCHEDULE_TAB}!A${target + 1}:E${target + 1}`, out);
  else await sheetsAppendRow(sheetId, `${SCHEDULE_TAB}!A:E`, out);
}

// Today's (or `date`) messages, for a daily notifier. `branch` optional (default: all branches).
// `lang` optional: one language; without it every language is returned.
async function handleScheduleToday(p: Record<string, unknown>) {
  const date = String(p.date ?? "") || bangkokToday();
  let q = supabase.from("schedule_entries").select("branch_id, topic_id, person").eq("date", date);
  if (p.branch) q = q.eq("branch_id", String(p.branch));
  const [{ data: entries, error }, { data: topics }, { data: branches }] = await Promise.all([
    q,
    supabase.from("topics").select("id, sort").eq("active", true).order("sort"),
    supabase.from("branches").select("id, name"),
  ]);
  if (error) return json({ ok: false, error: error.message });
  const rows = await getTranslations(undefined, "topic.");
  const textOf = (key: string) => rows.find((r) => r.key === key);
  const langs: Lang[] = p.lang ? [cleanLang(p.lang)] : [...ALL_LANGS];

  const byBranch = new Map<string, Array<Record<string, unknown>>>();
  for (const t of topics ?? []) {
    for (const e of (entries ?? []).filter((x) => x.topic_id === t.id)) {
      const msg = textOf(`topic.${t.id}.message`);
      const name = textOf(`topic.${t.id}.name`);
      const fill = (s: string) => s.replaceAll("{name}", e.person ?? "");
      const message = Object.fromEntries(langs.map((l) => [l, fill(msg?.[l] || msg?.th || "")]));
      const list = byBranch.get(e.branch_id) ?? [];
      list.push({ topic_id: t.id, name: name?.th ?? t.id, person: e.person, message });
      byBranch.set(e.branch_id, list);
    }
  }
  return json({
    ok: true,
    date,
    branches: [...byBranch.entries()].map(([id, items]) => ({
      branch_id: id, branch_name: (branches ?? []).find((b) => b.id === id)?.name ?? id, items,
    })),
  });
}

// Copies SCHEDULE, SCHEDULE_TEXT and the admin PIN from the sheet into Supabase, into the branch
// `branch_id` (created if missing, name `branch_name`), and marks that branch to sync with the sheet.
// Thai/Burmese texts written in the sheet are kept as hand-written (AI won't overwrite them).
// Staff are added from the toilet_duty_<name> rows of SCHEDULE_TEXT. Safe to re-run.
// Auth: the admin_pin currently stored in APP_STATE1 of the sheet (the calendar's existing PIN).
async function handleImportScheduleFromSheet(p: Record<string, unknown>) {
  const sheetId = scheduleSheetId();
  if (!sheetId) return json({ ok: false, error: "SCHEDULE_SHEET_ID not configured" });
  try {
    const [[stateJson] = []] = await sheetsGetValues(sheetId, "APP_STATE1!A2");
    const sheetPin = String(JSON.parse(stateJson ?? "{}").admin_pin ?? "").trim();
    if (!sheetPin || String(p.admin_pin ?? "").trim() !== sheetPin) return json({ ok: false, error: "wrong_admin_pin" });

    const branchId = cleanId(String(p.branch_id ?? "main")) || "main";
    const existing = await getBranch(branchId);
    const branchName = String(p.branch_name ?? "").trim() || existing?.name || "สาขาหลัก";
    {
      const { error } = await supabase.from("branches").upsert({ id: branchId, name: branchName, sync_sheet: true });
      if (error) throw new Error(error.message);
    }

    const entries: Array<Record<string, unknown>> = [];
    const dates = new Set<string>();
    const sheetRows = await sheetsGetValues(sheetId, `${SCHEDULE_TAB}!A:E`);
    const lastRowOf = new Map<string, string[]>(); // last row wins for duplicate dates
    for (const r of sheetRows) {
      const date = parseSheetDate(String(r[0] ?? ""));
      if (date && isIsoDate(date)) lastRowOf.set(date, r);
    }
    const now = new Date().toISOString();
    for (const [date, r] of lastRowOf) {
      dates.add(date);
      if (sheetBool(r[1])) entries.push({ branch_id: branchId, date, topic_id: "holiday", person: null, updated_at: now });
      if (sheetBool(r[2])) entries.push({ branch_id: branchId, date, topic_id: "big_clean", person: null, updated_at: now });
      if (sheetBool(r[3])) entries.push({ branch_id: branchId, date, topic_id: "stock_check", person: null, updated_at: now });
      const duty = String(r[4] ?? "").trim();
      if (duty) entries.push({ branch_id: branchId, date, topic_id: "toilet_duty", person: duty, updated_at: now });
    }
    for (const date of dates) {
      const { error } = await supabase.from("schedule_entries").delete().eq("branch_id", branchId).eq("date", date);
      if (error) throw new Error(error.message);
    }
    if (entries.length) {
      const { error } = await supabase.from("schedule_entries").insert(entries);
      if (error) throw new Error(error.message);
    }

    // SCHEDULE_TEXT: type | text_th | text_mm | text_lo
    const textRows = await sheetsGetValues(sheetId, `${SCHEDULE_TEXT_TAB}!A:D`);
    const head = (textRows.shift() ?? []).map((h) => String(h).trim());
    const col = (name: string) => head.indexOf(name);
    const texts = textRows
      .map((r) => ({
        type: String(r[col("type")] ?? "").trim(),
        th: String(r[col("text_th")] ?? "").trim(),
        my: String(r[col("text_mm")] ?? "").trim(),
        lo: String(r[col("text_lo")] ?? "").trim(),
      }))
      .filter((t) => t.type);
    const messageRows: Array<Record<string, unknown>> = [];
    const toMessage = (topicId: string, t: { th: string; my: string; lo: string }, name?: string) => {
      const swap = (s: string) => name ? s.split(name).join("{name}") : s;
      const row: Record<string, unknown> = { key: `topic.${topicId}.message`, edited: [] as string[] };
      if (t.th) row.th = swap(t.th);
      if (t.my) { row.my = swap(t.my); (row.edited as string[]).push("my"); }
      if (t.lo) { row.lo = swap(t.lo); (row.edited as string[]).push("lo"); }
      if (row.th || row.my || row.lo) messageRows.push(row);
    };
    for (const id of ["holiday", "big_clean", "stock_check"]) {
      const t = texts.find((x) => x.type === id);
      if (t) toMessage(id, t);
    }
    const duty = texts.filter((t) => t.type.startsWith("toilet_duty_"));
    if (duty[0]) toMessage("toilet_duty", duty[0], duty[0].type.slice("toilet_duty_".length));
    await saveTranslationRows(messageRows);

    // Staff from toilet_duty_<name>, only adding people not already in this branch.
    const { data: haveStaff } = await supabase.from("staff").select("name").eq("branch_id", branchId);
    const have = new Set((haveStaff ?? []).map((s) => s.name));
    const newStaff = duty
      .map((t, i) => ({ branch_id: branchId, name: t.type.slice("toilet_duty_".length), sort: have.size + i }))
      .filter((s) => s.name && !have.has(s.name));
    if (newStaff.length) {
      const { error } = await supabase.from("staff").insert(newStaff);
      if (error) throw new Error(error.message);
    }

    if (!(await getSetting<string | null>(ADMIN_PIN_KEY, null))) {
      await setSetting(ADMIN_PIN_KEY, await hashPassword(sheetPin));
    }
    await logAdmin("import_schedule_from_sheet", { branchId, days: dates.size, entries: entries.length, staff: newStaff.length });
    return json({ ok: true, branch_id: branchId, days: dates.size, entries: entries.length, texts: messageRows.length, staff_added: newStaff.length });
  } catch (e) {
    return json({ ok: false, error: String((e as Error)?.message ?? e) });
  }
}

// ============================================================
// Dispatch
// ============================================================

const ACTIONS: Record<string, (p: Record<string, unknown>) => Promise<Response>> = {
  bootstrap: handleBootstrap,
  schedule_month: handleScheduleMonth,
  schedule_today: handleScheduleToday,
  save_schedule_day: handleSaveScheduleDay,
  import_schedule_from_sheet: handleImportScheduleFromSheet,
  check_admin_pin: handleCheckAdminPin,
  change_admin_pin: handleChangeAdminPin,
  save_branch: handleSaveBranch,
  delete_branch: handleDeleteBranch,
  save_staff: handleSaveStaff,
  save_topic: handleSaveTopic,
  delete_topic: handleDeleteTopic,
  get_topic_texts: handleGetTopicTexts,
  ai_translate: handleAiTranslate,
  translate_page: handleTranslatePage,
  list_translations: handleListTranslations,
  save_translations: handleSaveTranslations,
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS_HEADERS });
  try {
    const params: Record<string, unknown> = req.method === "GET"
      ? Object.fromEntries(new URL(req.url).searchParams)
      : await req.json();
    const action = String(params.action ?? "");
    const handler = ACTIONS[action];
    if (!handler) return json({ ok: false, error: "unknown_action: " + action }, 404);
    return await handler(params);
  } catch (e) {
    console.error("dispatch error", e);
    return json({ ok: false, error: String(e) }, 500);
  }
});
