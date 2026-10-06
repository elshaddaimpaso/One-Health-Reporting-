"use strict";
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const { Pool, types } = require("pg");

// bigint (int8) columns come back as strings by default; we only store ms timestamps and ids.
types.setTypeParser(20, (v) => Number(v));

// ---- Configuration (environment only: serverless has no writable disk) ----
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SECRET = process.env.SESSION_SECRET;
if (!DATABASE_URL) throw new Error("DATABASE_URL is not set.");
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) throw new Error("ADMIN_PASSWORD must be set and at least 12 characters.");
if (!SECRET || SECRET.length < 32) throw new Error("SESSION_SECRET must be set and at least 32 characters (openssl rand -hex 32).");

// ---- Reference data (mirrors the frontend) ----
const HAZARDS = {
  "Human Health": ["Respiratory uptick", "Suspected diarrhoeal outbreak", "Febrile illness cluster", "Other"],
  "Agriculture": ["Moldy Maize / Aflatoxin", "Crop pest outbreak", "Livestock feed concern", "Other"],
  "Veterinary": ["Livestock illness", "Unusual animal deaths", "Zoonotic disease concern", "Other"],
  "Environment": ["Water contamination", "Flooding", "Unusual wildlife deaths", "Environmental pollution", "Other"],
};
const AREAS = ["Lilongwe", "Zomba", "Blantyre", "Mangochi", "Mzuzu", "Kasungu", "Mulanje", "Salima"];
const URGENCIES = ["Low", "Medium", "High"];
const STATUSES = ["Open", "Investigating", "Resolved"];

// ---- Database ----
const isLocalDb = /@(localhost|127\.0\.0\.1)(:|\/)/.test(DATABASE_URL);
const pool = new Pool({
  connectionString: DATABASE_URL.replace(/[?&]sslmode=[^&]*/g, ""),
  ssl: isLocalDb ? false : { rejectUnauthorized: false },
  max: 3,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 8000,
});
pool.on("error", (e) => console.error("Postgres pool error:", e.message));
const q = (text, params) => pool.query(text, params);

const serialize = (r) => ({
  id: r.id, sector: r.sector, area: r.area, hazard: r.hazard, description: r.description,
  urgency: r.urgency, status: r.status,
  createdAt: new Date(r.created_at).toISOString(),
  updatedAt: new Date(r.updated_at).toISOString(),
});

// ---- Token signing ----
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const sign = (p) => crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
function issueToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + TOKEN_TTL_MS })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}
function validToken(t) {
  if (typeof t !== "string") return false;
  const [payload, sig] = t.split(".");
  if (!payload || !sig) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(payload));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { return JSON.parse(Buffer.from(payload, "base64url").toString()).exp > Date.now(); }
  catch { return false; }
}
function requireAdmin(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get("authorization") || "");
  if (!m || !validToken(m[1])) return res.status(401).json({ error: "Admin authentication required." });
  next();
}
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---- Rate limiting (shared via Postgres, so it works across serverless instances) ----
function limiter(name, windowMs, limit, message) {
  return async (req, res, next) => {
    const now = Date.now();
    const key = `${name}:${req.ip}`;
    const { rows } = await q(
      `INSERT INTO rate_limits (key, count, reset_at) VALUES ($1, 1, $2)
       ON CONFLICT (key) DO UPDATE SET
         count = CASE WHEN rate_limits.reset_at <= $3 THEN 1 ELSE rate_limits.count + 1 END,
         reset_at = CASE WHEN rate_limits.reset_at <= $3 THEN $2 ELSE rate_limits.reset_at END
       RETURNING count, reset_at`,
      [key, now + windowMs, now]
    );
    if (Math.random() < 0.02) q("DELETE FROM rate_limits WHERE reset_at < $1", [now]).catch(() => {});
    if (rows[0].count > limit) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((rows[0].reset_at - now) / 1000))));
      return res.status(429).json({ error: message });
    }
    next();
  };
}
const submitLimiter = limiter("submit", 60 * 1000, 10, "Too many submissions. Please wait a minute.");
const loginLimiter = limiter("login", 15 * 60 * 1000, 10, "Too many attempts. Try again later.");

// ---- App ----
const app = express();
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(express.json({ limit: "20kb" }));

const api = express.Router();

api.get("/meta", (_req, res) => res.json({ hazards: HAZARDS, areas: AREAS, urgencies: URGENCIES, statuses: STATUSES }));

// Checks the database connection (handy right after deploying)
api.get("/health", async (_req, res) => {
  await q("SELECT 1");
  res.json({ ok: true });
});

// Public: list reports (filters: sector, area, status; paging: limit, offset)
api.get("/reports", async (req, res) => {
  const where = [], params = [];
  const add = (col, val) => { params.push(String(val)); where.push(`${col} = $${params.length}`); };
  const { sector, area, status } = req.query;
  if (sector && sector !== "All") add("sector", sector);
  if (area) add("area", area);
  if (status) add("status", status);
  const w = where.length ? "WHERE " + where.join(" AND ") : "";
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const total = (await q(`SELECT COUNT(*)::int c FROM reports ${w}`, params)).rows[0].c;
  const rows = (await q(
    `SELECT * FROM reports ${w} ORDER BY created_at DESC, id DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset]
  )).rows;
  res.json({ total, reports: rows.map(serialize) });
});

// Public: submit a report
api.post("/reports", submitLimiter, async (req, res) => {
  const b = req.body || {};
  const errors = {};
  if (!HAZARDS[b.sector]) errors.sector = "Select a valid sector.";
  if (!AREAS.includes(b.area)) errors.area = "Select a valid district / area.";
  if (HAZARDS[b.sector] && !HAZARDS[b.sector].includes(b.hazard)) errors.hazard = "Select a hazard type valid for this sector.";
  const description = typeof b.description === "string" ? b.description.trim() : "";
  if (!description) errors.description = "Description is required.";
  else if (description.length > 500) errors.description = "Description must be 500 characters or fewer.";
  if (!URGENCIES.includes(b.urgency)) errors.urgency = "Select an urgency level.";
  if (Object.keys(errors).length) return res.status(400).json({ error: "Validation failed.", errors });

  const now = Date.now();
  const { rows } = await q(
    `INSERT INTO reports (sector, area, hazard, description, urgency, status, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, 'Open', $6, $6) RETURNING *`,
    [b.sector, b.area, b.hazard, description, b.urgency, now]
  );
  res.status(201).json(serialize(rows[0]));
});

// Admin auth
api.post("/admin/login", loginLimiter, (req, res) => {
  const pw = req.body && req.body.password;
  if (typeof pw !== "string" || !safeEqual(pw, ADMIN_PASSWORD)) return res.status(401).json({ error: "Incorrect password." });
  res.json({ token: issueToken(), expiresInMs: TOKEN_TTL_MS });
});
api.get("/admin/session", requireAdmin, (_req, res) => res.json({ ok: true }));

const parseId = (v) => { const n = Number(v); return Number.isSafeInteger(n) && n > 0 ? n : null; };

// Admin: update status
api.patch("/reports/:id", requireAdmin, async (req, res) => {
  const id = parseId(req.params.id);
  const { status } = req.body || {};
  if (!STATUSES.includes(status)) return res.status(400).json({ error: "Invalid status." });
  if (!id) return res.status(404).json({ error: "Report not found." });
  const { rows } = await q("UPDATE reports SET status = $1, updated_at = $2 WHERE id = $3 RETURNING *", [status, Date.now(), id]);
  if (!rows.length) return res.status(404).json({ error: "Report not found." });
  res.json(serialize(rows[0]));
});

// Admin: delete
api.delete("/reports/:id", requireAdmin, async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(404).json({ error: "Report not found." });
  const r = await q("DELETE FROM reports WHERE id = $1", [id]);
  if (!r.rowCount) return res.status(404).json({ error: "Report not found." });
  res.status(204).end();
});

// Admin: stats
api.get("/admin/stats", requireAdmin, async (_req, res) => {
  const group = async (col, keys) => {
    const { rows } = await q(`SELECT ${col} k, COUNT(*)::int c FROM reports GROUP BY ${col}`); // col is a fixed literal below
    return Object.fromEntries(keys.map((k) => [k, (rows.find((r) => r.k === k) || { c: 0 }).c]));
  };
  const totals = await q(`SELECT COUNT(*)::int total,
              (COUNT(*) FILTER (WHERE status <> 'Resolved'))::int unresolved,
              (COUNT(*) FILTER (WHERE status <> 'Resolved' AND urgency = 'High'))::int high,
              (COUNT(DISTINCT area) FILTER (WHERE status <> 'Resolved'))::int districts
       FROM reports`);
  const bySector = await group("sector", Object.keys(HAZARDS));
  const byUrgency = await group("urgency", ["High", "Medium", "Low"]);
  const byStatus = await group("status", STATUSES);
  const t = totals.rows[0];
  res.json({ total: t.total, unresolved: t.unresolved, highUrgencyUnresolved: t.high, districtsAffected: t.districts, bySector, byUrgency, byStatus });
});

api.use((_req, res) => res.status(404).json({ error: "Not found." }));
app.use("/api", api);

app.use((err, _req, res, _next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON." });
  console.error(err);
  res.status(500).json({ error: "Server error." });
});

module.exports = app;
