"use strict";
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

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

// ---- Admin credentials & token signing ----
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
let generatedPassword = false;
if (!ADMIN_PASSWORD) {
  const pf = path.join(DATA_DIR, "admin-password.txt");
  if (fs.existsSync(pf)) ADMIN_PASSWORD = fs.readFileSync(pf, "utf8").trim();
  else {
    ADMIN_PASSWORD = crypto.randomBytes(9).toString("base64url");
    fs.writeFileSync(pf, ADMIN_PASSWORD + "\n", { mode: 0o600 });
    generatedPassword = true;
  }
}
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  const sf = path.join(DATA_DIR, "session-secret");
  if (fs.existsSync(sf)) SECRET = fs.readFileSync(sf, "utf8").trim();
  else {
    SECRET = crypto.randomBytes(32).toString("hex");
    fs.writeFileSync(sf, SECRET, { mode: 0o600 });
  }
}
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
  const expected = sign(payload);
  const a = Buffer.from(sig), b = Buffer.from(expected);
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

// ---- Database ----
const db = new Database(path.join(DATA_DIR, "onehealth.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  sector      TEXT NOT NULL,
  area        TEXT NOT NULL,
  hazard      TEXT NOT NULL,
  description TEXT NOT NULL,
  urgency     TEXT NOT NULL CHECK (urgency IN ('Low','Medium','High')),
  status      TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Investigating','Resolved')),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_area ON reports(area);
CREATE INDEX IF NOT EXISTS idx_reports_sector ON reports(sector);
`);

// Seed the demo reports from the original frontend on first run only.
if (db.prepare("SELECT COUNT(*) c FROM reports").get().c === 0 && process.env.NO_SEED !== "1") {
  const now = Date.now(), min = 60 * 1000;
  const ins = db.prepare(`INSERT INTO reports (sector,area,hazard,description,urgency,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)`);
  [
    ["Environment", "Lilongwe", "Water contamination", "Community members observed unusual colour and odour in a local water source.", "Low", "Open", 60],
    ["Veterinary", "Zomba", "Livestock illness", "Farmers report unusual illness affecting cattle in two nearby villages.", "Medium", "Investigating", 41],
    ["Human Health", "Blantyre", "Respiratory uptick", "Several households report an increase in cough and breathing-related symptoms.", "Medium", "Open", 28],
    ["Agriculture", "Lilongwe", "Moldy Maize / Aflatoxin", "Visible mould reported in stored maize at a community grain facility.", "High", "Open", 12],
  ].forEach(([s, a, h, d, u, st, ago]) => ins.run(s, a, h, d, u, st, now - ago * min, now - ago * min));
}

const serialize = (r) => ({
  id: r.id, sector: r.sector, area: r.area, hazard: r.hazard, description: r.description,
  urgency: r.urgency, status: r.status,
  createdAt: new Date(r.created_at).toISOString(),
  updatedAt: new Date(r.updated_at).toISOString(),
});

// ---- Live updates (Server-Sent Events) ----
const clients = new Set();
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}

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

// Public: list reports (filters: sector, area, status; paging: limit, offset)
api.get("/reports", (req, res) => {
  const where = [], params = [];
  const { sector, area, status } = req.query;
  if (sector && sector !== "All") { where.push("sector = ?"); params.push(String(sector)); }
  if (area) { where.push("area = ?"); params.push(String(area)); }
  if (status) { where.push("status = ?"); params.push(String(status)); }
  const w = where.length ? "WHERE " + where.join(" AND ") : "";
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const total = db.prepare(`SELECT COUNT(*) c FROM reports ${w}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM reports ${w} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  res.json({ total, reports: rows.map(serialize) });
});

// Public: submit a report
const submitLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many submissions. Please wait a minute." } });
api.post("/reports", submitLimiter, (req, res) => {
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
  const info = db.prepare(`INSERT INTO reports (sector,area,hazard,description,urgency,status,created_at,updated_at) VALUES (?,?,?,?,?, 'Open', ?, ?)`)
    .run(b.sector, b.area, b.hazard, description, b.urgency, now, now);
  const report = serialize(db.prepare("SELECT * FROM reports WHERE id = ?").get(info.lastInsertRowid));
  broadcast("report:created", report);
  res.status(201).json(report);
});

// Public: live stream
api.get("/stream", (req, res) => {
  res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  res.flushHeaders();
  res.write("retry: 3000\n\n");
  clients.add(res);
  const ping = setInterval(() => res.write(": ping\n\n"), 25000);
  req.on("close", () => { clearInterval(ping); clients.delete(res); });
});

// Admin auth
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many attempts. Try again later." } });
api.post("/admin/login", loginLimiter, (req, res) => {
  const pw = req.body && req.body.password;
  if (typeof pw !== "string" || !safeEqual(pw, ADMIN_PASSWORD)) return res.status(401).json({ error: "Incorrect password." });
  res.json({ token: issueToken(), expiresInMs: TOKEN_TTL_MS });
});
api.get("/admin/session", requireAdmin, (_req, res) => res.json({ ok: true }));

// Admin: update status
api.patch("/reports/:id", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const { status } = req.body || {};
  if (!STATUSES.includes(status)) return res.status(400).json({ error: "Invalid status." });
  const info = db.prepare("UPDATE reports SET status = ?, updated_at = ? WHERE id = ?").run(status, Date.now(), id);
  if (!info.changes) return res.status(404).json({ error: "Report not found." });
  const report = serialize(db.prepare("SELECT * FROM reports WHERE id = ?").get(id));
  broadcast("report:updated", report);
  res.json(report);
});

// Admin: delete
api.delete("/reports/:id", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const info = db.prepare("DELETE FROM reports WHERE id = ?").run(id);
  if (!info.changes) return res.status(404).json({ error: "Report not found." });
  broadcast("report:deleted", { id });
  res.status(204).end();
});

// Admin: stats
api.get("/admin/stats", requireAdmin, (_req, res) => {
  const c = (sql, ...p) => db.prepare(sql).get(...p).c;
  const group = (col, keys) => {
    const rows = db.prepare(`SELECT ${col} k, COUNT(*) c FROM reports GROUP BY ${col}`).all();
    return Object.fromEntries(keys.map((k) => [k, (rows.find((r) => r.k === k) || { c: 0 }).c]));
  };
  res.json({
    total: c("SELECT COUNT(*) c FROM reports"),
    unresolved: c("SELECT COUNT(*) c FROM reports WHERE status != 'Resolved'"),
    highUrgencyUnresolved: c("SELECT COUNT(*) c FROM reports WHERE status != 'Resolved' AND urgency = 'High'"),
    districtsAffected: c("SELECT COUNT(DISTINCT area) c FROM reports WHERE status != 'Resolved'"),
    bySector: group("sector", Object.keys(HAZARDS)),
    byUrgency: group("urgency", ["High", "Medium", "Low"]),
    byStatus: group("status", STATUSES),
  });
});

api.use((_req, res) => res.status(404).json({ error: "Not found." }));
app.use("/api", api);

app.use(express.static(path.join(__dirname, "public")));
app.use((err, _req, res, _next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON." });
  console.error(err);
  res.status(500).json({ error: "Server error." });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`One Health backend running on http://localhost:${PORT}`);
    if (generatedPassword) console.log(`Generated admin password (saved to ${path.join(DATA_DIR, "admin-password.txt")}): ${ADMIN_PASSWORD}`);
  });
}
module.exports = app;
