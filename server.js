const express = require("express");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const cors    = require("cors");
const path    = require("path");
const { ready } = require("./database");

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev-secret-change-in-production";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Wait for DB before handling requests ──────────────────────────────────────
let db;
ready.then(d => { db = d; console.log("✅ Database ready"); });

const dbReady = (req, res, next) => {
  if (!db) return res.status(503).json({ error: "Database not ready yet. Try again in a moment." });
  next();
};

// ── Auth middleware ────────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token provided." });
  try { req.user = jwt.verify(h.split(" ")[1], SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid or expired token." }); }
};

const adminOnly = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required." });
  next();
};

const SECURITY_QUESTIONS = [
  "What was the name of your first pet?",
  "What is your mother's maiden name?",
  "What city were you born in?",
  "What was the name of your primary school?",
  "What is your favourite book?",
];

// ── Auth routes ────────────────────────────────────────────────────────────────

// POST /api/register
app.post("/api/register", dbReady, (req, res) => {
  try {
    const { username, password, secQ, secA } = req.body;
    if (!username || !password || secA === undefined || secQ === undefined)
      return res.status(400).json({ error: "Missing fields." });
    if (username.toLowerCase() === "admin")
      return res.status(400).json({ error: "Username not allowed." });
    if (password.length < 4)
      return res.status(400).json({ error: "Password must be at least 4 characters." });
    if (db.get("SELECT id FROM users WHERE username = ?", [username.toLowerCase()]))
      return res.status(409).json({ error: "Username already taken." });
    const hash = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password, sec_q, sec_a) VALUES (?, ?, ?, ?)",
      [username.toLowerCase(), hash, +secQ, secA.trim().toLowerCase()]);
    const id = db.lastId();
    const token = jwt.sign({ id, username: username.toLowerCase(), isAdmin: false }, SECRET, { expiresIn: "7d" });
    res.json({ token, username: username.toLowerCase(), isAdmin: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/login
app.post("/api/login", dbReady, (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields." });
    const user = db.get("SELECT * FROM users WHERE username = ?", [username.toLowerCase()]);
    if (!user) return res.status(401).json({ error: "User not found." });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: "Wrong password." });
    const token = jwt.sign({ id: user.id, username: user.username, isAdmin: !!user.is_admin }, SECRET, { expiresIn: "7d" });
    res.json({ token, username: user.username, isAdmin: !!user.is_admin });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/recover/question
app.post("/api/recover/question", dbReady, (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username." });
    const user = db.get("SELECT * FROM users WHERE username = ?", [username.toLowerCase()]);
    if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
    if (!user.sec_a) return res.status(404).json({ error: "No security question set." });
    res.json({ question: SECURITY_QUESTIONS[user.sec_q] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/recover/verify
app.post("/api/recover/verify", dbReady, (req, res) => {
  try {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = db.get("SELECT * FROM users WHERE username = ?", [username.toLowerCase()]);
    if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
    if (answer.trim().toLowerCase() !== user.sec_a)
      return res.status(401).json({ error: "Incorrect answer." });
    db.run("UPDATE users SET password = ? WHERE username = ?",
      [bcrypt.hashSync(newPassword, 10), user.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/change-password
app.post("/api/change-password", dbReady, auth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = db.get("SELECT * FROM users WHERE id = ?", [req.user.id]);
    if (!bcrypt.compareSync(currentPassword, user.password))
      return res.status(401).json({ error: "Current password is incorrect." });
    db.run("UPDATE users SET password = ? WHERE id = ?",
      [bcrypt.hashSync(newPassword, 10), req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Entry routes ───────────────────────────────────────────────────────────────

// GET /api/entries
app.get("/api/entries", dbReady, auth, (req, res) => {
  try { res.json(db.all("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC", [req.user.id])); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/entries
app.post("/api/entries", dbReady, auth, (req, res) => {
  try {
    const { date, bedTime, wakeTime, duration, screenTime, energy, notes } = req.body;
    if (!date || !bedTime || !wakeTime || duration == null || screenTime == null || energy == null)
      return res.status(400).json({ error: "Missing fields." });
    db.run(`
      INSERT INTO entries (user_id, date, bed_time, wake_time, duration, screen_time, energy, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, date) DO UPDATE SET
        bed_time = excluded.bed_time, wake_time = excluded.wake_time,
        duration = excluded.duration, screen_time = excluded.screen_time,
        energy = excluded.energy, notes = excluded.notes`,
      [req.user.id, date, bedTime, wakeTime, duration, screenTime, energy, notes || ""]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/entries/:id
app.delete("/api/entries/:id", dbReady, auth, (req, res) => {
  try {
    db.run("DELETE FROM entries WHERE id = ? AND user_id = ?", [+req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin routes ───────────────────────────────────────────────────────────────

// GET /api/admin/users
app.get("/api/admin/users", dbReady, auth, adminOnly, (req, res) => {
  try {
    const users = db.all("SELECT id, username, created_at FROM users WHERE is_admin = 0");
    res.json(users.map(u => ({
      ...u,
      entries: db.all("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC", [u.id])
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/reset-password
app.post("/api/admin/reset-password", dbReady, auth, adminOnly, (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = db.get("SELECT id FROM users WHERE username = ?", [username.toLowerCase()]);
    if (!user) return res.status(404).json({ error: "User not found." });
    db.run("UPDATE users SET password = ? WHERE username = ?",
      [bcrypt.hashSync(newPassword, 10), username.toLowerCase()]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SPA fallback ───────────────────────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => console.log(`🌙 Sleep Diary running on port ${PORT}`));
