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

// ── Wait for DB ───────────────────────────────────────────────────────────────
let db;
ready.then(d => { db = d; }).catch(e => { console.error("❌ DB init failed:", e.message); process.exit(1); });

const dbReady = (req, res, next) => {
  if (!db) return res.status(503).json({ error: "Database not ready. Try again." });
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

app.post("/api/register", dbReady, async (req, res) => {
  try {
    const { username, password, secQ, secA } = req.body;
    if (!username || !password || secA === undefined || secQ === undefined)
      return res.status(400).json({ error: "Missing fields." });
    if (username.toLowerCase() === "admin")
      return res.status(400).json({ error: "Username not allowed." });
    if (password.length < 4)
      return res.status(400).json({ error: "Password must be at least 4 characters." });
    if (await db.get("SELECT id FROM users WHERE username = $1", [username.toLowerCase()]))
      return res.status(409).json({ error: "Username already taken." });
    const hash   = bcrypt.hashSync(password, 10);
    const result = await db.run(
      "INSERT INTO users (username, password, sec_q, sec_a) VALUES ($1, $2, $3, $4) RETURNING id",
      [username.toLowerCase(), hash, +secQ, secA.trim().toLowerCase()]
    );
    const id    = result.rows[0].id;
    const token = jwt.sign({ id, username: username.toLowerCase(), isAdmin: false }, SECRET, { expiresIn: "7d" });
    res.json({ token, username: username.toLowerCase(), isAdmin: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/login", dbReady, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields." });
    const user = await db.get("SELECT * FROM users WHERE username = $1", [username.toLowerCase()]);
    if (!user) return res.status(401).json({ error: "User not found." });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: "Wrong password." });
    const token = jwt.sign({ id: user.id, username: user.username, isAdmin: !!user.is_admin }, SECRET, { expiresIn: "7d" });
    res.json({ token, username: user.username, isAdmin: !!user.is_admin });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/recover/question", dbReady, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Missing username." });
    const user = await db.get("SELECT * FROM users WHERE username = $1", [username.toLowerCase()]);
    if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
    if (!user.sec_a) return res.status(404).json({ error: "No security question set." });
    res.json({ question: SECURITY_QUESTIONS[user.sec_q] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/recover/verify", dbReady, async (req, res) => {
  try {
    const { username, answer, newPassword } = req.body;
    if (!username || !answer || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = await db.get("SELECT * FROM users WHERE username = $1", [username.toLowerCase()]);
    if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
    if (answer.trim().toLowerCase() !== user.sec_a)
      return res.status(401).json({ error: "Incorrect answer." });
    await db.run("UPDATE users SET password = $1 WHERE username = $2",
      [bcrypt.hashSync(newPassword, 10), user.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/change-password", dbReady, auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = await db.get("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!bcrypt.compareSync(currentPassword, user.password))
      return res.status(401).json({ error: "Current password is incorrect." });
    await db.run("UPDATE users SET password = $1 WHERE id = $2",
      [bcrypt.hashSync(newPassword, 10), req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Entry routes ───────────────────────────────────────────────────────────────

app.get("/api/entries", dbReady, auth, async (req, res) => {
  try {
    res.json(await db.all("SELECT * FROM entries WHERE user_id = $1 ORDER BY date DESC", [req.user.id]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/entries", dbReady, auth, async (req, res) => {
  try {
    const { date, bedTime, wakeTime, duration, screenTime, energy, notes } = req.body;
    if (!date || !bedTime || !wakeTime || duration == null || screenTime == null || energy == null)
      return res.status(400).json({ error: "Missing fields." });
    const existing = await db.get(
      "SELECT id FROM entries WHERE user_id = $1 AND date = $2", [req.user.id, date]
    );
    if (existing) {
      await db.run(
        "UPDATE entries SET bed_time=$1, wake_time=$2, duration=$3, screen_time=$4, energy=$5, notes=$6 WHERE id=$7",
        [bedTime, wakeTime, duration, screenTime, energy, notes || "", existing.id]
      );
    } else {
      await db.run(
        "INSERT INTO entries (user_id, date, bed_time, wake_time, duration, screen_time, energy, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        [req.user.id, date, bedTime, wakeTime, duration, screenTime, energy, notes || ""]
      );
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/entries/:id", dbReady, auth, async (req, res) => {
  try {
    await db.run("DELETE FROM entries WHERE id = $1 AND user_id = $2", [+req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin routes ───────────────────────────────────────────────────────────────

app.get("/api/admin/users", dbReady, auth, adminOnly, async (req, res) => {
  try {
    const users = await db.all("SELECT id, username, created_at FROM users WHERE is_admin = 0");
    const result = await Promise.all(users.map(async u => ({
      ...u,
      entries: await db.all("SELECT * FROM entries WHERE user_id = $1 ORDER BY date DESC", [u.id])
    })));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/admin/reset-password", dbReady, auth, adminOnly, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: "Missing fields." });
    if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
    const user = await db.get("SELECT id FROM users WHERE username = $1", [username.toLowerCase()]);
    if (!user) return res.status(404).json({ error: "User not found." });
    await db.run("UPDATE users SET password = $1 WHERE username = $2",
      [bcrypt.hashSync(newPassword, 10), username.toLowerCase()]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SPA fallback ───────────────────────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => console.log("🌙 Sleep Diary running on port " + PORT));
