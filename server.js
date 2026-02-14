const express = require("express");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const cors    = require("cors");
const path    = require("path");
const { stmts } = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Auth middleware ────────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token provided." });
  try {
    req.user = jwt.verify(header.split(" ")[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token." });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Admin access required." });
  next();
};

// ── Auth routes ────────────────────────────────────────────────────────────────
const SECURITY_QUESTIONS = [
  "What was the name of your first pet?",
  "What is your mother's maiden name?",
  "What city were you born in?",
  "What was the name of your primary school?",
  "What is your favourite book?",
];

// POST /api/register
app.post("/api/register", (req, res) => {
  const { username, password, secQ, secA } = req.body;
  if (!username || !password || secA === undefined || secQ === undefined)
    return res.status(400).json({ error: "Missing fields." });
  if (username.toLowerCase() === "admin")
    return res.status(400).json({ error: "Username not allowed." });
  if (password.length < 4)
    return res.status(400).json({ error: "Password must be at least 4 characters." });
  const exists = stmts.findUser.get(username.toLowerCase());
  if (exists) return res.status(409).json({ error: "Username already taken." });
  const hash = bcrypt.hashSync(password, 10);
  const result = stmts.createUser.run(username.toLowerCase(), hash, +secQ, secA.trim().toLowerCase());
  const token = jwt.sign({ id: result.lastInsertRowid, username: username.toLowerCase(), isAdmin: false }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username: username.toLowerCase(), isAdmin: false });
});

// POST /api/login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields." });
  const user = stmts.findUser.get(username.toLowerCase());
  if (!user) return res.status(401).json({ error: "User not found." });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Wrong password." });
  const token = jwt.sign({ id: user.id, username: user.username, isAdmin: !!user.is_admin }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username: user.username, isAdmin: !!user.is_admin });
});

// POST /api/recover/question — get security question for a user
app.post("/api/recover/question", (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "Missing username." });
  const user = stmts.findUser.get(username.toLowerCase());
  if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
  if (!user.sec_a) return res.status(404).json({ error: "No security question set." });
  res.json({ question: SECURITY_QUESTIONS[user.sec_q] });
});

// POST /api/recover/verify — verify answer and reset password
app.post("/api/recover/verify", (req, res) => {
  const { username, answer, newPassword } = req.body;
  if (!username || !answer || !newPassword) return res.status(400).json({ error: "Missing fields." });
  if (newPassword.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters." });
  const user = stmts.findUser.get(username.toLowerCase());
  if (!user || user.is_admin) return res.status(404).json({ error: "User not found." });
  if (answer.trim().toLowerCase() !== user.sec_a)
    return res.status(401).json({ error: "Incorrect answer." });
  const hash = bcrypt.hashSync(newPassword, 10);
  stmts.updatePassword.run(hash, user.username);
  res.json({ ok: true });
});

// POST /api/change-password — authenticated user changes own password
app.post("/api/change-password", auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "Missing fields." });
  if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
  const user = stmts.findUserById.get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password))
    return res.status(401).json({ error: "Current password is incorrect." });
  stmts.updatePassword.run(bcrypt.hashSync(newPassword, 10), user.username);
  res.json({ ok: true });
});

// ── Entry routes ───────────────────────────────────────────────────────────────

// GET /api/entries — get all entries for logged-in user
app.get("/api/entries", auth, (req, res) => {
  const entries = stmts.getUserEntries.all(req.user.id);
  res.json(entries);
});

// POST /api/entries — create or update entry for a date
app.post("/api/entries", auth, (req, res) => {
  const { date, bedTime, wakeTime, duration, screenTime, energy, notes } = req.body;
  if (!date || !bedTime || !wakeTime || duration == null || screenTime == null || energy == null)
    return res.status(400).json({ error: "Missing fields." });
  stmts.upsertEntry.run(req.user.id, date, bedTime, wakeTime, duration, screenTime, energy, notes || "");
  res.json({ ok: true });
});

// DELETE /api/entries/:id — delete a specific entry
app.delete("/api/entries/:id", auth, (req, res) => {
  stmts.deleteEntry.run(+req.params.id, req.user.id);
  res.json({ ok: true });
});

// ── Admin routes ───────────────────────────────────────────────────────────────

// GET /api/admin/users — list all students with their entries
app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const users = stmts.listUsers.all();
  const result = users.map(u => ({
    ...u,
    entries: stmts.entriesByUser.all(u.id),
  }));
  res.json(result);
});

// POST /api/admin/reset-password — admin resets any user's password
app.post("/api/admin/reset-password", auth, adminOnly, (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) return res.status(400).json({ error: "Missing fields." });
  if (newPassword.length < 4) return res.status(400).json({ error: "Min. 4 characters." });
  const user = stmts.findUser.get(username.toLowerCase());
  if (!user) return res.status(404).json({ error: "User not found." });
  stmts.updatePassword.run(bcrypt.hashSync(newPassword, 10), user.username);
  res.json({ ok: true });
});

// ── Fallback → SPA ─────────────────────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`🌙 Sleep Diary running on http://localhost:${PORT}`));
