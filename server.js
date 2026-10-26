
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 3000);

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET кемінде 32 таңбадан тұратын құпия мән болуы керек");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL .env ішінде көрсетілуі керек");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "http://localhost:5500"
}));
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) {
    return res.status(401).json({ message: "Жүйеге кіріңіз" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      message: "Токен жарамсыз немесе мерзімі аяқталған"
    });
  }
}

function validEmail(email) {
  return typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    email.length <= 255;
}

app.get("/api/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ status: "ok", database: "connected", service: "Giftly API" });
}));

// REGISTER
app.post("/api/auth/register", authLimiter, asyncRoute(async (req, res) => {
  const { name, email, password } = req.body;

  if (typeof name !== "string" || !name.trim() || name.trim().length > 100) {
    return res.status(400).json({ message: "Атыңызды дұрыс енгізіңіз" });
  }
  if (!validEmail(email)) {
    return res.status(400).json({ message: "Email форматы дұрыс емес" });
  }
  if (typeof password !== "string" || password.length < 8 || password.length > 72) {
    return res.status(400).json({
      message: "Құпиясөз 8–72 таңба болуы керек"
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      `INSERT INTO users(name,email,password_hash)
       VALUES($1,$2,$3)
       RETURNING id,name,email,created_at`,
      [name.trim(), email.trim().toLowerCase(), hash]
    );

    const user = result.rows[0];
    res.status(201).json({
      message: "Тіркелу сәтті аяқталды",
      user,
      token: createToken(user)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "Бұл email бұрын тіркелген"
      });
    }
    throw error;
  }
}));

// LOGIN
app.post("/api/auth/login", authLimiter, asyncRoute(async (req, res) => {
  const { email, password } = req.body;

  if (!validEmail(email) || typeof password !== "string") {
    return res.status(400).json({ message: "Email мен құпиясөзді тексеріңіз" });
  }

  const result = await pool.query(
    `SELECT id,name,email,password_hash
     FROM users WHERE email=$1`,
    [email.trim().toLowerCase()]
  );

  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ message: "Email немесе құпиясөз қате" });
  }

  res.json({
    message: "Жүйеге сәтті кірдіңіз",
    user: { id: user.id, name: user.name, email: user.email },
    token: createToken(user)
  });
}));

// CURRENT USER
app.get("/api/auth/me", authenticate, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,created_at FROM users WHERE id=$1",
    [req.user.id]
  );
  if (!result.rowCount) {
    return res.status(404).json({ message: "Пайдаланушы табылмады" });
  }
  res.json({ user: result.rows[0] });
}));

// ALL GIFTS
app.get("/api/gifts", asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,name,description,price,category,emoji
     FROM gifts ORDER BY id ASC`
  );
  res.json({ gifts: result.rows });
}));

// SINGLE GIFT
app.get("/api/gifts/:id", asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ message: "ID дұрыс емес" });
  }

  const result = await pool.query(
    `SELECT id,name,description,price,category,emoji
     FROM gifts WHERE id=$1`,
    [id]
  );

  if (!result.rowCount) {
    return res.status(404).json({ message: "Сыйлық табылмады" });
  }
  res.json({ gift: result.rows[0] });
}));

// RECOMMENDATIONS
app.post("/api/gifts/recommend", asyncRoute(async (req, res) => {
  const { budget, interest } = req.body;
  const maxBudget = Number(budget);

  if (!Number.isFinite(maxBudget) || maxBudget < 0 || maxBudget > 100000000) {
    return res.status(400).json({ message: "Бюджет дұрыс емес" });
  }

  const allowedCategories = [
    "technology", "music", "sport", "books",
    "travel", "beauty", "gaming", "home"
  ];
  const category = allowedCategories.includes(interest) ? interest : "";

  const result = await pool.query(
    `SELECT id,name,description,price,category,emoji
     FROM gifts
     WHERE price <= $1
     ORDER BY
       CASE WHEN category=$2 THEN 0 ELSE 1 END,
       price ASC
     LIMIT 50`,
    [maxBudget, category]
  );

  res.json({ gifts: result.rows, count: result.rowCount });
}));

// FAVORITES: GET
app.get("/api/favorites", authenticate, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT g.id,g.name,g.description,g.price,g.category,g.emoji
     FROM favorites f
     JOIN gifts g ON g.id=f.gift_id
     WHERE f.user_id=$1
     ORDER BY f.created_at DESC`,
    [req.user.id]
  );
  res.json({ favorites: result.rows });
}));

// FAVORITES: ADD
app.post("/api/favorites/:giftId", authenticate, asyncRoute(async (req, res) => {
  const giftId = Number(req.params.giftId);

  if (!Number.isInteger(giftId) || giftId < 1) {
    return res.status(400).json({ message: "Сыйлық ID дұрыс емес" });
  }

  const result = await pool.query(
    `INSERT INTO favorites(user_id,gift_id)
     SELECT $1,id FROM gifts WHERE id=$2
     ON CONFLICT(user_id,gift_id) DO NOTHING
     RETURNING gift_id`,
    [req.user.id, giftId]
  );

  if (!result.rowCount) {
    const gift = await pool.query("SELECT id FROM gifts WHERE id=$1", [giftId]);
    if (!gift.rowCount) {
      return res.status(404).json({ message: "Сыйлық табылмады" });
    }
    return res.json({ message: "Бұл сыйлық бұрын таңдаулыға қосылған" });
  }

  res.status(201).json({ message: "Таңдаулыға қосылды" });
}));

// FAVORITES: DELETE
app.delete("/api/favorites/:giftId", authenticate, asyncRoute(async (req, res) => {
  const giftId = Number(req.params.giftId);

  if (!Number.isInteger(giftId) || giftId < 1) {
    return res.status(400).json({ message: "Сыйлық ID дұрыс емес" });
  }

  await pool.query(
    "DELETE FROM favorites WHERE user_id=$1 AND gift_id=$2",
    [req.user.id, giftId]
  );
  res.json({ message: "Таңдаулылардан өшірілді" });
}));

app.use((req, res) => {
  res.status(404).json({ message: "API мекенжайы табылмады" });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ message: "Серверде ішкі қате пайда болды" });
});

async function start() {
  await pool.query("SELECT 1");
  app.listen(PORT, () => {
    console.log(`Giftly API: http://localhost:${PORT}`);
  });
}

start().catch(error => {
  console.error("Backend іске қосылмады:", error.message);
  process.exit(1);
});

process.on("SIGINT", async () => {
  await pool.end();
  process.exit(0);
});
