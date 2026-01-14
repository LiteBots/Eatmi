// server.js (ESM) — bez weryfikacji mailowej (bez Resend) + mail powitalny SMTP
import express from "express";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

console.log("NODE VERSION:", process.version);

const app = express();
app.use(express.json({ limit: "1mb" }));

// ====== Serve static files from ROOT ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ====== ENV ======
const {
  // ====== PAYU ======
  PAYU_ENV = "prod", // "prod" albo "sandbox"
  PAYU_POS_ID,
  PAYU_CLIENT_ID,
  PAYU_CLIENT_SECRET,
  PAYU_MD5_SECOND_KEY, // unused (na start)
  PAYU_NOTIFY_URL,
  PAYU_CONTINUE_URL,

  // ====== ADMIN ======
  ADMIN_PIN, // 4 cyfry
  ADMIN_TOKEN_SECRET = "CHANGE_ME_LONG_SECRET_64CHARS_MIN",
  ADMIN_PIN_SALT = "CHANGE_ME_SALT",

  // ====== AUTH ======
  JWT_SECRET,

  // ====== SMTP ======
  SMTP_HOST,
  SMTP_PORT = 465,
  SMTP_SECURE = "true",
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM,

  // ====== MANAGEMENT PANEL (panel.html) ======
  MGMT_PASSWORD, // hasło do kroku 1
  MGMT_PIN, // 4 cyfry do kroku 2
  MGMT_TOKEN_TTL_MIN = "120" // TTL tokena panelu (minuty)
} = process.env;

// Railway daje MONGO_URL (czasem ludzie mają MONGO_URI) — wspieramy oba
const MONGO_URI_EFFECTIVE = process.env.MONGO_URI || process.env.MONGO_URL;

const PAYU_BASE =
  PAYU_ENV === "sandbox" ? "https://secure.snd.payu.com" : "https://secure.payu.com";

function requireEnv(name, value) {
  if (!value) throw new Error(`Missing env var: ${name}`);
}

// ===============================
// SMTP (home.pl) — MAIL POWITALNY
// ===============================
function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

const smtpEnabled = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);

const mailer = smtpEnabled
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: String(SMTP_SECURE) === "true", // 465 => true
      auth: { user: SMTP_USER, pass: SMTP_PASS },

      // ====== TIMEOUTY (żeby nie wisiało) ======
      connectionTimeout: 5000,
      greetingTimeout: 5000,
      socketTimeout: 7000
    })
  : null;

if (mailer) {
  mailer.verify().then(
    () => console.log("[SMTP] ready"),
    (e) => console.error("[SMTP] ERROR:", e?.message || e)
  );
} else {
  console.log("[SMTP] disabled (missing SMTP env vars)");
}

async function sendWelcomeEmail({ to, fullName }) {
  if (!mailer) return;

  const name = escapeHtml(fullName || "");

  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;line-height:1.6;color:#111">
      <h2 style="margin:0 0 12px">Witam ${name}! 👋</h2>
      <p style="margin:0 0 12px">
        Witamy w <strong>eatmi</strong> — cieszymy się, że do nas dołączyłeś.
      </p>
      <p style="margin:0 0 12px">
        Twoje konto zostało właśnie utworzone i jest już aktywne.
        Od teraz możesz zamawiać szybciej i wygodniej.
      </p>
      <p style="margin:0 0 16px">
        Jeśli to nie Ty zakładałeś konto, zignoruj tę wiadomość.
      </p>
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:18px 0" />
      <p style="margin:0;color:#6b7280;font-size:12px">
        Wiadomość wygenerowana automatycznie — prosimy na nią nie odpowiadać.
      </p>
    </div>
  `;

  await mailer.sendMail({
    from: MAIL_FROM || SMTP_USER,
    to,
    subject: "Witamy w eatmi 👋",
    html
  });
}

// ===============================
// MONGO CONNECT + MODELS
// ===============================
requireEnv("MONGO_URL (or MONGO_URI)", MONGO_URI_EFFECTIVE);
requireEnv("JWT_SECRET", JWT_SECRET);

mongoose.set("strictQuery", true);
await mongoose.connect(MONGO_URI_EFFECTIVE);
console.log("Mongo connected");

// -------------------------------
// USERS (kolekcja: users)
// Rozszerzamy schema o pola, których potrzebuje panel.
// Działa też na starych dokumentach (pola będą po prostu undefined).
// -------------------------------
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    fullName: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true },

    // ✅ Panel fields:
    firstName: { type: String, default: "", trim: true },
    lastName: { type: String, default: "", trim: true },
    phone: { type: String, default: "", trim: true },
    address: { type: String, default: "", trim: true }
  },
  { timestamps: true, collection: "users" }
);

UserSchema.index({ email: 1 }, { unique: true });

const User = mongoose.models.User || mongoose.model("User", UserSchema);

// -------------------------------
// STAFF (kolekcja: staff)
// -------------------------------
const StaffSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    pinHash: { type: String, required: true },
    role: { type: String, enum: ["staff"], default: "staff" }
  },
  { timestamps: true, collection: "staff" }
);

// unikalność pinHash (żeby nie było duplikatów PIN-ów)
StaffSchema.index({ pinHash: 1 }, { unique: true });

const Staff = mongoose.models.Staff || mongoose.model("Staff", StaffSchema);

// -------------------------------
// ORDERS (kolekcja: orders)
// -------------------------------
const OrderSchema = new mongoose.Schema(
  {
    extOrderId: { type: String, required: true, unique: true, index: true },
    payuOrderId: { type: String, default: null, index: true },
    status: { type: String, default: "PENDING", index: true },

    // ✅ metoda płatności + flaga offline
    // payu | card | cash
    paymentMethod: { type: String, default: "payu", index: true },
    isOffline: { type: Boolean, default: false, index: true },

    totalAmount: { type: Number, required: true }, // grosze
    totalPLN: { type: Number, required: true }, // zł (np 49.0)

    customer: { type: Object, default: {} }, // bez narzucania struktury
    cart: { type: Array, default: [] },

    payuRaw: { type: Object, default: null }
  },
  { timestamps: true, collection: "orders" }
);

OrderSchema.index({ createdAt: -1 });
OrderSchema.index({ "customer.email": 1 }); // ✅ szybkie wyszukiwanie po mailu

const Order = mongoose.models.Order || mongoose.model("Order", OrderSchema);

// ===============================
// AUTH HELPERS
// ===============================
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function signAuthToken(user) {
  return jwt.sign({ uid: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: "14d" });
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

// ===============================
// AUTH API (bez kodu mailowego)
// ===============================

// Register -> zapis usera + token (od razu aktywne konto) + mail powitalny
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const fullName = String(req.body?.fullName || "").trim();
    const password = String(req.body?.password || "");
    const confirm = String(req.body?.confirm || "");

    if (!email || !email.includes("@")) return res.status(400).json({ error: "Invalid email" });
    if (!fullName || fullName.length < 3) return res.status(400).json({ error: "Invalid fullName" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 chars" });
    if (password !== confirm) return res.status(400).json({ error: "Passwords do not match" });

    const exists = await User.findOne({ email }).lean();
    if (exists) return res.status(409).json({ error: "Email already in use" });

    const passwordHash = await bcrypt.hash(password, 10);

    // spróbuj wyciągnąć first/last z fullName (opcjonalnie)
    const parts = fullName.split(/\s+/).filter(Boolean);
    const firstName = parts[0] || "";
    const lastName = parts.slice(1).join(" ") || "";

    const user = await User.create({
      email,
      fullName,
      passwordHash,
      firstName,
      lastName
    });

    // ✅ MAIL POWITALNY — NIE BLOKUJE REJESTRACJI (bez await)
    sendWelcomeEmail({ to: user.email, fullName: user.fullName })
      .catch((e) => console.log("WELCOME EMAIL ERROR:", e?.message || e));

    const token = signAuthToken(user);

    return res.json({
      ok: true,
      token,
      user: { email: user.email, fullName: user.fullName }
    });
  } catch (e) {
    const msg = String(e?.message || "");
    if (msg.includes("E11000") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ error: "Email already in use" });
    }
    console.log("REGISTER ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// Login -> token
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email || !password) return res.status(400).json({ error: "Missing credentials" });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Bad credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Bad credentials" });

    const token = signAuthToken(user);
    return res.json({
      ok: true,
      token,
      user: { email: user.email, fullName: user.fullName }
    });
  } catch (e) {
    console.log("LOGIN ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// Me (po tokenie)
app.get("/api/auth/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid).select("email fullName firstName lastName phone address createdAt");
    if (!user) return res.status(404).json({ error: "Not found" });
    return res.json({ ok: true, user });
  } catch (e) {
    console.log("ME ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ===============================
// ADMIN HELPERS (STAFF + TOKENS)
// ===============================
function hashPin(pin) {
  return crypto.createHash("sha256").update(`${ADMIN_PIN_SALT}:${pin}`).digest("hex");
}

// ====== Minimal token (HMAC) ======
function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}
function verifyToken(token) {
  const [h, b, s] = String(token || "").split(".");
  if (!h || !b || !s) return null;
  const sig = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(`${h}.${b}`).digest("base64url");
  if (sig !== s) return null;
  try {
    return JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}
function getBearer(req) {
  const auth = req.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : "";
}
function requireStaff(req, res, next) {
  const token = getBearer(req);
  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  req.admin = data;
  next();
}
function requireAdminOnly(req, res, next) {
  const token = getBearer(req);
  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  if (data.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  req.admin = data;
  next();
}
function requireStaffForStream(req, res, next) {
  const token = String(req.query.token || "");
  const data = verifyToken(token);
  if (!data) return res.status(401).end();
  req.admin = data;
  next();
}

// ====== SSE clients ======
const sseClients = new Set();
function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch {}
  }
}

// ===============================
// ✅ MANAGEMENT PANEL (panel.html) — silna ochrona
// 2-step: hasło -> (min 5s) -> PIN -> token
// ===============================
function nowMs() {
  return Date.now();
}

function normalizePin(pin) {
  return String(pin || "").trim();
}

function timingSafeEq(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

// proste rate-limit w pamięci (na IP)
const mgmtRate = new Map(); // key => { count, resetAt }
function mgmtRateLimit(req, res, next) {
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip").split(",")[0].trim();
  const key = `mgmt:${ip}`;
  const winMs = 60_000;
  const max = 30;

  const rec = mgmtRate.get(key) || { count: 0, resetAt: nowMs() + winMs };
  if (nowMs() > rec.resetAt) {
    rec.count = 0;
    rec.resetAt = nowMs() + winMs;
  }
  rec.count += 1;
  mgmtRate.set(key, rec);

  if (rec.count > max) {
    return res.status(429).json({ error: "Too many requests" });
  }
  next();
}

// challenge store (pamięć) — żeby backend mógł wymusić 5s
const mgmtChallenges = new Map(); // challengeId => { iat, ip, used }
function createMgmtChallenge(ip) {
  const id = crypto.randomBytes(16).toString("hex");
  mgmtChallenges.set(id, { iat: nowMs(), ip, used: false });
  return id;
}
function consumeMgmtChallenge(id, ip) {
  const rec = mgmtChallenges.get(id);
  if (!rec) return { ok: false, error: "Invalid challenge" };
  if (rec.used) return { ok: false, error: "Challenge used" };
  if (rec.ip !== ip) return { ok: false, error: "Challenge mismatch" };
  // challenge ważny 10 minut
  if (nowMs() - rec.iat > 10 * 60_000) return { ok: false, error: "Challenge expired" };
  // wymuś min 5 sekund
  if (nowMs() - rec.iat < 5000) return { ok: false, error: "Wait 5 seconds" };
  rec.used = true;
  mgmtChallenges.set(id, rec);
  return { ok: true };
}

function signMgmtToken() {
  const ttlMin = Math.max(5, Number(MGMT_TOKEN_TTL_MIN || 120));
  const payload = {
    role: "mgmt",
    name: "Management",
    iat: nowMs(),
    exp: nowMs() + ttlMin * 60_000
  };
  return signToken(payload);
}

function requireMgmt(req, res, next) {
  const token = getBearer(req);
  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  if (data.role !== "mgmt") return res.status(403).json({ error: "Forbidden" });
  if (data.exp && nowMs() > Number(data.exp)) return res.status(401).json({ error: "Token expired" });
  req.mgmt = data;
  next();
}

// Step 1: hasło -> challenge
app.post("/api/management/login-step1", mgmtRateLimit, async (req, res) => {
  try {
    requireEnv("MGMT_PASSWORD", MGMT_PASSWORD);
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip").split(",")[0].trim();

    const password = String(req.body?.password || "").trim();
    if (!password) return res.status(400).json({ ok: false, error: "Missing password" });

    if (!timingSafeEq(password, String(MGMT_PASSWORD))) {
      return res.status(401).json({ ok: false, error: "Bad password" });
    }

    const challenge = createMgmtChallenge(ip);
    return res.json({ ok: true, challenge });
  } catch (e) {
    console.log("MGMT STEP1 ERROR:", e?.message || e);
    return res.status(500).json({ ok: false, error: e?.message || "Server error" });
  }
});

// Step 2: pin + (opcjonalnie) challenge -> token
app.post("/api/management/login-step2", mgmtRateLimit, async (req, res) => {
  try {
    requireEnv("MGMT_PIN", MGMT_PIN);
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip").split(",")[0].trim();

    const pin = normalizePin(req.body?.pin);
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN must be 4 digits" });

    // jeśli front poda challenge, wymuś 5 sekund
    const challenge = String(req.body?.challenge || "").trim();
    if (challenge) {
      const chk = consumeMgmtChallenge(challenge, ip);
      if (!chk.ok) return res.status(403).json({ error: chk.error || "Forbidden" });
    }

    if (!timingSafeEq(pin, String(MGMT_PIN))) {
      return res.status(401).json({ error: "Bad PIN" });
    }

    const token = signMgmtToken();
    return res.json({ ok: true, token });
  } catch (e) {
    console.log("MGMT STEP2 ERROR:", e?.message || e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ========== MANAGEMENT: USERS + ORDERS (Mongo) ==========
function splitFullName(fullName) {
  const parts = String(fullName || "").trim().split(/\s+/).filter(Boolean);
  const firstName = parts[0] || "";
  const lastName = parts.slice(1).join(" ") || "";
  return { firstName, lastName };
}

function sanitizeUserForList(u, ordersCount = 0) {
  const fullName = String(u.fullName || "").trim();
  const fallback = splitFullName(fullName);

  return {
    id: String(u._id),
    email: u.email,
    fullName: u.fullName,
    firstName: u.firstName || fallback.firstName,
    lastName: u.lastName || fallback.lastName,
    phone: u.phone || "",
    address: u.address || "",
    createdAt: u.createdAt,
    updatedAt: u.updatedAt,
    ordersCount: Number(ordersCount || 0)
  };
}

function sanitizeUserForDetail(u) {
  const fullName = String(u.fullName || "").trim();
  const fallback = splitFullName(fullName);
  return {
    id: String(u._id),
    email: u.email,
    fullName: u.fullName,
    firstName: u.firstName || fallback.firstName,
    lastName: u.lastName || fallback.lastName,
    phone: u.phone || "",
    address: u.address || "",
    createdAt: u.createdAt,
    updatedAt: u.updatedAt
  };
}

// LIST users + ordersCount
app.get("/api/management/users", requireMgmt, async (req, res) => {
  try {
    const users = await User.find({})
      .select("email fullName firstName lastName phone address createdAt updatedAt")
      .sort({ createdAt: -1 })
      .lean();

    const emails = users.map((u) => u.email).filter(Boolean);

    // policz zamówienia per email (orders.customer.email)
    const agg = await Order.aggregate([
      { $match: { "customer.email": { $in: emails } } },
      { $group: { _id: "$customer.email", count: { $sum: 1 } } }
    ]);

    const map = new Map();
    for (const row of agg) map.set(String(row._id || "").toLowerCase(), Number(row.count || 0));

    const out = users.map((u) => sanitizeUserForList(u, map.get(String(u.email).toLowerCase()) || 0));
    res.json({ users: out });
  } catch (e) {
    console.log("MGMT USERS LIST ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// GET user by id
app.get("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    const user = await User.findById(id)
      .select("email fullName firstName lastName phone address createdAt updatedAt")
      .lean();

    if (!user) return res.status(404).json({ error: "Not found" });
    res.json({ user: sanitizeUserForDetail(user) });
  } catch (e) {
    console.log("MGMT USER GET ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// PATCH user (edit any data)
app.patch("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    const email = req.body?.email !== undefined ? normalizeEmail(req.body?.email) : undefined;
    const firstName = req.body?.firstName !== undefined ? String(req.body?.firstName || "").trim() : undefined;
    const lastName = req.body?.lastName !== undefined ? String(req.body?.lastName || "").trim() : undefined;
    const phone = req.body?.phone !== undefined ? String(req.body?.phone || "").trim() : undefined;
    const address = req.body?.address !== undefined ? String(req.body?.address || "").trim() : undefined;

    const patch = {};
    if (email !== undefined) {
      if (!email || !email.includes("@")) return res.status(400).json({ error: "Invalid email" });
      patch.email = email;
    }
    if (firstName !== undefined) patch.firstName = firstName;
    if (lastName !== undefined) patch.lastName = lastName;
    if (phone !== undefined) patch.phone = phone;
    if (address !== undefined) patch.address = address;

    // aktualizuj fullName na podstawie first/last, jeśli podano
    if (firstName !== undefined || lastName !== undefined) {
      const current = await User.findById(id).select("fullName firstName lastName").lean();
      if (!current) return res.status(404).json({ error: "Not found" });

      const fn = firstName !== undefined ? firstName : (current.firstName || splitFullName(current.fullName).firstName);
      const ln = lastName !== undefined ? lastName : (current.lastName || splitFullName(current.fullName).lastName);
      const newFull = `${String(fn || "").trim()} ${String(ln || "").trim()}`.trim();
      if (newFull) patch.fullName = newFull;
    }

    const updated = await User.findOneAndUpdate(
      { _id: id },
      { $set: patch },
      { new: true }
    )
      .select("email fullName firstName lastName phone address createdAt updatedAt")
      .lean();

    if (!updated) return res.status(404).json({ error: "Not found" });

    res.json({ ok: true, user: sanitizeUserForDetail(updated) });
  } catch (e) {
    const msg = String(e?.message || "");
    if (msg.includes("E11000") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ error: "Email already in use" });
    }
    console.log("MGMT USER PATCH ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// Change user password (NO preview)
app.post("/api/management/users/:id/password", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    const newPassword = String(req.body?.newPassword || "");
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 chars" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    const updated = await User.findOneAndUpdate(
      { _id: id },
      { $set: { passwordHash } },
      { new: true }
    )
      .select("_id email")
      .lean();

    if (!updated) return res.status(404).json({ error: "Not found" });

    res.json({ ok: true });
  } catch (e) {
    console.log("MGMT USER PASSWORD ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// Delete user account
app.delete("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    const existing = await User.findById(id).select("email").lean();
    if (!existing) return res.status(404).json({ error: "Not found" });

    // Usuwamy konto usera. Zamówień nie kasujemy automatycznie (historia sprzedaży).
    await User.deleteOne({ _id: id });

    res.json({ ok: true });
  } catch (e) {
    console.log("MGMT USER DELETE ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// Orders per user (by email match)
app.get("/api/management/users/:id/orders", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    const user = await User.findById(id).select("email").lean();
    if (!user?.email) return res.status(404).json({ error: "Not found" });

    const email = String(user.email).toLowerCase();

    const orders = await Order.find({ "customer.email": email })
      .sort({ createdAt: -1 })
      .limit(1000)
      .lean();

    // zwracamy czysto do panelu (i tak ma renderować)
    const mapped = orders.map((o) => ({
      id: String(o._id),
      extOrderId: o.extOrderId,
      payuOrderId: o.payuOrderId,
      status: o.status,
      paymentMethod: o.paymentMethod || (o.isOffline ? "offline" : "payu"),
      isOffline: !!o.isOffline,
      totalAmount: o.totalAmount,
      totalPLN: o.totalPLN,
      customer: o.customer || {},
      cart: Array.isArray(o.cart) ? o.cart : [],
      createdAt: o.createdAt,
      updatedAt: o.updatedAt
    }));

    res.json({ orders: mapped });
  } catch (e) {
    console.log("MGMT USER ORDERS ERROR:", e?.message || e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ===============================
// PAYU HELPERS
// ===============================
function safeCustomer(customer) {
  const c = customer || {};
  return {
    imieNazwisko: c.imieNazwisko || c.name || "",
    telefon: c.telefon || c.phone || "",
    email: normalizeEmail(c.email || ""),
    miasto: c.miasto || "",
    kod: c.kod || "",
    ulica: c.ulica || "",
    nrBud: c.nrBud || "",
    pietro: c.pietro || "",
    lokal: c.lokal || "",
    uwagi: c.uwagi || "",
    faktura: !!c.faktura,
    nip: c.nip || "",
    firma: c.firma || ""
  };
}

function isPaidStatus(status) {
  const s = String(status || "").toUpperCase();
  return s === "COMPLETED" || s === "PAID";
}

// ✅ statusy offline
const OFFLINE_PENDING_STATUS = "AWAITING_PICKUP_PAYMENT";

// ====== PRICE LIST (server-side truth) ======
const PRICE_LIST = {
  "bs-small-1": 3800,
  "bs-small-2": 4000,
  "bs-small-3": 4200,
  "bs-small-vege": 3800,
  "bs-med-1": 5200,
  "bs-med-2": 5400,
  "bs-med-3": 5600,
  "bs-med-vege": 5200,
  "bs-big-1": 8000,
  "bs-big-2": 8200,
  "bs-big-3": 8400,
  "bs-big-vege": 8000,
  "lunch-week": 4900,
  "lunch-month": 5900,
  "lunch-vege": 4900,
  "k-jajecznica-bekon": 1700,
  "k-club-kurczak": 1700,
  "k-club-vege": 1700,
  "k-jajecznica-avo": 1700,
  "k-buritto-chorizo": 1900,
  "k-rostbef": 2100,
  "z-granola": 1900,
  "z-cezar": 1900,
  "z-koreanska": 1900,
  "z-burak": 1900,
  "s-smoothie": 1900,
  "s-tost-fr": 1900,
  "s-pancakes": 1900,
  "s-deser-czeko": 1900,
  "n-lemoniada": 1200,
  "n-sok-pom": 1200,
  "n-kawa-filt-cz": 1000,
  "n-kawa-filt-b": 1000,
  "n-espresso-double": 1100,
  "n-flat-white": 1100,
  "n-latte": 1200,
  "n-cappu": 1100,
  "n-matcha": 1800,
  "n-herbata-cz": 900,
  "n-zimowa": 1500,
  "extra-granola": 1900,
  "extra-lemoniada": 1200,
  "extra-deser": 1900
};

const NAME_LIST = {
  "bs-small-1": "Box śniadaniowy mały nr 1",
  "bs-small-2": "Box śniadaniowy mały nr 2",
  "bs-small-3": "Box śniadaniowy mały nr 3",
  "bs-small-vege": "Box śniadaniowy mały VEGE",
  "bs-med-1": "Box śniadaniowy średni nr 1",
  "bs-med-2": "Box śniadaniowy średni nr 2",
  "bs-med-3": "Box śniadaniowy średni nr 3",
  "bs-med-vege": "Box śniadaniowy średni VEGE",
  "bs-big-1": "Box śniadaniowy duży nr 1",
  "bs-big-2": "Box śniadaniowy duży nr 2",
  "bs-big-3": "Box śniadaniowy duży nr 3",
  "bs-big-vege": "Box śniadaniowy duży VEGE",
  "lunch-week": "Lunch tygodnia",
  "lunch-month": "Lunch miesiąca",
  "lunch-vege": "Lunch VEGE",
  "k-jajecznica-bekon": "Kanapka: jajecznica + bekon",
  "k-club-kurczak": "Club sandwich kurczak",
  "k-club-vege": "Club sandwich vege",
  "k-jajecznica-avo": "Kanapka: jajecznica + awokado",
  "k-buritto-chorizo": "Buritto chorizo",
  "k-rostbef": "Kanapka: rostbef",
  "z-granola": "Domowa granola",
  "z-cezar": "Sałatka Cezar",
  "z-koreanska": "Sałatka koreańska",
  "z-burak": "Sałatka burak + kozi ser",
  "s-smoothie": "Smoothie Mango Lassi",
  "s-tost-fr": "Tost francuski",
  "s-pancakes": "Pancakes",
  "s-deser-czeko": "Deser czekoladowy",
  "n-lemoniada": "Domowa lemoniada 250 ml",
  "n-sok-pom": "Sok pomarańczowy 250 ml",
  "n-kawa-filt-cz": "Kawa filtrowana czarna 300 ml",
  "n-kawa-filt-b": "Kawa filtrowana biała 300 ml",
  "n-espresso-double": "Kawa czarna (podwójne espresso) 300 ml",
  "n-flat-white": "Flat White 300 ml",
  "n-latte": "Latte 300 ml",
  "n-cappu": "Cappuccino 300 ml",
  "n-matcha": "Matcha 300 ml",
  "n-herbata-cz": "Herbata czarna 300 ml",
  "n-zimowa": "Zimowa herbata 300 ml",
  "extra-granola": "Domowa granola (extra)",
  "extra-lemoniada": "Domowa lemoniada (extra)",
  "extra-deser": "Deser czekoladowy (extra)"
};

function validateAndBuildCart(cart) {
  const arr = Array.isArray(cart) ? cart : [];
  if (!arr.length) throw new Error("Empty cart");

  const normalized = arr.map((i) => {
    const productId = i?.productId;
    const qty = Number(i?.qty || 1);

    if (!productId || !PRICE_LIST[productId]) {
      throw new Error(`Unknown productId: ${productId}`);
    }
    if (!Number.isFinite(qty) || qty < 1 || qty > 50) {
      throw new Error(`Invalid qty for ${productId}`);
    }

    return { productId, qty };
  });

  return normalized;
}

function calcTotalAmount(cartNorm) {
  return cartNorm.reduce((sum, i) => sum + PRICE_LIST[i.productId] * i.qty, 0);
}

async function getPayuToken() {
  requireEnv("PAYU_CLIENT_ID", PAYU_CLIENT_ID);
  requireEnv("PAYU_CLIENT_SECRET", PAYU_CLIENT_SECRET);

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: PAYU_CLIENT_ID,
    client_secret: PAYU_CLIENT_SECRET
  });

  const r = await fetch(`${PAYU_BASE}/pl/standard/user/oauth/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const raw = await r.text().catch(() => "");
  if (!r.ok) {
    console.log("PAYU OAUTH FAIL:", r.status, raw);
    throw new Error(`PayU OAuth failed: ${r.status} ${raw}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = {};
  }
  if (!data?.access_token) {
    console.log("PAYU OAUTH BAD JSON:", raw);
    throw new Error("PayU OAuth: missing access_token");
  }

  return data;
}

// ===============================
// ORDER STORE (Mongo) - UPSERT
// ===============================
async function upsertOrderMongo(patch) {
  if (!patch?.extOrderId) throw new Error("upsertOrderMongo: missing extOrderId");
  const now = new Date();

  const updated = await Order.findOneAndUpdate(
    { extOrderId: patch.extOrderId },
    {
      $set: { ...patch, updatedAt: now },
      $setOnInsert: { createdAt: now }
    },
    { upsert: true, new: true }
  ).lean();

  return updated;
}

// ===============================
// ✅ Offline order (karta/gotówka przy odbiorze)
// ===============================
app.post("/api/order/offline", async (req, res) => {
  try {
    const methodRaw = String(req.body?.paymentMethod || "").trim().toLowerCase();
    const paymentMethod = methodRaw === "card" ? "card" : methodRaw === "cash" ? "cash" : "";

    if (!paymentMethod) {
      return res.status(400).json({ error: "Invalid paymentMethod (expected 'card' or 'cash')" });
    }

    const customer = safeCustomer(req.body?.customer);

    // minimalne wymagania (zgodne z frontem)
    if (!customer.imieNazwisko || !customer.telefon || !customer.miasto || !customer.ulica) {
      return res.status(400).json({ error: "Missing required customer fields" });
    }

    const cartNorm = validateAndBuildCart(req.body?.cart);
    const totalAmount = calcTotalAmount(cartNorm);

    const extOrderId = `eatmi-offline-${Date.now()}-${Math.random().toString(16).slice(2)}`;

    // zapis do mongo
    const saved = await upsertOrderMongo({
      extOrderId,
      payuOrderId: null,
      status: OFFLINE_PENDING_STATUS,
      paymentMethod,
      isOffline: true,
      totalAmount,
      totalPLN: totalAmount / 100,
      customer,
      cart: cartNorm,
      payuRaw: null
    });

    // SSE: alarm w panelu admina (jak new order)
    sseBroadcast("new_order", {
      extOrderId: saved.extOrderId,
      payuOrderId: null,
      totalPLN: saved.totalPLN,
      customer: saved.customer?.imieNazwisko || null,
      status: saved.status,
      paymentMethod: saved.paymentMethod
    });

    return res.json({
      ok: true,
      orderId: saved.extOrderId,
      extOrderId: saved.extOrderId,
      status: saved.status
    });
  } catch (e) {
    console.log("OFFLINE ORDER ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ===============================
// PayU: Create order
// ===============================
app.post("/api/payu/order", async (req, res) => {
  try {
    requireEnv("PAYU_POS_ID", PAYU_POS_ID);
    requireEnv("PAYU_NOTIFY_URL", PAYU_NOTIFY_URL);
    requireEnv("PAYU_CONTINUE_URL", PAYU_CONTINUE_URL);

    const cartNorm = validateAndBuildCart(req.body?.cart);

    const products = cartNorm.map((i) => ({
      name: NAME_LIST[i.productId] || "Pozycja",
      unitPrice: String(PRICE_LIST[i.productId]),
      quantity: String(i.qty)
    }));

    const totalAmount = products.reduce(
      (sum, p) => sum + Number(p.unitPrice) * Number(p.quantity),
      0
    );

    const { access_token } = await getPayuToken();

    const customerIp =
      (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() ||
      req.socket.remoteAddress ||
      "127.0.0.1";

    const extOrderId = `eatmi-${Date.now()}-${Math.random().toString(16).slice(2)}`;

    const customer = safeCustomer(req.body?.customer);

    await upsertOrderMongo({
      extOrderId,
      payuOrderId: null,
      status: "PENDING",
      paymentMethod: "payu",
      isOffline: false,
      totalAmount,
      totalPLN: totalAmount / 100,
      customer,
      cart: cartNorm
    });

    const orderBody = {
      customerIp,
      merchantPosId: String(PAYU_POS_ID),
      extOrderId,
      description: "Zamówienie eatmi.pl",
      currencyCode: "PLN",
      totalAmount: String(totalAmount),
      notifyUrl: PAYU_NOTIFY_URL,
      continueUrl: PAYU_CONTINUE_URL,
      products
    };

    const r = await fetch(`${PAYU_BASE}/api/v2_1/orders`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`
      },
      body: JSON.stringify(orderBody)
    });

    const location = r.headers.get("location") || r.headers.get("Location");

    const raw = await r.text().catch(() => "");
    let data = null;
    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch {
        data = { raw };
      }
    }

    if (data?.orderId) {
      await upsertOrderMongo({ extOrderId, payuOrderId: data.orderId });
    }

    if ((r.status === 301 || r.status === 302 || r.status === 303) && location) {
      return res.json({ redirectUri: location, orderId: data?.orderId || null, extOrderId });
    }

    if (r.ok && data?.redirectUri) {
      return res.json({ redirectUri: data.redirectUri, orderId: data.orderId, extOrderId });
    }

    console.log("PAYU CREATE ORDER UNEXPECTED:", { status: r.status, location, data });

    return res.status(502).json({
      error: "PayU create order failed / no redirect",
      status: r.status,
      location: location || null,
      details: data
    });
  } catch (e) {
    console.log("PAYU ORDER ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ===============================
// PayU: Webhook notify
// ===============================
app.post("/api/payu/notify", async (req, res) => {
  try {
    const body = req.body || {};
    const order = body.order || {};
    const extOrderId = order.extOrderId;
    const status = order.status;
    const payuOrderId = order.orderId || null;

    console.log("PAYU NOTIFY:", JSON.stringify(body));

    if (extOrderId) {
      const updated = await upsertOrderMongo({
        extOrderId,
        payuOrderId,
        status: status || "UNKNOWN",
        payuRaw: order
      });

      if (isPaidStatus(status)) {
        sseBroadcast("new_order", {
          extOrderId: updated.extOrderId,
          payuOrderId: updated.payuOrderId,
          totalPLN: updated.totalPLN,
          customer: updated.customer?.imieNazwisko || updated.customer?.name || null,
          status: updated.status,
          paymentMethod: updated.paymentMethod || "payu"
        });
      }
    }

    res.sendStatus(200);
  } catch (e) {
    console.log("PAYU NOTIFY ERROR:", e?.message, e);
    res.sendStatus(200);
  }
});

app.get("/api/payu/notify", (req, res) => {
  res.status(200).send("OK (PayU notify endpoint expects POST)");
});

// ===============================
// ADMIN API (Mongo)
// ===============================
app.post("/api/admin/login", async (req, res) => {
  try {
    const pin = String(req.body?.pin || "").trim();
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN must be 4 digits" });

    if (!ADMIN_PIN) return res.status(500).json({ error: "ADMIN_PIN not set" });

    // admin PIN (env)
    if (pin === String(ADMIN_PIN)) {
      const token = signToken({ role: "admin", name: "Administrator", iat: Date.now() });
      return res.json({ token });
    }

    // staff w Mongo
    const h = hashPin(pin);
    const found = await Staff.findOne({ pinHash: h }).lean();
    if (!found) return res.status(401).json({ error: "Bad PIN" });

    const token = signToken({
      role: "staff",
      name: found.name || "Pracownik",
      staffId: String(found._id),
      iat: Date.now()
    });
    return res.json({ token });
  } catch (e) {
    console.log("ADMIN LOGIN ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("/api/admin/stream", requireStaffForStream, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true, role: req.admin?.role })}\n\n`);
  sseClients.add(res);

  req.on("close", () => {
    sseClients.delete(res);
  });
});

app.get("/api/admin/stats", requireStaff, async (req, res) => {
  try {
    const ordersTotal = await Order.countDocuments({});

    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0);
    const end = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999);

    const ordersToday = await Order.countDocuments({ createdAt: { $gte: start, $lte: end } });

    // ✅ revenueTotal: liczymy tylko realnie opłacone PayU (PAID/COMPLETED)
    const revenueAgg = await Order.aggregate([
      { $match: { status: { $in: ["PAID", "COMPLETED"] } } },
      { $group: { _id: null, sum: { $sum: "$totalPLN" } } }
    ]);

    const revenueTotal = Number(revenueAgg?.[0]?.sum || 0);

    res.json({ ordersTotal, ordersToday, revenueTotal });
  } catch (e) {
    console.log("ADMIN STATS ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("/api/admin/orders", requireStaff, async (req, res) => {
  try {
    const q = String(req.query.query || "").trim().toLowerCase();

    const or = [];

    if (q) {
      or.push({ extOrderId: { $regex: escapeRegex(q), $options: "i" } });
      or.push({ payuOrderId: { $regex: escapeRegex(q), $options: "i" } });

      or.push({ "customer.imieNazwisko": { $regex: escapeRegex(q), $options: "i" } });
      or.push({ "customer.email": { $regex: escapeRegex(q), $options: "i" } });
      or.push({ "customer.telefon": { $regex: escapeRegex(q), $options: "i" } });

      or.push({ paymentMethod: { $regex: escapeRegex(q), $options: "i" } });
      or.push({ status: { $regex: escapeRegex(q), $options: "i" } });
    }

    const filter = q ? { $or: or } : {};

    const orders = await Order.find(filter).sort({ createdAt: -1 }).limit(500).lean();

    res.json({ orders });
  } catch (e) {
    console.log("ADMIN ORDERS ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.post("/api/admin/push", requireStaff, (req, res) => {
  const title = String(req.body?.title || "").trim();
  const body = String(req.body?.body || "").trim();
  if (!body) return res.status(400).json({ error: "Missing body" });

  console.log("ADMIN PUSH:", { from: req.admin?.name, title, body });
  res.json({ ok: true });
});

app.get("/api/admin/staff", requireAdminOnly, async (req, res) => {
  try {
    const list = await Staff.find({}).sort({ createdAt: -1 }).lean();
    const staff = list.map((x) => ({
      id: String(x._id),
      name: x.name,
      role: x.role,
      createdAt: x.createdAt
    }));
    res.json({ staff });
  } catch (e) {
    console.log("ADMIN STAFF GET ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.post("/api/admin/staff", requireAdminOnly, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const pin = String(req.body?.pin || "").trim();

    if (!name) return res.status(400).json({ error: "Missing name" });
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN must be 4 digits" });
    if (pin === String(ADMIN_PIN)) return res.status(400).json({ error: "This PIN is reserved" });

    const pinHash = hashPin(pin);

    const item = await Staff.create({ name, pinHash, role: "staff" });

    res.json({
      ok: true,
      staff: { id: String(item._id), name: item.name, role: item.role, createdAt: item.createdAt }
    });
  } catch (e) {
    const msg = String(e?.message || "");
    if (msg.includes("E11000") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ error: "PIN already in use" });
    }
    console.log("ADMIN STAFF POST ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.delete("/api/admin/staff/:id", requireAdminOnly, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "Missing id" });

    await Staff.deleteOne({ _id: id });
    res.json({ ok: true });
  } catch (e) {
    console.log("ADMIN STAFF DELETE ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

// ===============================
// helpers
// ===============================
function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ===============================
// SPA fallback (hash-router)
// ===============================
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port", process.env.PORT || 3000);
});
