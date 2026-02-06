import express from "express";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import webpush from "web-push";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import slowDown from "express-slow-down";

console.log("NODE VERSION:", process.version);

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "10mb" }));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));

const {
  PAYU_ENV = "prod",
  PAYU_POS_ID,
  PAYU_CLIENT_ID,
  PAYU_CLIENT_SECRET,
  PAYU_MD5_SECOND_KEY,
  PAYU_NOTIFY_URL,
  PAYU_CONTINUE_URL,
  ADMIN_PIN,
  ADMIN_TOKEN_SECRET = "CHANGE_ME_LONG_SECRET_64CHARS_MIN",
  ADMIN_PIN_SALT = "CHANGE_ME_SALT",
  JWT_SECRET,
  SMTP_HOST,
  SMTP_PORT = 465,
  SMTP_SECURE = "true",
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM,
  MGMT_PASSWORD,
  MGMT_PIN,
  MGMT_TOKEN_SECRET,
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY,
  ALLOWED_ORIGINS
} = process.env;

const MONGO_URI_EFFECTIVE = process.env.MONGO_URI || process.env.MONGO_URL;

const PAYU_BASE =
  PAYU_ENV === "sandbox" ? "https://secure.snd.payu.com" : "https://secure.payu.com";

function requireEnv(name, value) {
  if (!value) console.warn(`⚠️ Warning: Missing env var: ${name}`);
}

const allowedOriginsSet = new Set(
  String(ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

if (!allowedOriginsSet.size) {
  allowedOriginsSet.add("https://eatmi.pl");
  allowedOriginsSet.add("https://www.eatmi.pl");
  allowedOriginsSet.add("http://localhost:3000");
  allowedOriginsSet.add("http://127.0.0.1:3000");
}

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (allowedOriginsSet.has(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", "data:", "https://i.imgur.com"],
        fontSrc: ["'self'", "data:"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https://cdn.tailwindcss.com",
          "https://unpkg.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.tailwindcss.com",
          "https://unpkg.com"
        ],
        connectSrc: ["'self'"],
        manifestSrc: ["'self'"],
        workerSrc: ["'self'"],
        upgradeInsecureRequests: isProd ? [] : null
      }
    }
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (isProd) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=15552000; includeSubDomains; preload"
    );
  }
  next();
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo zapytań. Spróbuj ponownie za chwilę." }
});

app.use("/api", apiLimiter);

const loginSlow = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 5,
  delayMs: () => 500
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo prób logowania. Odczekaj 15 minut." }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo rejestracji. Spróbuj później." }
});

const promoLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo prób kodów. Spróbuj za kilka minut." }
});

const payuLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo prób płatności. Spróbuj ponownie za chwilę." }
});

const ordersLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo odpytań o status. Zwolnij." }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 240,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo żądań (admin)." }
});

const mgmtLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Za dużo żądań (management)." }
});

app.use("/api/auth/login", loginSlow, loginLimiter);
app.use("/api/auth/register", registerLimiter);
app.use("/api/promo/verify", promoLimiter);
app.use("/api/payu", payuLimiter);
app.use("/api/orders", ordersLimiter);
app.use("/api/admin", adminLimiter);
app.use("/api/management", mgmtLimiter);

const VAPID_EMAIL = "mailto:admin@eatmi.pl";

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  console.log("[PUSH] VAPID initialized ✅");
} else {
  console.warn(
    "[PUSH] VAPID keys missing - notifications will not work! Generate them with 'npx web-push generate-vapid-keys'"
  );
}

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
      secure: String(SMTP_SECURE) === "true",
      auth: { user: SMTP_USER, pass: SMTP_PASS },
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

requireEnv("MONGO_URL (or MONGO_URI)", MONGO_URI_EFFECTIVE);
requireEnv("JWT_SECRET", JWT_SECRET);

mongoose.set("strictQuery", true);
await mongoose.connect(MONGO_URI_EFFECTIVE);
console.log("Mongo connected");

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    fullName: { type: String, required: true, trim: true },
    passwordHash: { type: String, required: true },
    firstName: { type: String, default: "", trim: true },
    lastName: { type: String, default: "", trim: true },
    phone: { type: String, default: "", trim: true },
    address: { type: String, default: "", trim: true }
  },
  { timestamps: true, collection: "users" }
);

UserSchema.index({ email: 1 }, { unique: true });

const User = mongoose.models.User || mongoose.model("User", UserSchema);

const StaffSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    pinHash: { type: String, required: true },
    role: { type: String, enum: ["staff"], default: "staff" }
  },
  { timestamps: true, collection: "staff" }
);

StaffSchema.index({ pinHash: 1 }, { unique: true });

const Staff = mongoose.models.Staff || mongoose.model("Staff", StaffSchema);

const OrderSchema = new mongoose.Schema(
  {
    extOrderId: { type: String, required: true, unique: true, index: true },
    payuOrderId: { type: String, default: null, index: true },
    status: { type: String, default: "PENDING", index: true },
    paymentMethod: { type: String, default: "payu", index: true },
    isOffline: { type: Boolean, default: false, index: true },
    totalAmount: { type: Number, required: true },
    totalPLN: { type: Number, required: true },
    promoCode: { type: String, default: null },
    discountAmount: { type: Number, default: 0 },
    customer: { type: Object, default: {} },
    cart: { type: Array, default: [] },
    payuRaw: { type: Object, default: null }
  },
  { timestamps: true, collection: "orders" }
);

OrderSchema.index({ createdAt: -1 });
OrderSchema.index({ "customer.email": 1 });
OrderSchema.index({ "customer.telefon": 1 });

const Order = mongoose.models.Order || mongoose.model("Order", OrderSchema);

const ProductSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    description: { type: String, default: "" },
    image: { type: String, default: "" },
    category: { type: String, default: "lunch" },
    isVisible: { type: Boolean, default: true }
  },
  { timestamps: true, collection: "products" }
);

const Product = mongoose.models.Product || mongoose.model("Product", ProductSchema);

const PushSubSchema = new mongoose.Schema({
  endpoint: { type: String, required: true, unique: true },
  keys: {
    p256dh: { type: String, required: true },
    auth: { type: String, required: true }
  },
  createdAt: { type: Date, default: Date.now }
});

const PushSubscription =
  mongoose.models.PushSubscription || mongoose.model("PushSubscription", PushSubSchema);

const PromoCodeSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, uppercase: true, trim: true },
    discountPercent: { type: Number, required: true, min: 1, max: 100 },
    expiresAt: { type: Date, required: true },
    usageLimit: { type: Number, default: null },
    usedCount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true }
  },
  { timestamps: true, collection: "promocodes" }
);

const PromoCode = mongoose.models.PromoCode || mongoose.model("PromoCode", PromoCodeSchema);

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

    const parts = fullName.split(/\s+/).filter(Boolean);
    const firstName = parts[0] || "";
    const lastName = parts.slice(1).join(" ");

    const user = await User.create({
      email,
      fullName,
      passwordHash,
      firstName,
      lastName
    });

    sendWelcomeEmail({ to: user.email, fullName: user.fullName }).catch((e) =>
      console.log("WELCOME EMAIL ERROR:", e?.message || e)
    );

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

app.get("/api/auth/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid).select(
      "email fullName firstName lastName phone address createdAt"
    );
    if (!user) return res.status(404).json({ error: "Not found" });
    return res.json({ ok: true, user });
  } catch (e) {
    console.log("ME ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

function hashPin(pin) {
  return crypto.createHash("sha256").update(`${ADMIN_PIN_SALT}:${pin}`).digest("hex");
}

function signToken(payload, secret) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function verifyToken(token, secret) {
  const [h, b, s] = String(token || "").split(".");
  if (!h || !b || !s) return null;
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${b}`).digest("base64url");
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
  const data = verifyToken(token, ADMIN_TOKEN_SECRET);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  req.admin = data;
  next();
}

function requireAdminOnly(req, res, next) {
  const token = getBearer(req);
  const data = verifyToken(token, ADMIN_TOKEN_SECRET);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  if (data.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  req.admin = data;
  next();
}

function requireStaffForStream(req, res, next) {
  const token = String(req.query.token || "");
  const data = verifyToken(token, ADMIN_TOKEN_SECRET);
  if (!data) return res.status(401).end();
  req.admin = data;
  next();
}

const sseClients = new Set();

function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch {}
  }
}

function safeCustomer(customer) {
  const c = customer || {};
  return {
    imieNazwisko: c.imieNazwisko || c.name || "",
    telefon: c.telefon || c.phone || "",
    email: c.email || "",
    miasto: c.miasto || "",
    kod: c.kod || "",
    ulica: c.ulica || "",
    nrBud: c.nrBud || "",
    pietro: c.pietro || "",
    lokal: c.lokal || "",
    uwagi: c.uwagi || "",
    faktura: !!c.faktura,
    nip: c.nip || "",
    firma: c.firma || "",
    deliveryTime: c.deliveryTime || "",
    fulfillmentMethod: c.fulfillmentMethod || ""
  };
}

function isPaidStatus(status) {
  const s = String(status || "").toUpperCase();
  return s === "COMPLETED" || s === "PAID";
}

const OFFLINE_PENDING_STATUS = "AWAITING_PICKUP_PAYMENT";

const PRICE_LIST = {
  "bs-small-1": 4300,
  "bs-small-2": 4500,
  "bs-small-3": 4700,
  "bs-small-vege": 4300,
  "bs-med-1": 5800,
  "bs-med-2": 6000,
  "bs-med-3": 6200,
  "bs-med-vege": 5800,
  "bs-big-1": 8700,
  "bs-big-2": 8900,
  "bs-big-3": 9200,
  "bs-big-vege": 8700,
  "lunch-week": 5500,
  "lunch-month": 6500,
  "lunch-vege": 5500,
  "k-jajecznica-bekon": 1800,
  "k-club-kurczak": 1800,
  "k-club-vege": 1800,
  "k-jajecznica-avo": 1800,
  "k-buritto-chorizo": 2000,
  "k-rostbef": 2200,
  "z-granola": 2000,
  "z-cezar": 2000,
  "z-koreanska": 2000,
  "z-burak": 2000,
  "s-smoothie": 2000,
  "s-tost-fr": 2000,
  "s-pancakes": 2000,
  "s-deser-czeko": 2000,
  "n-lemoniada": 1300,
  "n-sok-pom": 1300,
  "n-kawa-filt-cz": 1100,
  "n-kawa-filt-b": 1100,
  "n-espresso-double": 1200,
  "n-flat-white": 1200,
  "n-latte": 1300,
  "n-cappu": 1300,
  "n-matcha": 1900,
  "n-herbata-cz": 1000,
  "n-zimowa": 1600,
  "extra-granola": 2000,
  "extra-lemoniada": 1300,
  "extra-deser": 2000
};

const ADDONS_PRICE_LIST = {
  "milk-oat": 200,
  "milk-coconut": 200,
  "milk-pea": 200,
  "honey-50": 300
};

const ADDONS_NAME_LIST = {
  "milk-oat": "Mleko owsiane",
  "milk-coconut": "Mleko kokosowe",
  "milk-pea": "Mleko grochowe",
  "honey-50": "Miód 50 ml"
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

async function seedLunche() {
  try {
    const LUNCH_DEFAULTS = [
      {
        id: "lunch-week",
        name: "Lunch tygodnia",
        price: 5500,
        description:
          "Dostępny 12:00–16:00 • Zupa krem z pieczonych buraków 200 ml • Corn Flake Chicken: panierowana w płatkach kukurydzianych pierś z kurczaka z ziemniaczanym puree i coleslawem • Domowa lemoniada 250 ml",
        image: "https://i.imgur.com/sn5VMfS.jpeg",
        category: "lunch",
        isVisible: true
      },
      {
        id: "lunch-month",
        name: "Lunch miesiąca",
        price: 6500,
        description:
          "Dostępny 12:00–16:00 • Zupa krem z pieczonych buraków 200 ml • Kurczak Supreme: pieczona pierś z kurczaka z ziemniaczanym puree, warzywami i sosem demi glace • Domowa lemoniada 250 ml",
        image: "https://i.imgur.com/xGCYJZQ.jpeg",
        category: "lunch",
        isVisible: true
      },
      {
        id: "lunch-vege",
        name: "Lunch VEGE",
        price: 5500,
        description:
          "Dostępny 12:00–16:00 • Zupa krem z pieczonych buraków 200 ml • Tagliatelle z warzywami, oliwą z oliwek i pastą truflową • Domowa lemoniada 250 ml",
        image: "https://i.imgur.com/0hvAvxJ.jpeg",
        category: "lunch",
        isVisible: true
      }
    ];

    for (const lunch of LUNCH_DEFAULTS) {
      await Product.findOneAndUpdate({ id: lunch.id }, { $set: lunch }, { upsert: true, new: true });
    }
    console.log("✅ Lunche zaktualizowane w bazie danych.");
  } catch (e) {
    console.error("SEED ERROR:", e);
  }
}
seedLunche();

async function getProductInfo(id) {
  const doc = await Product.findOne({ id }).lean();
  if (doc) return { price: doc.price, name: doc.name };
  if (PRICE_LIST[id] !== undefined) return { price: PRICE_LIST[id], name: NAME_LIST[id] || "Produkt" };
  return null;
}

async function validateAndBuildCart(cart) {
  const arr = Array.isArray(cart) ? cart : [];
  if (!arr.length) throw new Error("Empty cart");

  const normalized = [];

  for (const i of arr) {
    const productId = i?.productId;
    const qty = Number(i?.qty || 1);

    const info = await getProductInfo(productId);

    if (!info) throw new Error(`Unknown productId: ${productId}`);
    if (!Number.isFinite(qty) || qty < 1 || qty > 50) throw new Error(`Invalid qty for ${productId}`);

    const rawAddons = Array.isArray(i.addons) ? i.addons : [];
    const validAddons = rawAddons.filter((a) => a && ADDONS_PRICE_LIST[a.id]);
    const addonsCost = validAddons.reduce((sum, a) => sum + ADDONS_PRICE_LIST[a.id], 0);

    const basePrice = info.price;
    const unitEffectivePrice = basePrice + addonsCost;

    normalized.push({
      productId,
      name: info.name,
      qty,
      addons: validAddons,
      unitBasePrice: basePrice,
      unitAddonsPrice: addonsCost,
      unitEffectivePrice
    });
  }

  return normalized;
}

function calcTotalProductsValue(cartNorm) {
  return cartNorm.reduce((sum, i) => sum + i.unitEffectivePrice * i.qty, 0);
}

function calcDeliveryCost(cartValue) {
  if (cartValue < 5000) return 1000;
  if (cartValue < 8000) return 500;
  return 0;
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

async function upsertOrderMongo(patch) {
  if (!patch?.extOrderId) throw new Error("upsertOrderMongo: missing extOrderId");
  const now = new Date();

  const updated = await Order.findOneAndUpdate(
    { extOrderId: patch.extOrderId },
    { $set: { ...patch, updatedAt: now }, $setOnInsert: { createdAt: now } },
    { upsert: true, new: true }
  ).lean();

  return updated;
}

app.get("/api/push/vapid-public-key", (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post("/api/push/subscribe", async (req, res) => {
  try {
    const subscription = req.body;
    if (!subscription || !subscription.endpoint) return res.status(400).json({ error: "Invalid subscription" });

    await PushSubscription.findOneAndUpdate({ endpoint: subscription.endpoint }, subscription, {
      upsert: true,
      new: true
    });

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error("PUSH SUBSCRIBE ERROR:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/promo/verify", async (req, res) => {
  try {
    const codeStr = String(req.body.code || "").toUpperCase().trim();
    const promo = await PromoCode.findOne({ code: codeStr, isActive: true });

    if (!promo) return res.status(404).json({ error: "Kod nieprawidłowy" });

    if (new Date() > promo.expiresAt) return res.status(400).json({ error: "Kod wygasł" });

    if (promo.usageLimit !== null && promo.usedCount >= promo.usageLimit) {
      return res.status(400).json({ error: "Limit użyć kodu wyczerpany" });
    }

    res.json({ ok: true, code: promo.code, discountPercent: promo.discountPercent });
  } catch {
    res.status(500).json({ error: "Błąd weryfikacji" });
  }
});

app.post("/api/order/offline", async (req, res) => {
  try {
    const methodRaw = String(req.body?.paymentMethod || "").trim().toLowerCase();
    const paymentMethod = methodRaw === "card" ? "card" : methodRaw === "cash" ? "cash" : "";

    if (!paymentMethod) return res.status(400).json({ error: "Invalid paymentMethod (expected 'card' or 'cash')" });

    const customer = safeCustomer(req.body?.customer);

    if (!customer.imieNazwisko || !customer.telefon) {
      return res.status(400).json({ error: "Missing required customer fields" });
    }

    const cartNorm = await validateAndBuildCart(req.body?.cart);

    const productsValue = calcTotalProductsValue(cartNorm);

    let discountAmount = 0;
    let usedPromoCode = null;

    if (req.body.promoCode) {
      const promo = await PromoCode.findOne({
        code: String(req.body.promoCode || "").toUpperCase(),
        isActive: true
      });

      if (
        promo &&
        new Date() <= promo.expiresAt &&
        (promo.usageLimit === null || promo.usedCount < promo.usageLimit)
      ) {
        discountAmount = Math.round(productsValue * (promo.discountPercent / 100));
        usedPromoCode = promo.code;
        await PromoCode.updateOne({ _id: promo._id }, { $inc: { usedCount: 1 } });
      }
    }

    const productsValueAfterDiscount = Math.max(0, productsValue - discountAmount);
    const deliveryCost = calcDeliveryCost(productsValueAfterDiscount);
    const totalAmount = productsValueAfterDiscount + deliveryCost;

    const extOrderId = `eatmi-offline-${Date.now()}-${Math.random().toString(16).slice(2)}`;

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
      payuRaw: null,
      promoCode: usedPromoCode,
      discountAmount
    });

    sseBroadcast("new_order", {
      extOrderId: saved.extOrderId,
      payuOrderId: null,
      totalPLN: saved.totalPLN,
      customer: saved.customer?.imieNazwisko || null,
      status: saved.status,
      paymentMethod: saved.paymentMethod
    });

    return res.json({ ok: true, orderId: saved.extOrderId, extOrderId: saved.extOrderId, status: saved.status });
  } catch (e) {
    console.log("OFFLINE ORDER ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("/api/orders/:extOrderId", async (req, res) => {
  try {
    const { extOrderId } = req.params;
    const order = await Order.findOne({ extOrderId }).lean();
    if (!order) return res.status(404).json({ error: "Order not found" });

    res.json({
      extOrderId: order.extOrderId,
      status: order.status,
      totalPLN: order.totalPLN,
      items: order.cart,
      paymentMethod: order.paymentMethod,
      timestamp: order.createdAt,
      customer: {
        imieNazwisko: order.customer?.imieNazwisko,
        miasto: order.customer?.miasto,
        ulica: order.customer?.ulica,
        deliveryTime: order.customer?.deliveryTime,
        fulfillmentMethod: order.customer?.fulfillmentMethod
      }
    });
  } catch (e) {
    console.log("GET ORDER ERROR:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/payu/order", async (req, res) => {
  try {
    requireEnv("PAYU_POS_ID", PAYU_POS_ID);
    requireEnv("PAYU_NOTIFY_URL", PAYU_NOTIFY_URL);
    requireEnv("PAYU_CONTINUE_URL", PAYU_CONTINUE_URL);

    const cartNorm = await validateAndBuildCart(req.body?.cart);

    let discountAmount = 0;
    let usedPromoCode = null;
    const productsValue = calcTotalProductsValue(cartNorm);

    if (req.body.promoCode) {
      const promo = await PromoCode.findOne({
        code: String(req.body.promoCode || "").toUpperCase(),
        isActive: true
      });

      if (
        promo &&
        new Date() <= promo.expiresAt &&
        (promo.usageLimit === null || promo.usedCount < promo.usageLimit)
      ) {
        discountAmount = Math.round(productsValue * (promo.discountPercent / 100));
        usedPromoCode = promo.code;
        await PromoCode.updateOne({ _id: promo._id }, { $inc: { usedCount: 1 } });
      }
    }

    const products = cartNorm.map((i) => {
      let name = i.name || "Pozycja";
      if (i.addons && i.addons.length > 0) {
        const addonNames = i.addons.map((a) => ADDONS_NAME_LIST[a.id] || a.label).join(", ");
        name += ` (+ ${addonNames})`;
      }
      return { name, unitPrice: String(i.unitEffectivePrice), quantity: String(i.qty) };
    });

    if (discountAmount > 0) {
      products.push({ name: `Rabat: ${usedPromoCode}`, unitPrice: String(-discountAmount), quantity: "1" });
    }

    const valueAfterDiscount = Math.max(0, productsValue - discountAmount);
    const deliveryCost = calcDeliveryCost(valueAfterDiscount);
    const totalAmount = valueAfterDiscount + deliveryCost;

    if (deliveryCost > 0) {
      products.push({ name: "Dostawa", unitPrice: String(deliveryCost), quantity: "1" });
    }

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
      cart: cartNorm,
      promoCode: usedPromoCode,
      discountAmount
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
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
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

    if (data?.orderId) await upsertOrderMongo({ extOrderId, payuOrderId: data.orderId });

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

app.post("/api/admin/login", async (req, res) => {
  try {
    const pin = String(req.body?.pin || "").trim();
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN must be 4 digits" });

    if (!ADMIN_PIN) return res.status(500).json({ error: "ADMIN_PIN not set" });

    if (pin === String(ADMIN_PIN)) {
      const token = signToken({ role: "admin", name: "Administrator", iat: Date.now() }, ADMIN_TOKEN_SECRET);
      return res.json({ token });
    }

    const h = hashPin(pin);
    const found = await Staff.findOne({ pinHash: h }).lean();
    if (!found) return res.status(401).json({ error: "Bad PIN" });

    const token = signToken(
      { role: "staff", name: found.name || "Pracownik", staffId: String(found._id), iat: Date.now() },
      ADMIN_TOKEN_SECRET
    );
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

    const revenueAgg = await Order.aggregate([
      { $match: { status: { $in: ["PAID", "COMPLETED", "Zrealizowane"] } } },
      { $group: { _id: null, sum: { $sum: "$totalPLN" } } }
    ]);
    const revenueTotal = Number(revenueAgg?.[0]?.sum || 0);

    const revenueTodayAgg = await Order.aggregate([
      { $match: { status: { $in: ["PAID", "COMPLETED", "Zrealizowane"] }, createdAt: { $gte: start, $lte: end } } },
      { $group: { _id: null, sum: { $sum: "$totalPLN" } } }
    ]);
    const revenueToday = Number(revenueTodayAgg?.[0]?.sum || 0);

    const usersTotal = await User.countDocuments({});

    res.json({ ordersTotal, ordersToday, revenueTotal, revenueToday, usersTotal });
  } catch (e) {
    console.log("ADMIN STATS ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

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

app.patch("/api/admin/orders/:extOrderId/status", requireStaff, async (req, res) => {
  try {
    const { extOrderId } = req.params;
    const { status } = req.body;

    if (!status) return res.status(400).json({ error: "Missing status" });

    const order = await Order.findOne({ extOrderId });
    if (!order) return res.status(404).json({ error: "Order not found" });

    order.status = status;
    await order.save();

    sseBroadcast("order_update", { type: "order_update", extOrderId, status });

    res.json({ ok: true, status });
  } catch (e) {
    console.log("ADMIN UPDATE STATUS ERROR:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/promocodes", requireStaff, async (req, res) => {
  try {
    const codes = await PromoCode.find({}).sort({ createdAt: -1 });
    res.json({ codes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/promocodes", requireStaff, async (req, res) => {
  try {
    const { code, discountPercent, durationMinutes, usageLimit } = req.body;

    if (!code || !discountPercent || !durationMinutes) return res.status(400).json({ error: "Brak wymaganych danych" });

    const expiresAt = new Date(Date.now() + Number(durationMinutes) * 60000);

    await PromoCode.create({
      code: String(code).toUpperCase(),
      discountPercent: Number(discountPercent),
      expiresAt,
      usageLimit: usageLimit ? Number(usageLimit) : null
    });

    res.json({ ok: true });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "Ten kod już istnieje" });
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/promocodes/:id", requireStaff, async (req, res) => {
  try {
    await PromoCode.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/admin/push", requireStaff, async (req, res) => {
  try {
    const title = String(req.body?.title || "").trim();
    const body = String(req.body?.body || "").trim();

    if (!title || !body) return res.status(400).json({ error: "Missing title or body" });

    const subscriptions = await PushSubscription.find({});

    const notificationPayload = JSON.stringify({
      title,
      body,
      icon: "/appicon.png",
      url: "https://eatmi.pl/#/"
    });

    const promises = subscriptions.map((sub) =>
      webpush.sendNotification(sub, notificationPayload).catch((err) => {
        if (err.statusCode === 410 || err.statusCode === 404) {
          return PushSubscription.deleteOne({ _id: sub._id });
        }
        console.error("[PUSH] Błąd wysyłki:", err.statusCode);
      })
    );

    await Promise.all(promises);

    res.json({ ok: true, count: subscriptions.length });
  } catch (e) {
    console.log("ADMIN PUSH ERROR:", e);
    res.status(500).json({ error: e.message || "Server error" });
  }
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

    res.json({ ok: true, staff: { id: String(item._id), name: item.name, role: item.role, createdAt: item.createdAt } });
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

app.get("/api/products/lunche", async (req, res) => {
  try {
    const products = await Product.find({ category: "lunch" }).lean();
    res.json({ lunche: products });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/products/lunche", requireStaff, async (req, res) => {
  try {
    const products = await Product.find({ category: "lunch" }).lean();
    res.json({ lunche: products });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/admin/products/lunche/:id", requireStaff, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, price, description, image } = req.body;

    const updated = await Product.findOneAndUpdate({ id }, { name, price, description, image }, { new: true });

    if (!updated) return res.status(404).json({ error: "Not found" });

    res.json({ ok: true, product: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const MGMT_SECRET_EFFECTIVE = MGMT_TOKEN_SECRET || ADMIN_TOKEN_SECRET;

const MGMT_STEP1_COOKIE = "eatmi_mgmt_step1";
const MGMT_STEP1_TTL_MS = 2 * 60 * 1000;
const MGMT_STEP1_MIN_WAIT_MS = 5 * 1000;

function parseCookies(req) {
  const header = String(req.headers.cookie || "");
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...rest] = part.split("=");
    if (!k) return;
    const key = k.trim();
    const val = rest.join("=").trim();
    if (!key) return;
    out[key] = decodeURIComponent(val || "");
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const { maxAge = 120, httpOnly = true, secure = true, sameSite = "Strict", path = "/" } = opts;

  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push(`Path=${path}`);
  parts.push(`Max-Age=${Math.floor(maxAge)}`);
  parts.push(`SameSite=${sameSite}`);
  if (httpOnly) parts.push("HttpOnly");
  if (secure) parts.push("Secure");

  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Strict; HttpOnly; Secure`);
}

function signMgmtStep1(ts) {
  const payload = { ts, rnd: crypto.randomBytes(8).toString("hex") };
  const b64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", MGMT_SECRET_EFFECTIVE).update(b64).digest("base64url");
  return `${b64}.${sig}`;
}

function verifyMgmtStep1(value) {
  const [b64, sig] = String(value || "").split(".");
  if (!b64 || !sig) return null;
  const check = crypto.createHmac("sha256", MGMT_SECRET_EFFECTIVE).update(b64).digest("base64url");
  if (check !== sig) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
    if (!payload?.ts) return null;
    return payload;
  } catch {
    return null;
  }
}

function signMgmtToken(payload) {
  const now = Date.now();
  const body = { ...payload, scope: "mgmt", iat: now, exp: now + 2 * 60 * 60 * 1000 };
  return signToken(body, MGMT_SECRET_EFFECTIVE);
}

function verifyMgmtToken(token) {
  const data = verifyToken(token, MGMT_SECRET_EFFECTIVE);
  if (!data) return null;
  if (data.scope !== "mgmt") return null;
  if (typeof data.exp === "number" && Date.now() > data.exp) return null;
  return data;
}

function requireMgmt(req, res, next) {
  const token = getBearer(req);
  const data = verifyMgmtToken(token);
  if (!data) return res.status(401).json({ error: "Unauthorized" });
  req.mgmt = data;
  next();
}

function splitFullName(fullName) {
  const s = String(fullName || "").trim();
  if (!s) return { firstName: "", lastName: "" };
  const parts = s.split(/\s+/).filter(Boolean);
  return { firstName: parts[0] || "", lastName: parts.slice(1).join(" ") };
}

function composeFullName(firstName, lastName, fallback = "") {
  const a = String(firstName || "").trim();
  const b = String(lastName || "").trim();
  const joined = [a, b].filter(Boolean).join(" ").trim();
  return joined || String(fallback || "").trim() || a || b || "";
}

function normalizePhone(v) {
  return String(v || "").trim();
}

function normalizeAddress(v) {
  return String(v || "").trim();
}

function buildAddressFromOrderCustomer(cust) {
  const c = cust || {};
  const parts = [c.ulica || c.street, c.nrBud || c.houseNumber, c.lokal || c.flatNumber].filter(Boolean);
  const line1 = parts.join(" ").trim();

  const line2Parts = [c.kod || c.zip, c.miasto || c.city].filter(Boolean);
  const line2 = line2Parts.join(" ").trim();

  const out = [line1, line2].filter(Boolean).join(", ").trim();
  return out;
}

async function getLatestOrderByEmail(email) {
  if (!email) return null;
  return Order.findOne({ "customer.email": email }).sort({ createdAt: -1 }).lean();
}

async function countOrdersByEmail(email) {
  if (!email) return 0;
  return Order.countDocuments({ "customer.email": email });
}

function publicUser(u) {
  if (!u) return null;
  const id = String(u._id);
  const split = splitFullName(u.fullName);
  const firstName = String(u.firstName || "").trim() || split.firstName;
  const lastName = String(u.lastName || "").trim() || split.lastName;
  const phone = String(u.phone || "").trim();
  const address = String(u.address || "").trim();

  return {
    id,
    _id: id,
    email: u.email,
    fullName: u.fullName,
    firstName,
    lastName,
    phone,
    address,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt
  };
}

app.post("/api/management/login-step1", async (req, res) => {
  try {
    requireEnv("MGMT_PASSWORD", MGMT_PASSWORD);
    const password = String(req.body?.password || "").trim();

    if (!password) return res.status(400).json({ ok: false, error: "Missing password" });
    if (password !== String(MGMT_PASSWORD)) return res.status(401).json({ ok: false, error: "Bad password" });

    const ts = Date.now();
    const signed = signMgmtStep1(ts);

    setCookie(res, MGMT_STEP1_COOKIE, signed, {
      maxAge: Math.floor(MGMT_STEP1_TTL_MS / 1000),
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/"
    });

    return res.json({ ok: true });
  } catch (e) {
    console.log("MGMT STEP1 ERROR:", e?.message, e);
    return res.status(500).json({ ok: false, error: e?.message || "Server error" });
  }
});

app.post("/api/management/login-step2", async (req, res) => {
  try {
    requireEnv("MGMT_PIN", MGMT_PIN);

    const pin = String(req.body?.pin || "").trim();
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN must be 4 digits" });

    const cookies = parseCookies(req);
    const step1 = verifyMgmtStep1(cookies[MGMT_STEP1_COOKIE]);

    if (!step1) return res.status(401).json({ error: "Step1 required" });

    const age = Date.now() - Number(step1.ts || 0);
    if (!Number.isFinite(age) || age < 0 || age > MGMT_STEP1_TTL_MS) {
      clearCookie(res, MGMT_STEP1_COOKIE);
      return res.status(401).json({ error: "Step1 expired" });
    }

    if (age < MGMT_STEP1_MIN_WAIT_MS) return res.status(429).json({ error: "Wait 5 seconds before PIN" });

    if (pin !== String(MGMT_PIN)) return res.status(401).json({ error: "Bad PIN" });

    clearCookie(res, MGMT_STEP1_COOKIE);

    const token = signMgmtToken({ role: "manager", name: "Management" });
    return res.json({ token });
  } catch (e) {
    console.log("MGMT STEP2 ERROR:", e?.message, e);
    return res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.post("/api/management/logout", (req, res) => {
  clearCookie(res, MGMT_STEP1_COOKIE);
  res.json({ ok: true });
});

app.get("/api/management/users", requireMgmt, async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 }).limit(2000).lean();

    const emails = users.map((u) => u.email).filter(Boolean);
    const agg = await Order.aggregate([
      { $match: { "customer.email": { $in: emails } } },
      { $group: { _id: "$customer.email", count: { $sum: 1 } } }
    ]);
    const mapCount = new Map(agg.map((x) => [String(x._id || "").toLowerCase(), Number(x.count || 0)]));

    const out = [];
    for (const u of users) {
      const pu = publicUser(u);
      const ordersCount = mapCount.get(String(pu.email || "").toLowerCase()) || 0;

      if ((!pu.phone || !pu.address) && ordersCount > 0) {
        const last = await getLatestOrderByEmail(pu.email);
        if (last?.customer) {
          if (!pu.phone) pu.phone = String(last.customer.telefon || last.customer.phone || "").trim();
          if (!pu.address) pu.address = buildAddressFromOrderCustomer(last.customer);
        }
      }

      out.push({ ...pu, ordersCount });
    }

    res.json({ users: out });
  } catch (e) {
    console.log("MGMT USERS LIST ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const user = await User.findById(id).lean();
    if (!user) return res.status(404).json({ error: "Not found" });

    const pu = publicUser(user);
    const ordersCount = await countOrdersByEmail(pu.email);

    if ((!pu.phone || !pu.address) && ordersCount > 0) {
      const last = await getLatestOrderByEmail(pu.email);
      if (last?.customer) {
        if (!pu.phone) pu.phone = String(last.customer.telefon || last.customer.phone || "").trim();
        if (!pu.address) pu.address = buildAddressFromOrderCustomer(last.customer);
      }
    }

    res.json({ user: { ...pu, ordersCount } });
  } catch (e) {
    console.log("MGMT USER GET ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.patch("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: "Not found" });

    const email = req.body?.email !== undefined ? normalizeEmail(req.body.email) : undefined;
    const firstName = req.body?.firstName !== undefined ? String(req.body.firstName || "").trim() : undefined;
    const lastName = req.body?.lastName !== undefined ? String(req.body.lastName || "").trim() : undefined;
    const phone = req.body?.phone !== undefined ? normalizePhone(req.body.phone) : undefined;
    const address = req.body?.address !== undefined ? normalizeAddress(req.body.address) : undefined;

    if (email !== undefined) {
      if (!email || !email.includes("@")) return res.status(400).json({ error: "Invalid email" });
      const exists = await User.findOne({ email, _id: { $ne: user._id } }).lean();
      if (exists) return res.status(409).json({ error: "Email already in use" });
      user.email = email;
    }

    if (firstName !== undefined) user.firstName = firstName;
    if (lastName !== undefined) user.lastName = lastName;
    if (phone !== undefined) user.phone = phone;
    if (address !== undefined) user.address = address;

    const fullNameNew = composeFullName(
      firstName !== undefined ? firstName : user.firstName,
      lastName !== undefined ? lastName : user.lastName,
      user.fullName
    );
    if (fullNameNew) user.fullName = fullNameNew;

    await user.save();

    const pu = publicUser(user.toObject());
    const ordersCount = await countOrdersByEmail(pu.email);
    res.json({ user: { ...pu, ordersCount } });
  } catch (e) {
    const msg = String(e?.message || "");
    if (msg.includes("E11000") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ error: "Email already in use" });
    }
    console.log("MGMT USER PATCH ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.post("/api/management/users/:id/password", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const newPassword = String(req.body?.newPassword || "");
    if (newPassword.length < 6) return res.status(400).json({ error: "Password too short (min 6)" });

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: "Not found" });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ ok: true });
  } catch (e) {
    console.log("MGMT USER PASS ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.delete("/api/management/users/:id", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const user = await User.findById(id).lean();
    if (!user) return res.status(404).json({ error: "Not found" });

    await User.deleteOne({ _id: id });

    res.json({ ok: true });
  } catch (e) {
    console.log("MGMT USER DELETE ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("/api/management/users/:id/orders", requireMgmt, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const user = await User.findById(id).lean();
    if (!user) return res.status(404).json({ error: "Not found" });

    const email = String(user.email || "").toLowerCase();
    if (!email) return res.json({ orders: [] });

    const orders = await Order.find({ "customer.email": email }).sort({ createdAt: -1 }).limit(1000).lean();

    res.json({ orders });
  } catch (e) {
    console.log("MGMT USER ORDERS ERROR:", e?.message, e);
    res.status(500).json({ error: e?.message || "Server error" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port", process.env.PORT || 3000);
});
