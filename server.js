import express from "express";
import path from "path";
import { fileURLToPath } from "url";

console.log("NODE VERSION:", process.version);

const app = express();
app.use(express.json({ limit: "1mb" }));

// ====== Serve static files from ROOT ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ====== PayU ENV ======
const {
  PAYU_ENV = "prod",            // "prod" albo "sandbox"
  PAYU_POS_ID,                  // pos_id (merchantPosId)
  PAYU_CLIENT_ID,               // OAuth client_id
  PAYU_CLIENT_SECRET,           // OAuth client_secret
  PAYU_MD5_SECOND_KEY,          // (na start nie używamy)
  PAYU_NOTIFY_URL,              // np. https://www.eatmi.pl/api/payu/notify
  PAYU_CONTINUE_URL             // np. https://www.eatmi.pl/#/zamowienie?paid=1
} = process.env;

const PAYU_BASE =
  PAYU_ENV === "sandbox" ? "https://secure.snd.payu.com" : "https://secure.payu.com";

function requireEnv(name, value) {
  if (!value) throw new Error(`Missing env var: ${name}`);
}

// ====== PRICE LIST (server-side truth) ======
// Ceny w GROSZACH
const PRICE_LIST = {
  // Boxy śniadaniowe
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

  // Lunche
  "lunch-week": 4900,
  "lunch-month": 5900,
  "lunch-vege": 4900,

  // Kanapki
  "k-jajecznica-bekon": 1700,
  "k-club-kurczak": 1700,
  "k-club-vege": 1700,
  "k-jajecznica-avo": 1700,
  "k-buritto-chorizo": 1900,
  "k-rostbef": 2100,

  // Zdrowe
  "z-granola": 1900,
  "z-cezar": 1900,
  "z-koreanska": 1900,
  "z-burak": 1900,

  // Słodkie
  "s-smoothie": 1900,
  "s-tost-fr": 1900,
  "s-pancakes": 1900,
  "s-deser-czeko": 1900,

  // Napoje
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

  // Extras
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
  try { data = JSON.parse(raw); } catch { data = {}; }
  if (!data?.access_token) {
    console.log("PAYU OAUTH BAD JSON:", raw);
    throw new Error("PayU OAuth: missing access_token");
  }

  return data; // { access_token, ... }
}

// ====== Create order ======
app.post("/api/payu/order", async (req, res) => {
  try {
    requireEnv("PAYU_POS_ID", PAYU_POS_ID);
    requireEnv("PAYU_NOTIFY_URL", PAYU_NOTIFY_URL);
    requireEnv("PAYU_CONTINUE_URL", PAYU_CONTINUE_URL);

    const cart = Array.isArray(req.body?.cart) ? req.body.cart : [];
    if (!cart.length) return res.status(400).json({ error: "Empty cart" });

    const products = cart.map((i) => {
      const productId = i.productId;
      const qty = Number(i.qty || 1);

      if (!productId || !PRICE_LIST[productId]) {
        throw new Error(`Unknown productId: ${productId}`);
      }
      if (!Number.isFinite(qty) || qty < 1 || qty > 50) {
        throw new Error(`Invalid qty for ${productId}`);
      }

      return {
        name: NAME_LIST[productId] || "Pozycja",
        unitPrice: String(PRICE_LIST[productId]), // grosze
        quantity: String(qty)
      };
    });

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

    // 🔥 KLUCZ: PayU potrafi zwrócić 302 + Location (redirectUri) -> fetch NIE MOŻE tego followować
    const r = await fetch(`${PAYU_BASE}/api/v2_1/orders`, {
      method: "POST",
      redirect: "manual", // ✅ IMPORTANT
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`
      },
      body: JSON.stringify(orderBody)
    });

    const location = r.headers.get("location") || r.headers.get("Location");

    // w razie gdy PayU jednak zwróci JSON (czasem zwraca)
    const raw = await r.text().catch(() => "");
    let data = null;
    if (raw) {
      try { data = JSON.parse(raw); } catch { data = { raw }; }
    }

    // ✅ Najczęstsza ścieżka: 302 + Location
    if ((r.status === 301 || r.status === 302 || r.status === 303) && location) {
      return res.json({
        redirectUri: location,
        orderId: data?.orderId || null,
        extOrderId
      });
    }

    // ✅ Druga ścieżka: 200/201 + JSON z redirectUri
    if (r.ok && data?.redirectUri) {
      return res.json({ redirectUri: data.redirectUri, orderId: data.orderId, extOrderId });
    }

    // ❌ Błędy / brak redirecta
    console.log("PAYU CREATE ORDER UNEXPECTED:", {
      status: r.status,
      location,
      data
    });

    return res.status(502).json({
      error: "PayU create order failed / no redirect",
      status: r.status,
      location: location || null,
      details: data
    });

  } catch (e) {
    console.log("PAYU ORDER ERROR:", e);
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// ====== Webhook from PayU ======
app.post("/api/payu/notify", (req, res) => {
  console.log("PAYU NOTIFY:", JSON.stringify(req.body));
  res.sendStatus(200);
});

// ✅ Debug endpoint (GET) - żeby w przeglądarce nie wracało na SPA
app.get("/api/payu/notify", (req, res) => {
  res.status(200).send("OK (PayU notify endpoint expects POST)");
});

// SPA fallback (hash-router)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port", process.env.PORT || 3000);
});
