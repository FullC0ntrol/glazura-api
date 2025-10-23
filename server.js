import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import sharp from "sharp";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";
import "dotenv/config";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "secret123";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "haslo123";

const DATA_FILE = path.join(__dirname, "db.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");

// ====== POMOCNICZE FUNKCJE DB ======
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  } catch {
    return { albums: [] };
  }
}
function writeDB(db) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), "utf-8");
}

// Tworzymy foldery, jeśli nie istnieją
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) writeDB({ albums: [] });

// ====== EXPRESS ======
const app = express();
app.use(express.json());
app.use(cookieParser());

// ====== CORS ======
app.use(
  cors({
    origin: true, // dowolny localhost
    credentials: true,
  })
);

// ====== STATYCZNE ======
app.use("/uploads", express.static(UPLOAD_DIR));

// ====== AUTH ======
let ADMIN_HASH = await bcrypt.hash(ADMIN_PASS, 10);

function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}

app.post("/api/auth/login", async (req, res) => {
  const { user, pass } = req.body || {};
  if (user === ADMIN_USER && (await bcrypt.compare(pass, ADMIN_HASH))) {
    const token = jwt.sign({ user }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: "bad creds" });
});

// ====== ALBUMY ======

// Lista wszystkich albumów
app.get("/api/albums", requireAuth, (req, res) => {
  const db = readDB();
  res.json(db.albums);
});

// Tworzenie nowego albumu
app.post("/api/albums", requireAuth, (req, res) => {
  const db = readDB();
  const album = {
    id: nanoid(),
    title: req.body.title || "Nowa realizacja",
    images: [],
    published: false,
    createdAt: new Date().toISOString(),
  };
  db.albums.unshift(album);
  writeDB(db);
  res.json(album);
});

// Edycja albumu (np. zmiana tytułu)
app.patch("/api/albums/:id", requireAuth, (req, res) => {
  const db = readDB();
  const i = db.albums.findIndex((a) => a.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: "not found" });
  db.albums[i] = { ...db.albums[i], ...req.body };
  writeDB(db);
  res.json(db.albums[i]);
});

// ====== UPLOAD ZDJĘĆ DO ALBUMU ======
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
});

app.post("/api/albums/:id/photos", requireAuth, upload.array("files", 15), async (req, res) => {
  const db = readDB();
  const album = db.albums.find((a) => a.id === req.params.id);
  if (!album) return res.status(404).json({ error: "album not found" });

  const out = [];
  for (const f of req.files || []) {
    if (!["image/jpeg", "image/png", "image/webp"].includes(f.mimetype)) continue;

    const id = nanoid();
    const base = f.originalname.replace(/\s+/g, "_");
    const fullName = `${id}-${base}.webp`;
    const thumbName = `${id}-thumb-${base}.webp`;
    const fullPath = path.join(UPLOAD_DIR, fullName);
    const thumbPath = path.join(UPLOAD_DIR, thumbName);

    await sharp(f.buffer).webp({ quality: 85 }).toFile(fullPath);
    await sharp(f.buffer).resize(600).webp({ quality: 75 }).toFile(thumbPath);

    const rec = {
      id,
      fileUrl: `/uploads/${fullName}`,
      thumbUrl: `/uploads/${thumbName}`,
    };
    album.images.push(rec);
    out.push(rec);
  }

  writeDB(db);
  res.json(out);
});
app.delete("/api/photos/:id", (req, res) => {
  const id = req.params.id;
  const db = readDB();
  db.albums.forEach(a => {
    a.images = a.images.filter(img => img.id !== id);
  });
  writeDB(db);
  res.json({ ok: true });
});

app.delete("/api/albums/:id", (req, res) => {
  const id = req.params.id;
  const db = readDB();
  db.albums = db.albums.filter(a => a.id !== id);
  writeDB(db);
  res.json({ ok: true });
});

// Publiczne API dla strony głównej
app.get("/api/public/albums", (req, res) => {
  const db = readDB();
  res.json(db.albums.filter((a) => a.published));
});

app.listen(PORT, () => {
  console.log(`✅ API działa na http://localhost:${PORT}`);
});
