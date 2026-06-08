require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { PrismaClient } = require("@prisma/client");
// In your backend - api/upload.js
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const app = express();
const prisma = new PrismaClient();

const DEFAULT_PHONE_CC = process.env.PHONE_DEFAULT_COUNTRY || "252";

function formatPhoneForWhatsApp(input) {
  const raw = String(input || "").trim();
  const formattedPhone = raw.replace(/\D/g, "");
  let cleanPhone = formattedPhone;
  if (!cleanPhone) return "";
  // International formats should be preserved:
  // +44..., +1..., 0044..., etc.
  if (raw.startsWith("+")) {
    return cleanPhone;
  }
  if (cleanPhone.startsWith("00")) {
    return cleanPhone.slice(2);
  }
  // Local format (e.g. 061...) => default country code.
  if (cleanPhone.startsWith("0")) {
    cleanPhone = DEFAULT_PHONE_CC + cleanPhone.substring(1);
  } else {
    // If number is short, treat as local and prepend default country code.
    // If long enough, assume it's already international digits.
    cleanPhone = cleanPhone.length <= 9 ? DEFAULT_PHONE_CC + cleanPhone : cleanPhone;
  }
  return cleanPhone;
}

function getPhoneCandidates(input) {
  const normalized = formatPhoneForWhatsApp(input);
  const digits = String(input || "").replace(/\D/g, "");
  const localFromNormalized =
    normalized && normalized.startsWith(DEFAULT_PHONE_CC)
      ? `0${normalized.slice(DEFAULT_PHONE_CC.length)}`
      : "";
  const localFromRaw = digits.startsWith("0") ? digits : "";
  const plusNormalized = normalized ? `+${normalized}` : "";
  return Array.from(
    new Set(
      [normalized, digits, plusNormalized, localFromNormalized, localFromRaw].filter(Boolean),
    ),
  );
}

function hasValidPhoneLength(input) {
  const digits = String(input || "").replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;
}

async function findUserByRegisteredPhone(phoneInput) {
  const target = formatPhoneForWhatsApp(phoneInput);
  if (!target || target.length < 8) return null;

  const candidates = getPhoneCandidates(phoneInput);
  let user = await prisma.user.findFirst({
    where: {
      phone: { in: candidates },
    },
    select: { id: true, phone: true, name: true, email: true },
  });
  if (user) return user;

  // Fallback for legacy rows with mixed formatting
  const users = await prisma.user.findMany({
    where: {
      AND: [{ phone: { not: null } }, { NOT: { phone: "" } }],
    },
    select: { id: true, phone: true, name: true, email: true },
  });
  user =
    users.find((u) => {
      const p = formatPhoneForWhatsApp(u.phone || "");
      return p === target;
    }) || null;
  return user;
}

// Configure multer for file upload
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

// App version config (in-memory; replace with DB if needed)
let appVersionConfig = {
  latestVersion: "1.0.0",
  minVersion: "1.0.0",
  androidUrl: "",
  iosUrl: "",
  forceUpdate: false,
  releaseNotes: "",
  updatedAt: new Date().toISOString(),
};

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    if (
      !email ||
      !password ||
      !name ||
      phone == null ||
      !String(phone).trim()
    ) {
      return res.status(400).json({
        error: "All fields are required, including phone number",
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    if (!normalizedEmail.includes("@")) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const normalizedPhone = formatPhoneForWhatsApp(String(phone).trim());
    if (!normalizedPhone || normalizedPhone.length < 10) {
      return res.status(400).json({ error: "A valid phone number is required" });
    }

    // 1. Check for existing user (email stored lowercase — matches login)
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // 2. Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Create the user (store email lowercase so login/register stay consistent)
    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: String(name).trim(),
        phone: normalizedPhone,
      },
    });

    // 4. Send response (excluding the password) — flat user object with id for mobile clients
    const { password: _, ...userWithoutPassword } = user;
    res.status(201).json(userWithoutPassword);
  } catch (error) {
    console.error("Registration error:", error);
    if (error.code === "P2002") {
      return res.status(400).json({ error: "Email already registered" });
    }
    res.status(500).json({
      error: "Registration failed. Please try again later.",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    let user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    // Legacy rows may have mixed-case email; match case-insensitively via LOWER()
    if (!user) {
      const rows = await prisma.$queryRaw`
        SELECT id FROM User WHERE LOWER(email) = ${normalizedEmail} LIMIT 1`;
      const legacyId = rows?.[0]?.id;
      if (legacyId != null) {
        user = await prisma.user.findUnique({ where: { id: Number(legacyId) } });
      }
    }
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed. Please try again later." });
  }
});

// --- Email Config (from DB or env, default: ismaalnet@gmail.com) ---
async function getEmailConfig() {
  try {
    const config = await prisma.systemConfig.findUnique({
      where: { key: "email_config" },
    });
    if (config && config.value) {
      return JSON.parse(config.value);
    }
  } catch (e) {
    console.warn("Email config from DB failed, using env:", e.message);
  }
  return {
    fromEmail: process.env.EMAIL_FROM || "ismaalnet@gmail.com",
    smtpHost: process.env.SMTP_HOST || "smtp.gmail.com",
    smtpPort: parseInt(process.env.SMTP_PORT || "587", 10),
    smtpUser: process.env.SMTP_USER || "ismaalnet@gmail.com",
    smtpPass: process.env.SMTP_PASS || "",
    resetBaseUrl: process.env.RESET_PASSWORD_URL || "https://ismaal.taamsolutions.net",
  };
}

function createEmailTransporter(config) {
  return nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpPort === 465,
    auth: config.smtpUser && config.smtpPass ? {
      user: config.smtpUser,
      pass: config.smtpPass,
    } : undefined,
  });
}

// --- Forgot password via WhatsApp (Bawa) — same pattern as libaax-fitness /api/whatsapp/send ---
// Prefer BAWA_TOKEN / BAWA_INSTANCE_ID in .env; fallbacks are the Ismaal Bawa client (rotate via env).
const BAWA_FALLBACK_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiJIaU9YbnJuRmxRTkI2a2Y4UjNHOWlJSDI0WU1xRGhDMiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzYxNTc0MjMwfQ.-l0jsppJn0tST-Yeq0lJz_NGKTL34or9oUUqohnUqnw";
const BAWA_FALLBACK_INSTANCE_ID =
  "eyJ1aWQiOiJIaU9YbnJuRmxRTkI2a2Y4UjNHOWlJSDI0WU1xRGhDMiIsImNsaWVudF9pZCI6IklzbWFhbCJ9";

function generateNumericCode(length = 6) {
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return String(Math.floor(min + Math.random() * (max - min + 1)));
}

function maskPhoneNumber(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (!digits) return "your phone";
  if (digits.length <= 4) return `****${digits}`;
  return `${"*".repeat(Math.min(digits.length - 4, 6))}${digits.slice(-4)}`;
}

async function sendBawaWhatsAppText(whatsappDigits, message) {
  const token = (process.env.BAWA_TOKEN || "").trim() || BAWA_FALLBACK_TOKEN;
  const instanceId =
    (process.env.BAWA_INSTANCE_ID || "").trim() || BAWA_FALLBACK_INSTANCE_ID;
  if (!token || !instanceId) {
    throw new Error("Bawa is not configured (BAWA_TOKEN / BAWA_INSTANCE_ID)");
  }
  const jid = `${whatsappDigits}@s.whatsapp.net`;
  const apiUrl = `https://bawa.app/api/v1/send-text?token=${token}&instance_id=${instanceId}&jid=${jid}&msg=${encodeURIComponent(
    message,
  )}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(apiUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": "IsmaalBackend/1.0",
      },
      signal: controller.signal,
    });

    const contentType = response.headers.get("content-type") || "";
    let responseData;
    if (contentType.includes("application/json")) {
      responseData = await response.json();
    } else {
      const textResponse = await response.text();
      try {
        responseData = JSON.parse(textResponse);
      } catch {
        responseData = {
          status: response.ok ? "success" : "error",
          rawResponse: textResponse,
          statusCode: response.status,
        };
      }
    }

    const bawaOk =
      response.ok &&
      (responseData?.status === "success" || responseData?.success === true);
    if (!bawaOk) {
      const detail =
        responseData?.message ||
        responseData?.error ||
        `HTTP ${response.status}: ${response.statusText || ""}`;
      throw new Error(detail);
    }
    return true;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Request timeout - Bawa API took too long to respond");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function sendBawaPasswordResetCode(whatsappDigits, plainCode) {
  const message = `Your Ismaal password reset code is: ${plainCode}. It expires in 15 minutes. If you did not request this, ignore this message.`;
  return sendBawaWhatsAppText(whatsappDigits, message);
}

async function sendBawaLoginVerificationCode(whatsappDigits, plainCode) {
  const message = `Your Ismaal admin login verification code is: ${plainCode}. It expires in 10 minutes. If you did not request this, ignore this message.`;
  return sendBawaWhatsAppText(whatsappDigits, message);
}

const LOGIN_CODE_TTL_MS = 10 * 60 * 1000;

async function issueLoginVerificationCode(user) {
  if (!user.phone || !String(user.phone).trim()) {
    const err = new Error(
      "No phone number on this admin account. Please add a phone number before logging in.",
    );
    err.statusCode = 400;
    throw err;
  }

  await prisma.loginVerificationToken.updateMany({
    where: { userId: user.id, used: false },
    data: { used: true },
  });

  const plainCode = generateNumericCode(6);
  const tokenHash = await bcrypt.hash(plainCode, 10);
  const expiresAt = new Date(Date.now() + LOGIN_CODE_TTL_MS);

  const verificationRow = await prisma.loginVerificationToken.create({
    data: {
      userId: user.id,
      token: tokenHash,
      expiresAt,
    },
  });

  const waPhone = formatPhoneForWhatsApp(user.phone);
  try {
    await sendBawaLoginVerificationCode(waPhone, plainCode);
  } catch (bawaErr) {
    await prisma.loginVerificationToken
      .delete({ where: { id: verificationRow.id } })
      .catch(() => {});
    throw bawaErr;
  }

  return maskPhoneNumber(user.phone);
}

async function findUserByNormalizedEmail(email) {
  const normalizedEmail = String(email).trim().toLowerCase();
  let user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });
  if (!user) {
    const rows = await prisma.$queryRaw`
      SELECT id FROM User WHERE LOWER(email) = ${normalizedEmail} LIMIT 1`;
    const legacyId = rows?.[0]?.id;
    if (legacyId != null) {
      user = await prisma.user.findUnique({ where: { id: Number(legacyId) } });
    }
  }
  return user;
}

async function verifyLoginCodeForUser(user, codeTrim) {
  const verificationRow = await prisma.loginVerificationToken.findFirst({
    where: {
      userId: user.id,
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: "desc" },
  });

  if (!verificationRow || !String(verificationRow.token).startsWith("$2")) {
    return false;
  }

  return bcrypt.compare(codeTrim, verificationRow.token).then(async (match) => {
    if (!match) return false;
    await prisma.loginVerificationToken.update({
      where: { id: verificationRow.id },
      data: { used: true },
    });
    return true;
  });
}

// POST /api/auth/forgot-password — sends a 6-digit code via Bawa WhatsApp
app.post("/api/auth/forgot-password", async (req, res) => {
  const successMessage =
    "If an account exists with this phone number, you will receive a verification code on WhatsApp shortly.";
  try {
    const rawPhone =
      req.body.phone ??
      req.body.phoneNumber ??
      req.body.mobile ??
      req.body.msisdn;
    if (!rawPhone || !String(rawPhone).trim()) {
      return res.status(400).json({ error: "Phone number is required" });
    }
    if (!hasValidPhoneLength(rawPhone)) {
      return res
        .status(400)
        .json({ error: "Phone number must be between 8 and 15 digits" });
    }

    const user = await findUserByRegisteredPhone(rawPhone);
    if (!user) {
      return res.json({ success: true, message: successMessage });
    }

    await prisma.passwordResetToken.updateMany({
      where: { userId: user.id, used: false },
      data: { used: true },
    });

    const plainCode = generateNumericCode(6);
    const tokenHash = await bcrypt.hash(plainCode, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    const resetRow = await prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        token: tokenHash,
        expiresAt,
      },
    });

    // Prefer sending to the verified/registered phone from DB (more reliable than raw input).
    const waPhone = formatPhoneForWhatsApp(user.phone || rawPhone);
    try {
      await sendBawaPasswordResetCode(waPhone, plainCode);
    } catch (bawaErr) {
      console.error("Bawa send error:", bawaErr);
      await prisma.passwordResetToken.delete({ where: { id: resetRow.id } }).catch(() => {});
      return res.status(502).json({
        error: "Could not send verification code. Please try again later or contact support.",
        details: String(bawaErr?.message || "Bawa send failed"),
      });
    }

    return res.json({ success: true, message: successMessage });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// POST /api/auth/reset-password — WhatsApp code + new password, or legacy email token
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, phone, code, newPassword } = req.body;
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const phoneTrim = phone != null ? String(phone).trim() : "";
    const codeTrim = code != null ? String(code).trim() : "";

    if (phoneTrim && !hasValidPhoneLength(phoneTrim)) {
      return res
        .status(400)
        .json({ error: "Phone number must be between 8 and 15 digits" });
    }
    if (phoneTrim && !codeTrim) {
      return res.status(400).json({ error: "Verification code is required" });
    }
    if (!phoneTrim && codeTrim) {
      return res.status(400).json({ error: "Phone number is required" });
    }

    if (phoneTrim && codeTrim) {
      const user = await findUserByRegisteredPhone(phoneTrim);
      if (!user) {
        return res.status(400).json({ error: "Invalid or expired verification code" });
      }

      const resetRow = await prisma.passwordResetToken.findFirst({
        where: {
          userId: user.id,
          used: false,
          expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: "desc" },
      });

      if (!resetRow || !String(resetRow.token).startsWith("$2")) {
        return res.status(400).json({ error: "Invalid or expired verification code" });
      }

      const match = await bcrypt.compare(codeTrim, resetRow.token);
      if (!match) {
        return res.status(400).json({ error: "Invalid or expired verification code" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await prisma.$transaction([
        prisma.user.update({
          where: { id: user.id },
          data: { password: hashedPassword },
        }),
        prisma.passwordResetToken.update({
          where: { id: resetRow.id },
          data: { used: true },
        }),
      ]);

      return res.json({
        success: true,
        message: "Password has been reset successfully. You can now log in.",
      });
    }

    if (!token || !String(token).trim()) {
      return res.status(400).json({
        error: "Provide phone and verification code with new password, or a reset token",
      });
    }

    const resetToken = await prisma.passwordResetToken.findUnique({
      where: { token: String(token).trim() },
      include: { user: true },
    });

    if (!resetToken) {
      return res.status(400).json({ error: "Invalid or expired reset link" });
    }
    if (resetToken.used) {
      return res.status(400).json({ error: "This reset link has already been used" });
    }
    if (new Date() > resetToken.expiresAt) {
      return res.status(400).json({ error: "Reset link has expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.$transaction([
      prisma.user.update({
        where: { id: resetToken.userId },
        data: { password: hashedPassword },
      }),
      prisma.passwordResetToken.update({
        where: { id: resetToken.id },
        data: { used: true },
      }),
    ]);

    return res.json({
      success: true,
      message: "Password has been reset successfully. You can now log in.",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// App version endpoints
app.get("/api/app-version", (req, res) => {
  res.json(appVersionConfig);
});

// GET /api/admin/email-config (Admin only)
app.get("/api/admin/email-config", async (req, res) => {
  try {
    const userId = req.headers["x-user-id"];
    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const adminUser = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      select: { role: true },
    });
    if (!adminUser || adminUser.role !== "ADMIN") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const config = await getEmailConfig();
    res.json({
      fromEmail: config.fromEmail,
      smtpHost: config.smtpHost,
      smtpPort: config.smtpPort,
      smtpUser: config.smtpUser,
      smtpPassMasked: config.smtpPass ? "********" : "",
      resetBaseUrl: config.resetBaseUrl,
    });
  } catch (error) {
    console.error("Get email config error:", error);
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/admin/email-config (Admin only)
app.put("/api/admin/email-config", async (req, res) => {
  try {
    const userId = req.headers["x-user-id"];
    if (!userId) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const adminUser = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      select: { role: true },
    });
    if (!adminUser || adminUser.role !== "ADMIN") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { fromEmail, smtpHost, smtpPort, smtpUser, smtpPass, resetBaseUrl } = req.body || {};
    const current = await getEmailConfig();
    const updated = {
      fromEmail: fromEmail ?? current.fromEmail,
      smtpHost: smtpHost ?? current.smtpHost,
      smtpPort: smtpPort ?? current.smtpPort,
      smtpUser: smtpUser ?? current.smtpUser,
      smtpPass: smtpPass !== undefined && smtpPass !== "" ? smtpPass : current.smtpPass,
      resetBaseUrl: resetBaseUrl ?? current.resetBaseUrl,
    };

    await prisma.systemConfig.upsert({
      where: { key: "email_config" },
      create: { key: "email_config", value: JSON.stringify(updated) },
      update: { value: JSON.stringify(updated) },
    });

    res.json({
      success: true,
      fromEmail: updated.fromEmail,
      smtpHost: updated.smtpHost,
      smtpPort: updated.smtpPort,
      smtpUser: updated.smtpUser,
      smtpPassMasked: updated.smtpPass ? "********" : "",
      resetBaseUrl: updated.resetBaseUrl,
    });
  } catch (error) {
    console.error("Update email config error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/app-version", (req, res) => {
  const {
    latestVersion,
    minVersion,
    androidUrl,
    iosUrl,
    forceUpdate,
    releaseNotes,
  } = req.body || {};

  if (!latestVersion || !minVersion) {
    return res.status(400).json({
      error: "latestVersion and minVersion are required",
    });
  }

  appVersionConfig = {
    latestVersion,
    minVersion,
    androidUrl: androidUrl || "",
    iosUrl: iosUrl || "",
    forceUpdate: Boolean(forceUpdate),
    releaseNotes: releaseNotes || "",
    updatedAt: new Date().toISOString(),
  };

  res.json(appVersionConfig);
});

// --- Lookup: cities & categories (public read, admin CRUD) ---
const LOOKUP_CATEGORY_TYPES = new Set(["business", "product", "profession"]);

async function getAdminUserOrError(req) {
  const userIdRaw = req.headers["x-user-id"];
  if (!userIdRaw) {
    return { status: 401, error: "Authentication required" };
  }
  const userId = parseInt(String(userIdRaw), 10);
  if (Number.isNaN(userId) || userId <= 0) {
    return { status: 401, error: "Authentication required" };
  }
  const adminUser = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true },
  });
  if (!adminUser || adminUser.role !== "ADMIN") {
    return { status: 403, error: "Admin access required" };
  }
  return { userId };
}

// Public (mobile app & site)
app.get("/api/cities", async (req, res) => {
  try {
    const rows = await prisma.lookupCity.findMany({
      where: { active: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    });
    res.json(rows);
  } catch (error) {
    console.error("GET /api/cities", error);
    res.status(500).json({ error: "Failed to load cities" });
  }
});

app.get("/api/categories", async (req, res) => {
  try {
    const type = String(req.query.type || "").toLowerCase();
    if (!LOOKUP_CATEGORY_TYPES.has(type)) {
      return res.status(400).json({
        error:
          "Query parameter type is required and must be business, product, or profession",
      });
    }
    const rows = await prisma.lookupCategory.findMany({
      where: { type, active: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    });
    res.json(rows);
  } catch (error) {
    console.error("GET /api/categories", error);
    res.status(500).json({ error: "Failed to load categories" });
  }
});

// Admin — cities
app.get("/api/admin/cities", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const includeInactive =
      req.query.includeInactive === "1" || req.query.includeInactive === "true";
    const rows = await prisma.lookupCity.findMany({
      where: includeInactive ? {} : { active: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    });
    res.json(rows);
  } catch (error) {
    console.error("GET /api/admin/cities", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/admin/cities", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const { name, sortOrder, active } = req.body || {};
    const trimmed = String(name || "").trim();
    if (!trimmed) {
      return res.status(400).json({ error: "name is required" });
    }
    const row = await prisma.lookupCity.create({
      data: {
        name: trimmed,
        sortOrder: Number.isFinite(Number(sortOrder)) ? Number(sortOrder) : 0,
        active: active !== false,
      },
    });
    res.status(201).json(row);
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(400).json({ error: "A city with this name already exists" });
    }
    console.error("POST /api/admin/cities", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/admin/cities/:id", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }
    const { name, sortOrder, active } = req.body || {};
    const data = {};
    if (name !== undefined) data.name = String(name).trim();
    if (sortOrder !== undefined) {
      data.sortOrder = Number.isFinite(Number(sortOrder)) ? Number(sortOrder) : 0;
    }
    if (active !== undefined) data.active = Boolean(active);
    if (data.name === "") {
      return res.status(400).json({ error: "name cannot be empty" });
    }
    const row = await prisma.lookupCity.update({
      where: { id },
      data,
    });
    res.json(row);
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({ error: "City not found" });
    }
    if (error.code === "P2002") {
      return res.status(400).json({ error: "A city with this name already exists" });
    }
    console.error("PUT /api/admin/cities/:id", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/admin/cities/:id", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }
    await prisma.lookupCity.delete({ where: { id } });
    res.json({ success: true });
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({ error: "City not found" });
    }
    console.error("DELETE /api/admin/cities/:id", error);
    res.status(500).json({ error: error.message });
  }
});

// Admin — categories
app.get("/api/admin/categories", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const type = String(req.query.type || "").toLowerCase();
    if (!LOOKUP_CATEGORY_TYPES.has(type)) {
      return res.status(400).json({
        error: "Query parameter type is required (business, product, or profession)",
      });
    }
    const includeInactive =
      req.query.includeInactive === "1" || req.query.includeInactive === "true";
    const rows = await prisma.lookupCategory.findMany({
      where: includeInactive ? { type } : { type, active: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    });
    res.json(rows);
  } catch (error) {
    console.error("GET /api/admin/categories", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/admin/categories", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const { name, type, sortOrder, active } = req.body || {};
    const t = String(type || "").toLowerCase();
    if (!LOOKUP_CATEGORY_TYPES.has(t)) {
      return res.status(400).json({
        error: "type must be business, product, or profession",
      });
    }
    const trimmed = String(name || "").trim();
    if (!trimmed) {
      return res.status(400).json({ error: "name is required" });
    }
    const row = await prisma.lookupCategory.create({
      data: {
        name: trimmed,
        type: t,
        sortOrder: Number.isFinite(Number(sortOrder)) ? Number(sortOrder) : 0,
        active: active !== false,
      },
    });
    res.status(201).json(row);
  } catch (error) {
    if (error.code === "P2002") {
      return res
        .status(400)
        .json({ error: "A category with this name already exists for this type" });
    }
    console.error("POST /api/admin/categories", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/admin/categories/:id", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }
    const { name, type, sortOrder, active } = req.body || {};
    const data = {};
    if (name !== undefined) data.name = String(name).trim();
    if (type !== undefined) {
      const t = String(type).toLowerCase();
      if (!LOOKUP_CATEGORY_TYPES.has(t)) {
        return res.status(400).json({
          error: "type must be business, product, or profession",
        });
      }
      data.type = t;
    }
    if (sortOrder !== undefined) {
      data.sortOrder = Number.isFinite(Number(sortOrder)) ? Number(sortOrder) : 0;
    }
    if (active !== undefined) data.active = Boolean(active);
    if (data.name === "") {
      return res.status(400).json({ error: "name cannot be empty" });
    }
    const row = await prisma.lookupCategory.update({
      where: { id },
      data,
    });
    res.json(row);
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({ error: "Category not found" });
    }
    if (error.code === "P2002") {
      return res
        .status(400)
        .json({ error: "A category with this name already exists for this type" });
    }
    console.error("PUT /api/admin/categories/:id", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/admin/categories/:id", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "Invalid id" });
    }
    await prisma.lookupCategory.delete({ where: { id } });
    res.json({ success: true });
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({ error: "Category not found" });
    }
    console.error("DELETE /api/admin/categories/:id", error);
    res.status(500).json({ error: error.message });
  }
});

// Admin Login - Step 1: validate credentials, send 6-digit WhatsApp code
app.post("/api/auth/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await findUserByNormalizedEmail(email);

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (user.role !== "ADMIN") {
      return res.status(403).json({
        error: "Access denied. Admin privileges required.",
      });
    }

    let maskedPhone;
    try {
      maskedPhone = await issueLoginVerificationCode(user);
    } catch (sendErr) {
      console.error("Admin login WhatsApp send error:", sendErr);
      const status = sendErr.statusCode || 502;
      return res.status(status).json({
        error:
          sendErr.message ||
          "Could not send verification code. Please try again later.",
      });
    }

    res.json({
      requiresVerification: true,
      email: user.email,
      maskedPhone,
      message: `A 6-digit verification code has been sent to your WhatsApp (${maskedPhone}).`,
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

// Admin Login - Step 2: verify WhatsApp code and complete login
app.post("/api/auth/admin/verify-login", async (req, res) => {
  try {
    const { email, code } = req.body;
    const codeTrim = code != null ? String(code).trim() : "";

    if (!email || !codeTrim) {
      return res
        .status(400)
        .json({ error: "Email and verification code are required" });
    }

    if (!/^\d{6}$/.test(codeTrim)) {
      return res
        .status(400)
        .json({ error: "Verification code must be exactly 6 digits" });
    }

    const user = await findUserByNormalizedEmail(email);

    if (!user || user.role !== "ADMIN") {
      return res.status(400).json({ error: "Invalid or expired verification code" });
    }

    const isValid = await verifyLoginCodeForUser(user, codeTrim);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid or expired verification code" });
    }

    const { password: _, ...userWithoutPassword } = user;

    res.json({
      user: userWithoutPassword,
      message: "Admin login successful",
    });
  } catch (error) {
    console.error("Admin verify-login error:", error);
    res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// Admin Login - resend WhatsApp verification code
app.post("/api/auth/admin/resend-login-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await findUserByNormalizedEmail(email);

    if (!user || user.role !== "ADMIN") {
      return res.json({
        success: true,
        message:
          "If your account is eligible, a new verification code has been sent to your WhatsApp.",
      });
    }

    let maskedPhone;
    try {
      maskedPhone = await issueLoginVerificationCode(user);
    } catch (sendErr) {
      console.error("Admin resend login code error:", sendErr);
      const status = sendErr.statusCode || 502;
      return res.status(status).json({
        error:
          sendErr.message ||
          "Could not send verification code. Please try again later.",
      });
    }

    res.json({
      success: true,
      maskedPhone,
      message: `A new 6-digit verification code has been sent to your WhatsApp (${maskedPhone}).`,
    });
  } catch (error) {
    console.error("Admin resend-login-code error:", error);
    res.status(500).json({ error: "Could not resend code. Please try again." });
  }
});

// Delete account permanently
app.delete("/api/auth/account", async (req, res) => {
  try {
    const { userId } = req.body;

    // Validate userId is provided
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "User ID is required",
      });
    }

    // Parse and validate userId is a valid integer
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt) || userIdInt <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid user ID format",
      });
    }

    // Find the user first to check if they exist
    const user = await prisma.user.findUnique({
      where: { id: userIdInt },
      select: {
        id: true,
        fullName: true,
        email: true,
        phone: true,
        role: true,
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Prevent deletion of admin users (safety check)
    if (user.role === "ADMIN") {
      return res.status(403).json({
        success: false,
        error: "Cannot delete admin users",
      });
    }

    console.log(
      `🗑️  Starting deletion process for user ID: ${userIdInt} (${user.fullName})`,
    );

    // Start a transaction to delete all related data atomically
    await prisma.$transaction(async (tx) => {
      // Delete user's sessions/tokens if they exist
      try {
        const deletedSessions = await tx.session.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedSessions.count} session(s)`);
      } catch (e) {
        // Session table might not exist, ignore error
        console.log(`ℹ️  Sessions table not found or already deleted`);
      }

      // Delete user's blood requests
      try {
        const deletedRequests = await tx.bloodRequest.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedRequests.count} blood request(s)`);
      } catch (e) {
        console.log(`ℹ️  Blood requests not found or already deleted`);
      }

      // Delete user's donations (as donor)
      try {
        const deletedDonations = await tx.donation.deleteMany({
          where: { donorId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedDonations.count} donation(s)`);
      } catch (e) {
        console.log(`ℹ️  Donations not found or already deleted`);
      }

      // Delete user's notifications
      try {
        const deletedNotifications = await tx.userNotification.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedNotifications.count} notification(s)`);
      } catch (e) {
        console.log(`ℹ️  Notifications not found or already deleted`);
      }

      // Delete user's history if exists
      try {
        const deletedHistory = await tx.userHistory.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedHistory.count} history record(s)`);
      } catch (e) {
        console.log(`ℹ️  User history not found or already deleted`);
      }

      // Finally delete the user
      await tx.user.delete({
        where: { id: userIdInt },
      });
      console.log(`✅ User deleted successfully`);
    });

    console.log(`✅ Account deletion completed for user ID: ${userIdInt}`);

    res.json({
      success: true,
      message: "Account deleted permanently",
      deletedUser: {
        id: user.id,
        name: user.fullName,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Error deleting account:", error);

    // Handle Prisma specific errors
    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Handle foreign key constraint errors
    if (error.code === "P2003") {
      return res.status(400).json({
        success: false,
        error: "Cannot delete user due to existing relationships",
        details: "Please remove all related data first",
      });
    }

    res.status(500).json({
      success: false,
      error: "Failed to delete account",
      details: error.message,
    });
  }
});

// Admin authentication route
app.post("/api/auth/admin-login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    if (user.role !== "ADMIN") {
      return res
        .status(403)
        .json({ error: "Access denied. Admin privileges required." });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Business routes
const validateBusinessData = (data) => {
  const required = [
    "name",
    "description",
    "category",
    "phone",
    "email",
    "location",
    "businessType",
    "ownerId",
  ];
  for (const field of required) {
    if (!data[field]) return `${field} is required`;
  }
  return null;
};

// Business routes
const validatedPlanData = (data) => {
  const required = [
    "name",
    "description",
    "priceMonthly",
    "priceYearly",
    "allowedBusinesses",
    "allowedProducts",
    "profile_status",
  ];

  for (const field of required) {
    // Special handling for prices since 0 is a valid value but falsy
    if (field === "priceMonthly" || field === "priceYearly") {
      if (data[field] === undefined || data[field] === null) {
        return `${field} is required`;
      }
    }
    // allowedBusinesses / allowedProducts: 0 is valid (same falsy issue as prices)
    else if (field === "allowedBusinesses" || field === "allowedProducts") {
      if (data[field] === undefined || data[field] === null || data[field] === "") {
        return `${field} is required`;
      }
      const n = Number(data[field]);
      if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
        return `${field} must be a non-negative integer`;
      }
    }
    // For other fields, check if they exist and have truthy values
    else if (!data[field]) {
      return `${field} is required`;
    }
  }
  if (
    data.allowProfessionalPublish !== undefined &&
    typeof data.allowProfessionalPublish !== "boolean"
  ) {
    return "allowProfessionalPublish must be a boolean";
  }
  return null;
};

const isAdmin = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true },
  });
  return user?.role === "ADMIN";
};

/** True if x-user-id refers to an ADMIN user (for dashboard / PATCH overrides). */
const requestUserIsAdmin = async (req) => {
  const id = parseInt(String(req.headers["x-user-id"] || ""), 10);
  if (Number.isNaN(id) || id <= 0) return false;
  return isAdmin(id);
};

const LISTING_STATUS = new Set([
  "PENDING",
  "APPROVED",
  "REJECTED",
  "ACTIVE",
  "INACTIVE",
]);

app.post("/api/upload", upload.array("images"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No image files provided" });
    }

    // Log file details for debugging
    req.files.forEach((file, index) => {
      console.log(`[UPLOAD] File ${index + 1}:`, {
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
        fieldname: file.fieldname,
      });
    });

    const uploadPromises = req.files.map((file) => {
      // Convert buffer to base64 Data URI
      const b64 = Buffer.from(file.buffer).toString("base64");
      const dataURI = "data:" + file.mimetype + ";base64," + b64;

      return cloudinary.uploader.upload(dataURI, {
        folder: "caafiCare",
        resource_type: "auto",
      });
    });

    const results = await Promise.all(uploadPromises);

    console.log(
      `[UPLOAD] Cloudinary success: ${results.length} files uploaded.`,
    );

    res.json(
      results.map((result) => ({
        imageUrl: result.secure_url,
        publicId: result.public_id,
      })),
    );
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      error: error.message || "Failed to upload images to Cloudinary",
    });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        location: true,
        description: true,
        role: true,
        plan_id: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: {
            businesses: true,
            products: true,
          },
        },
        professional: {
          select: {
            id: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    // Get plan details for each user
    const usersWithPlans = await Promise.all(
      users.map(async (user) => {
        let plan = null;
        if (user.plan_id) {
          plan = await prisma.plans.findUnique({
            where: { id: user.plan_id },
            select: {
              id: true,
              name: true,
              price: true,
              allowedBusinesses: true,
              allowedProducts: true,
            },
          });
        }
        return {
          ...user,
          plan,
          // Add professional count (0 or 1 since it's a single relation)
          _count: {
            ...user._count,
            professionals: user.professional ? 1 : 0,
          },
        };
      }),
    );

    res.json(usersWithPlans);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        location: true,
        image: true,
        description: true,
        role: true,
        plan_id: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: {
            businesses: true,
            products: true,
          },
        },
        professional: {
          select: {
            id: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get plan details
    let plan = null;
    if (user.plan_id) {
      plan = await prisma.plans.findUnique({
        where: { id: user.plan_id },
        select: {
          id: true,
          name: true,
          price: true,
          allowedBusinesses: true,
          allowedProducts: true,
        },
      });
    }

    res.json({
      ...user,
      plan,
      _count: {
        ...user._count,
        professionals: user.professional ? 1 : 0,
      },
    });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId) || userId <= 0) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Prevent deletion of admin users (optional safety check)
    if (user.role === "ADMIN") {
      return res.status(403).json({ error: "Cannot delete admin users" });
    }

    // Delete user and all related data using transaction
    // Order matters: delete children before parent (respect foreign keys)
    await prisma.$transaction(async (tx) => {
      // 1. Delete user's plan upgrade requests
      await tx.planUpgradeRequest.deleteMany({
        where: { userId: userId },
      });

      // 2. Delete user's transactions
      await tx.transaction.deleteMany({
        where: { userId: userId },
      });

      // 3. Delete user's professional (one-to-one)
      await tx.professional.deleteMany({
        where: { userId: userId },
      });

      // 4. Delete user's products
      await tx.product.deleteMany({
        where: { userId: userId },
      });

      // 5. Delete user's businesses
      await tx.business.deleteMany({
        where: { ownerId: userId },
      });

      // 6. Finally delete the user
      await tx.user.delete({
        where: { id: userId },
      });
    });

    res.json({
      success: true,
      message: "User and all related data deleted successfully",
      deletedUser: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Error deleting user:", error);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);

    // Handle Prisma specific errors
    if (error.code === "P2025") {
      return res.status(404).json({ error: "User not found" });
    }

    // Handle foreign key constraint errors
    if (error.code === "P2003") {
      return res.status(400).json({
        error: "Cannot delete user due to existing relationships",
        details: "Please remove all related data first",
      });
    }

    // Handle transaction errors
    if (error.code === "P2034") {
      return res.status(500).json({
        error: "Transaction failed",
        details: error.message,
      });
    }

    res.status(500).json({
      error: "Failed to delete user",
      details: error.message,
    });
  }
});

// Backend: Single Image Upload API (POST /api/upload/single)

// Multer now uses upload.single() and expects a field named "image"
app.post("/api/upload/single", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" });
    }

    // Log file details for debugging
    console.log(`[UPLOAD] File:`, {
      originalname: req.file.originalname,
      size: req.file.size,
    });

    // Convert buffer to base64 Data URI
    const b64 = Buffer.from(req.file.buffer).toString("base64");
    const dataURI = "data:" + req.file.mimetype + ";base64," + b64;

    const result = await cloudinary.uploader.upload(dataURI, {
      folder: "caafiCare",
      resource_type: "auto",
    });

    console.log(`[UPLOAD] Cloudinary success: 1 file uploaded.`);

    // Return a single object, not an array
    res.json({
      imageUrl: result.secure_url,
      publicId: result.public_id,
    });
  } catch (error) {
    console.error("Single Upload error:", error);
    res.status(500).json({
      error: error.message || "Failed to upload image to Cloudinary",
    });
  }
});

// CREATE plan
const validateUpdateUserData = (data) => {
  // Check if any field is provided
  if (Object.keys(data).length === 0) {
    return "No fields provided for update.";
  }

  // Basic validation for name
  if (
    data.name !== undefined && // Check only if field is present
    (typeof data.name !== "string" || data.name.trim().length < 2)
  ) {
    return "Name must be a valid string of at least 2 characters.";
  }

  // Basic validation for email format
  if (data.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      return "Invalid email format.";
    }
  }

  // 🌟 NEW: Basic validation for password 🌟
  if (data.password !== undefined) {
    if (typeof data.password !== "string" || data.password.length < 8) {
      return "Password must be at least 8 characters long.";
    }
    // Optionally check for confirmation password if needed, but not required by this API signature
  }

  // Phone and Location can be optional and free-form strings
  if (data.phone !== undefined && typeof data.phone !== "string") {
    return "Phone must be a string.";
  }
  if (data.location !== undefined && typeof data.location !== "string") {
    return "Location must be a string.";
  }

  if (data.image !== undefined && typeof data.image !== "string") {
    return "Image must be a string (URL).";
  }
  if (
    data.description !== undefined &&
    data.description !== null &&
    typeof data.description !== "string"
  ) {
    return "Description must be a string.";
  }
  if (
    data.description &&
    typeof data.description === "string" &&
    data.description.length > 2000
  ) {
    return "Description must be 2000 characters or less.";
  }

  if (data.role !== undefined && !["USER", "ADMIN"].includes(data.role)) {
    return "Role must be USER or ADMIN.";
  }

  if (data.plan_id !== undefined) {
    const planId = parseInt(String(data.plan_id), 10);
    if (Number.isNaN(planId) || planId <= 0) {
      return "plan_id must be a valid positive number.";
    }
  }

  return null; // Validation passed
};

const isAuthenticated = (req, res, next) => {
  // SECURITY NOTE: This is a placeholder. In production, this should validate a JWT token.
  if (req.headers["x-user-id"]) {
    req.userId = req.headers["x-user-id"]; // Assuming the auth middleware attaches the user ID
    next();
  } else {
    res.status(401).json({
      error: "Authentication required. Please provide 'x-user-id' header.",
    });
  }
};

const validateUpdateData = (data) => {
  // In a real app, check field formats (e.g., price is numeric, email is valid)
  if (data.price && isNaN(parseFloat(data.price))) {
    return "Price must be a valid number.";
  }
  return null;
};

const normalizeImageField = (image) => {
  if (Array.isArray(image)) {
    return image.map((url) => String(url).trim()).filter(Boolean).join(", ");
  }
  if (typeof image === "string") {
    return image
      .split(",")
      .map((url) => url.trim())
      .filter(Boolean)
      .join(", ");
  }
  if (image === "") return "";
  return undefined;
};

// --- 🌟 UPDATED UPDATE USER API ROUTE 🌟 ---
// Backend endpoint for PATCH /api/users/:id
app.patch("/api/users/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const userIdToUpdate = req.params.id;

    console.log("=== PROFILE UPDATE ATTEMPT ===");
    console.log(
      "Current User ID from header:",
      currentUserId,
      "Type:",
      typeof currentUserId,
    );
    console.log(
      "Target User ID from URL:",
      userIdToUpdate,
      "Type:",
      typeof userIdToUpdate,
    );
    console.log("Update data:", req.body);

    const {
      name,
      email,
      phone,
      location,
      password,
      image,
      description,
      role,
      plan_id,
    } = req.body;

    // Convert IDs to numbers to match Prisma schema
    const currentUserIdNum = parseInt(currentUserId);
    const userIdToUpdateNum = parseInt(userIdToUpdate);

    console.log(
      "Converted Current User ID:",
      currentUserIdNum,
      "Type:",
      typeof currentUserIdNum,
    );
    console.log(
      "Converted Target User ID:",
      userIdToUpdateNum,
      "Type:",
      typeof userIdToUpdateNum,
    );

    if (isNaN(currentUserIdNum) || isNaN(userIdToUpdateNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const admin = await requestUserIsAdmin(req);

    const payloadForValidation = {
      ...(name !== undefined && { name }),
      ...(email !== undefined && { email }),
      ...(phone !== undefined && { phone }),
      ...(location !== undefined && { location }),
      ...(password !== undefined && { password }),
      ...(image !== undefined && { image }),
      ...(description !== undefined && {
        description:
          description === null || description === ""
            ? ""
            : String(description),
      }),
      ...(admin && role !== undefined && { role }),
      ...(admin && plan_id !== undefined && { plan_id }),
    };
    const validationErr = validateUpdateUserData(payloadForValidation);
    if (validationErr) {
      return res.status(400).json({ error: validationErr });
    }

    // Security check: users can update their own profile; admins can update any user
    if (!admin && currentUserIdNum !== userIdToUpdateNum) {
      console.log("❌ Authorization mismatch:", {
        currentUser: currentUserIdNum,
        targetUser: userIdToUpdateNum,
      });
      return res
        .status(403)
        .json({ error: "Not authorized to update this profile" });
    }

    console.log(
      admin
        ? "✅ Authorization verified - admin updating user profile"
        : "✅ Authorization verified - user can update their own profile",
    );

    // 1. Find the user first
    const existingUser = await prisma.user.findUnique({
      where: { id: userIdToUpdateNum },
    });

    if (!existingUser) {
      console.log("❌ User not found with ID:", userIdToUpdateNum);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("Found user:", {
      id: existingUser.id,
      email: existingUser.email,
      name: existingUser.name,
    });

    // 2. Prepare update data (Prisma updates `updatedAt` via @updatedAt on the model)
    const updateData = {
      ...(name !== undefined && { name: String(name).trim() }),
      ...(email !== undefined && { email: String(email).trim().toLowerCase() }),
      ...(phone !== undefined && {
        phone:
          phone === null || phone === "" ? null : String(phone).trim(),
      }),
      ...(location !== undefined && {
        location:
          location === null || location === "" ? null : String(location).trim(),
      }),
      ...(image !== undefined && {
        image: image === null || image === "" ? null : String(image).trim(),
      }),
      ...(description !== undefined && {
        description:
          description === null || description === ""
            ? null
            : String(description).trim().slice(0, 2000),
      }),
    };

    if (admin) {
      if (role !== undefined) {
        updateData.role = role;
      }
      if (plan_id !== undefined) {
        const planIdNum = parseInt(String(plan_id), 10);
        const planExists = await prisma.plans.findUnique({
          where: { id: planIdNum },
          select: { id: true },
        });
        if (!planExists) {
          return res.status(400).json({ error: "Selected plan does not exist." });
        }
        updateData.plan_id = planIdNum;
      }
    }

    // Handle password hashing if provided
    if (password) {
      console.log("🔐 Password update requested");
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    console.log("📝 Final update data:", Object.keys(updateData));

    // 3. Perform update
    const result = await prisma.user.update({
      where: { id: userIdToUpdateNum },
      data: updateData,
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        location: true,
        image: true,
        description: true,
        role: true,
        plan_id: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    console.log("✅ Profile update successful:", {
      id: result.id,
      email: result.email,
      name: result.name,
    });

    res.json(result);
  } catch (error) {
    console.error("❌ PROFILE UPDATE ERROR DETAILS:");
    console.error("Error name:", error.name);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "User not found" });
    }

    if (error.code === "P2002") {
      // Unique constraint violation (email)
      if (error.meta?.target?.includes("email")) {
        return res.status(409).json({
          error: "This email is already registered to another account.",
        });
      }
    }

    // Return the actual error message for debugging
    res.status(500).json({
      error: `Profile update failed: ${error.message}`,
    });
  }
});

app.post("/api/plans", async (req, res) => {
  try {
    const validationError = validatedPlanData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }
    const business = await prisma.plans.create({
      data: {
        ...req.body,
        price: req.body.priceMonthly ?? req.body.price ?? 0,
        priceMonthly: req.body.priceMonthly ?? req.body.price ?? 0,
        priceYearly: req.body.priceYearly ?? 0,
      },
    });
    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET all plans
app.get("/api/plans", async (req, res) => {
  try {
    const plans = await prisma.plans.findMany({
      include: {
        users: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        price: "asc",
      },
    });
    res.json(plans);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET single plan
app.get("/api/plans/:id", async (req, res) => {
  try {
    const plan = await prisma.plans.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    if (!plan) {
      return res.status(404).json({ error: "Plan not found" });
    }

    res.json(plan);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// UPDATE plan
app.put("/api/plans/:id", async (req, res) => {
  try {
    const validationError = validatedPlanData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const plan = await prisma.plans.update({
      where: { id: parseInt(req.params.id) },
      data: {
        ...req.body,
        price: req.body.priceMonthly ?? req.body.price ?? 0,
        priceMonthly: req.body.priceMonthly ?? req.body.price ?? 0,
        priceYearly: req.body.priceYearly ?? 0,
      },
    });

    res.json(plan);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE plan
app.delete("/api/plans/:id", async (req, res) => {
  try {
    await prisma.plans.delete({
      where: { id: parseInt(req.params.id) },
    });

    res.json({ message: "Plan deleted successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET user's current usage - FIXED with enum values
app.get("/api/users/:userId/usage", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    console.log(`Fetching usage data for user ${userId}`);

    // Get user with businesses and products
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        businesses: true,
        products: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    console.log(`User found: ${user.name}, plan_id: ${user.plan_id}`);

    // CORRECTED: Get the plan using user.plan_id directly
    let activePlan = await prisma.plans.findUnique({
      where: {
        id: user.plan_id || 1, // Use user's plan_id or default to plan 1
      },
    });

    // If no plan found with plan_id, get the default plan
    if (!activePlan) {
      console.log(`No plan found with id ${user.plan_id}, using default plan`);
      activePlan = await prisma.plans.findUnique({
        where: { id: 1 }, // Default plan ID
      });
    }

    if (!activePlan) {
      return res.status(400).json({ error: "No plan configuration found" });
    }

    console.log(
      `Active plan: ${activePlan.name}, allowed businesses: ${activePlan.allowedBusinesses}, allowed products: ${activePlan.allowedProducts}`,
    );

    // Count only ACTIVE or APPROVED businesses/products
    const activeBusinesses = user.businesses.filter(
      (business) =>
        business.status === "ACTIVE" || business.status === "APPROVED",
    );

    const activeProducts = user.products.filter(
      (product) => product.status === "ACTIVE" || product.status === "APPROVED",
    );

    const usage = {
      plan: activePlan,
      businesses: {
        count: activeBusinesses.length,
        limit: activePlan.allowedBusinesses,
        remaining: Math.max(
          0,
          activePlan.allowedBusinesses - activeBusinesses.length,
        ),
      },
      products: {
        count: activeProducts.length,
        limit: activePlan.allowedProducts,
        remaining: Math.max(
          0,
          activePlan.allowedProducts - activeProducts.length,
        ),
      },
    };

    console.log(`Usage data for user ${userId}:`, {
      businesses: `${usage.businesses.count}/${usage.businesses.limit}`,
      products: `${usage.products.count}/${usage.products.limit}`,
    });

    res.json(usage);
  } catch (error) {
    console.error("Error fetching user usage:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/businesses", async (req, res) => {
  try {
    // 1. Run the updated server-side validation
    const validationError = validateBusinessData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const {
      name,
      description,
      category,
      phone,
      email,
      location,
      image, // This should be a comma-separated string of URLs
      ownerId,
      businessType = "GENERAL",
    } = req.body;

    // 2. Limit Check Logic
    const user = await prisma.user.findUnique({
      where: { id: ownerId },
      include: {
        plan: true,
        businesses: {
          where: {
            status: "APPROVED",
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get the user's plan - it's an array
    let userPlan;
    if (user.plan && user.plan.length > 0) {
      userPlan = user.plan[0];
    } else {
      userPlan = await prisma.plans.findUnique({
        where: { id: user.plan_id || 1 },
      });
    }

    if (!userPlan) {
      return res.status(400).json({ error: "No active plan found" });
    }

    const businessLimit = userPlan.allowedBusinesses;
    const currentBusinessCount = user.businesses.length;

    if (currentBusinessCount >= businessLimit) {
      return res.status(403).json({
        error: `Business limit reached. You can only create ${businessLimit} business(es) with your ${userPlan.name}.`,
        code: "BUSINESS_LIMIT_REACHED",
        currentCount: currentBusinessCount,
        limit: businessLimit,
      });
    }

    // 3. Create Business with comma-separated image string
    const business = await prisma.business.create({
      data: {
        name,
        description,
        category,
        phone,
        email,
        location,
        image: image, // Store as comma-separated string
        ownerId,
        status: "PENDING",
        businessType,
      },
      include: {
        owner: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    res.json({
      success: true,
      business,
      message: "Business submitted for approval",
      limits: {
        currentCount: currentBusinessCount + 1,
        limit: businessLimit,
        remaining: businessLimit - (currentBusinessCount + 1),
      },
    });
  } catch (error) {
    console.error("Error creating business:", error);
    res.status(400).json({
      error: error.message || "Failed to create business",
    });
  }
});

app.get("/api/businesses", async (req, res) => {
  try {
    const businesses = await prisma.business.findMany({
      where: { status: "APPROVED" },
    });
    res.json(businesses);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const normalizeListingDisplay = (v) => {
  const s = v == null ? "" : String(v).trim().toLowerCase();
  return s === "category" ? "category" : "location";
};

const validateProductData = (data) => {
  const errors = {};

  if (!data.name?.trim()) errors.name = "Product name is required.";
  if (!data.description?.trim() || data.description.length < 15) {
    errors.description = "Description must be at least 15 characters.";
  }

  // --- Price Validation ---
  const priceValue = parseFloat(data.price);
  const priceToValue = parseFloat(data.price_to);
  const crossedPriceValue = parseFloat(data.crossed_price);

  if (data.price_option === "Fixed" || data.price_option === "Crossed") {
    if (!data.price || isNaN(priceValue) || priceValue <= 0) {
      errors.price = "A valid fixed price is required.";
    }
  } else if (data.price_option === "Range") {
    if (!data.price || isNaN(priceValue) || priceValue <= 0) {
      errors.price = "A valid 'Price From' is required.";
    }
    if (
      !data.price_to ||
      isNaN(priceToValue) ||
      priceToValue <= 0 ||
      priceToValue < priceValue
    ) {
      errors.price_to =
        "A valid 'Price To' is required and must be greater than Price From.";
    }
  } else if (data.price_option === "Negotiable") {
    // Price is optional, but if provided, must be valid
    if (data.price && (isNaN(priceValue) || priceValue <= 0)) {
      errors.price = "If providing a price, it must be valid.";
    }
  }

  if (data.price_option === "Crossed") {
    if (
      !data.crossed_price ||
      isNaN(crossedPriceValue) ||
      crossedPriceValue <= priceValue
    ) {
      errors.crossed_price =
        "Original price (crossed) is required and must be higher than the new price.";
    }
  }

  // --- Other Validations ---
  if (data.category.length === 0)
    errors.category = "At least one category is required.";
  if (!data.type?.trim()) errors.type = "Product condition (type) is required.";
  if (!data.location?.trim()) errors.location = "Location is required.";
  if (data.image.length === 0)
    errors.image = "At least one product image is required.";
  if (!data.posted_from?.trim())
    errors.posted_from = "Posting source is required.";

  if (data.listingDisplay != null && String(data.listingDisplay).trim() !== "") {
    const ld = String(data.listingDisplay).trim().toLowerCase();
    if (ld !== "location" && ld !== "category") {
      errors.listingDisplay = "listingDisplay must be 'location' or 'category'.";
    }
  }

  return Object.keys(errors).length > 0 ? errors : null;
};

app.post("/api/products", async (req, res) => {
  try {
    const {
      userId,
      name,
      description,
      price,
      price_to,
      price_option,
      crossed_price,
      category,
      type,
      location,
      listingDisplay,
      posted_from, // This should be a string like "Personal Account" or "Business: Business Name"
      posted_from_id, // This is the numeric ID
      image,
      status = "PENDING",
    } = req.body;

    // Validation
    const validationError = validateProductData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      include: {
        plan: true,
        products: {
          where: { status: "ACTIVE" },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get the user's plan - it's an array
    let userPlan;
    if (user.plan && user.plan.length > 0) {
      userPlan = user.plan[0];
    } else {
      userPlan = await prisma.plans.findUnique({
        where: { id: user.plan_id || 1 },
      });
    }

    if (!userPlan) {
      return res.status(400).json({ error: "User has no active plan" });
    }

    // Check product limit
    const productLimit = userPlan.allowedProducts;
    const currentProductCount = user.products.length;

    if (currentProductCount >= productLimit) {
      return res.status(403).json({
        error: `Product limit reached. You can only create ${productLimit} product(s) with your ${userPlan.name} plan.`,
        code: "PRODUCT_LIMIT_REACHED",
        currentCount: currentProductCount,
        limit: productLimit,
      });
    }

    // Make sure posted_from is a string
    let postedFromString = posted_from;
    if (typeof postedFromString !== "string") {
      // If posted_from is not a string, convert it
      postedFromString = String(postedFromString || "Personal Account");
    }

    // Create product data
    const productData = {
      name,
      description,
      price: parseFloat(price || 0),
      price_option,
      crossed_price: crossed_price ? parseFloat(crossed_price) : null,
      category,
      type,
      location,
      listingDisplay: normalizeListingDisplay(listingDisplay),
      posted_from: postedFromString, // Must be a string
      image,
      userId: parseInt(userId),
      status,
    };

    // Only include price_to if it has a value
    if (price_to !== undefined && price_to !== null && price_to !== "") {
      productData.price_to = parseFloat(price_to);
    }

    console.log("Creating product with data:", productData);

    // Create product
    const product = await prisma.product.create({
      data: productData,
    });

    res.json({
      success: true,
      product,
      message: "Product submitted successfully for approval",
      limits: {
        currentCount: currentProductCount + 1,
        limit: productLimit,
        remaining: productLimit - (currentProductCount + 1),
      },
    });
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(500).json({
      error: error.message || "Failed to create product",
    });
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { status: "APPROVED" },
    });

    const processedProducts = products.map(processProductData);

    res.json(processedProducts);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/businesses/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserIdNum = parseInt(String(req.userId), 10);
    const businessIdNum = parseInt(String(req.params.id), 10);

    if (isNaN(currentUserIdNum) || isNaN(businessIdNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const business = await prisma.business.findUnique({
      where: { id: businessIdNum },
    });

    if (!business) {
      return res.status(404).json({ error: "Business not found" });
    }

    const admin = await requestUserIsAdmin(req);
    if (!admin && business.ownerId !== currentUserIdNum) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this business" });
    }

    const normalizedImage = normalizeImageField(req.body.image);
    const { name, description, category, phone, email, location, businessType, status } =
      req.body;

    if (admin) {
      const data = {};
      if (name !== undefined) data.name = String(name).trim();
      if (description !== undefined) data.description = String(description);
      if (category !== undefined) data.category = String(category).trim();
      if (phone !== undefined) data.phone = String(phone).trim();
      if (email !== undefined) data.email = String(email).trim();
      if (location !== undefined) data.location = String(location).trim();
      if (businessType !== undefined) {
        data.businessType =
          businessType === null || businessType === ""
            ? null
            : String(businessType).trim();
      }
      if (status !== undefined && LISTING_STATUS.has(String(status))) {
        data.status = String(status);
      }
      if (normalizedImage !== undefined) data.image = normalizedImage;

      const result = await prisma.business.update({
        where: { id: businessIdNum },
        data,
      });
      return res.json({
        message: "Business updated",
        business: result,
      });
    }

    const updateData = {
      name: name || business.name,
      description: description || business.description,
      category: category || business.category,
      phone: phone || business.phone,
      email: email || business.email,
      location: location || business.location,
      status: "PENDING",
      updatedAt: new Date(),
    };
    if (businessType !== undefined) {
      updateData.businessType =
        businessType === null || businessType === ""
          ? null
          : String(businessType).trim();
    }
    if (normalizedImage !== undefined) {
      updateData.image = normalizedImage;
    }

    const result = await prisma.business.update({
      where: { id: businessIdNum },
      data: updateData,
    });

    res.json({
      message: "Business updated successfully and set to PENDING for review",
      business: result,
    });
  } catch (error) {
    console.error("PATCH /api/businesses/:id", error);
    if (error.code === "P2025") {
      return res.status(404).json({ error: "Business not found" });
    }
    if (error.code === "P2002") {
      return res
        .status(409)
        .json({ error: "A business with this name or email already exists" });
    }
    res.status(500).json({
      error: `Update failed: ${error.message}`,
    });
  }
});

// PATCH /api/products/:id — owner or ADMIN (dashboard)
app.patch("/api/products/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserIdNum = parseInt(String(req.userId), 10);
    const productIdNum = parseInt(String(req.params.id), 10);

    if (isNaN(currentUserIdNum) || isNaN(productIdNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const existingProduct = await prisma.product.findUnique({
      where: { id: productIdNum },
    });

    if (!existingProduct) {
      return res.status(404).json({ error: "Product not found" });
    }

    const admin = await requestUserIsAdmin(req);
    if (!admin && existingProduct.userId !== currentUserIdNum) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this product" });
    }

    const normalizedImage = normalizeImageField(req.body.image);
    const {
      name,
      description,
      price,
      price_to,
      price_option,
      crossed_price,
      category,
      type,
      posted_from,
      location,
      listingDisplay,
      status,
    } = req.body;

    const numOr = (v, fallback) => {
      if (v === undefined) return fallback;
      if (v === null || v === "") return null;
      const n = typeof v === "number" ? v : parseFloat(v);
      return Number.isFinite(n) ? n : fallback;
    };

    if (admin) {
      const data = {};
      if (name !== undefined) data.name = String(name).trim();
      if (description !== undefined) data.description = String(description);
      if (category !== undefined) data.category = String(category).trim();
      if (location !== undefined) data.location = String(location).trim();
      if (listingDisplay !== undefined)
        data.listingDisplay = normalizeListingDisplay(listingDisplay);
      if (type !== undefined) data.type = String(type).trim();
      if (posted_from !== undefined) data.posted_from = String(posted_from).trim();
      if (price_option !== undefined) data.price_option = String(price_option).trim();
      if (price !== undefined) data.price = numOr(price, existingProduct.price);
      if (price_to !== undefined) data.price_to = numOr(price_to, existingProduct.price_to);
      if (crossed_price !== undefined)
        data.crossed_price = numOr(crossed_price, existingProduct.crossed_price);
      if (status !== undefined && LISTING_STATUS.has(String(status))) {
        data.status = String(status);
      }
      if (normalizedImage !== undefined) data.image = normalizedImage;

      const result = await prisma.product.update({
        where: { id: productIdNum },
        data,
      });
      return res.json({
        message: "Product updated",
        product: processProductData(result),
      });
    }

    const updateData = {
      name: name || existingProduct.name,
      description: description || existingProduct.description,
      price: price !== undefined ? numOr(price, existingProduct.price) : existingProduct.price,
      category: category || existingProduct.category,
      location: location || existingProduct.location,
      listingDisplay:
        listingDisplay !== undefined
          ? normalizeListingDisplay(listingDisplay)
          : normalizeListingDisplay(existingProduct.listingDisplay),
      status: "PENDING",
      updatedAt: new Date(),
    };
    if (price_to !== undefined) updateData.price_to = numOr(price_to, existingProduct.price_to);
    if (price_option !== undefined) updateData.price_option = String(price_option).trim();
    if (crossed_price !== undefined)
      updateData.crossed_price = numOr(crossed_price, existingProduct.crossed_price);
    if (type !== undefined) updateData.type = String(type).trim();
    if (posted_from !== undefined) updateData.posted_from = String(posted_from).trim();
    if (normalizedImage !== undefined) updateData.image = normalizedImage;

    const result = await prisma.product.update({
      where: { id: productIdNum },
      data: updateData,
    });

    res.json({
      message: "Product updated successfully and set to PENDING for review",
      product: processProductData(result),
    });
  } catch (error) {
    console.error("PATCH /api/products/:id", error);
    if (error.code === "P2025") {
      return res.status(404).json({ error: "Product not found" });
    }
    if (error.code === "P2002") {
      return res
        .status(409)
        .json({ error: "A product with this name already exists" });
    }
    res.status(500).json({
      error: `Product update failed: ${error.message}`,
    });
  }
});

// Get all businesses (for admin)
app.get("/api/admin/businesses", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const businesses = await prisma.business.findMany({
      include: { owner: { select: { name: true, email: true } } },
    });
    res.json(businesses);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/businesses/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update business status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const business = await prisma.business.update({
      where: { id },
      data: { status },
    });
    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const processProductData = (product) => {
  const base = {
    ...product,
    city: product.location || null,
  };
  if (product.image && typeof product.image === "string") {
    const imagesArray = product.image
      .split(",")
      .map((url) => url.trim())
      .filter((url) => url.length > 0);
    return {
      ...base,
      images: imagesArray,
      primaryImage: imagesArray[0] || null,
    };
  }
  return {
    ...base,
    images: [],
    primaryImage: null,
  };
};

// Get all products (for admin)
app.get("/api/admin/products", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const products = await prisma.product.findMany({
      include: { user: { select: { name: true, email: true } } },
    });
    res.json(products);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/products/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update product status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const product = await prisma.product.update({
      where: { id },
      data: { status },
    });
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Professional routes
const normalizeProfessionList = (profession) => {
  if (Array.isArray(profession)) {
    return profession.map((p) => String(p).trim()).filter(Boolean);
  }
  if (typeof profession === "string") {
    return profession
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
  }
  return [];
};

const validateProfessionalData = (data) => {
  const errors = {};

  const professions = normalizeProfessionList(data.profession);

  if (professions.length === 0) {
    errors.profession = "At least one profession is required";
  } else if (professions.length > 5) {
    errors.profession = "Maximum 5 professions allowed";
  }

  if (!data.specialty?.trim()) {
    errors.specialty = "Specialty/Education level is required";
  }

  if (!data.experience?.trim()) {
    errors.experience = "Experience level is required";
  }

  if (!data.location?.trim()) {
    errors.location = "Location is required";
  }

  const phoneRaw = String(data.phone || "").trim();
  const phoneNormalized = phoneRaw.replace(/\s+/g, "");
  if (!phoneNormalized) {
    errors.phone = "Phone number is required";
  } else if (!/^\+?\d{5,15}$/.test(phoneNormalized)) {
    errors.phone =
      "Please enter a valid phone number (digits only, optional +)";
  } else {
    data.phone = phoneNormalized;
  }

  if (!data.email?.trim()) {
    errors.email = "Email is required";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.email = "Please enter a valid email address";
  }

  // Optional: Add description validation if needed
  if (data.description && data.description.length > 1000) {
    errors.description = "Description must be 1000 characters or less";
  }

  return Object.keys(errors).length > 0 ? errors : null;
};

app.post("/api/professionals", async (req, res) => {
  try {
    const body = { ...req.body };
    const uid =
      typeof body.userId === "string"
        ? parseInt(body.userId, 10)
        : body.userId;
    if (
      (!body.email || !String(body.email).trim()) &&
      uid != null &&
      !Number.isNaN(Number(uid))
    ) {
      const account = await prisma.user.findUnique({
        where: { id: Number(uid) },
        select: { email: true },
      });
      if (account?.email) {
        body.email = account.email;
      }
    }

    const validationError = validateProfessionalData(body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }
    const professions = normalizeProfessionList(body.profession);
    const descriptionNormalized =
      body.description == null || String(body.description).trim() === ""
        ? null
        : String(body.description).slice(0, 1000);

    const professional = await prisma.professional.create({
      data: {
        userId:
          typeof body.userId === "string"
            ? parseInt(body.userId, 10)
            : body.userId,
        profession: professions.join(", "),
        specialty: body.specialty,
        experience: body.experience,
        location: body.location,
        phone: body.phone,
        email: body.email,
        image: body.image ?? null,
        description: descriptionNormalized,
        status: body.status ?? "PENDING",
      },
    });
    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update professional profile — owner or ADMIN
app.patch("/api/professionals/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserId = parseInt(req.userId);
    const professionalId = parseInt(req.params.id);

    if (isNaN(currentUserId) || isNaN(professionalId)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const professional = await prisma.professional.findUnique({
      where: { id: professionalId },
    });

    if (!professional) {
      return res.status(404).json({ error: "Professional not found" });
    }

    const admin = await requestUserIsAdmin(req);
    if (!admin && professional.userId !== currentUserId) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this profile" });
    }

    const normalizedImage = normalizeImageField(req.body.image);

    if (admin) {
      const data = {};
      if (req.body.profession !== undefined) {
        data.profession = normalizeProfessionList(req.body.profession).join(", ");
      }
      if (req.body.specialty !== undefined)
        data.specialty = String(req.body.specialty).trim();
      if (req.body.experience !== undefined)
        data.experience = String(req.body.experience).trim();
      if (req.body.location !== undefined)
        data.location = String(req.body.location).trim();
      if (req.body.phone !== undefined)
        data.phone = String(req.body.phone).trim().replace(/\s+/g, "");
      if (req.body.email !== undefined) data.email = String(req.body.email).trim();
      if (req.body.description !== undefined) {
        const raw = req.body.description;
        data.description =
          raw == null || String(raw).trim() === ""
            ? null
            : String(raw).slice(0, 1000);
      }
      if (req.body.status !== undefined && LISTING_STATUS.has(String(req.body.status))) {
        data.status = String(req.body.status);
      }
      if (req.body.published !== undefined) data.published = Boolean(req.body.published);
      if (normalizedImage !== undefined) data.image = normalizedImage;

      const snapshot = { ...professional, ...data };
      const validationError = validateProfessionalData({
        profession: snapshot.profession,
        specialty: snapshot.specialty,
        experience: snapshot.experience,
        location: snapshot.location,
        phone: snapshot.phone,
        email: snapshot.email,
        description: snapshot.description,
      });
      if (validationError) {
        return res.status(400).json({ error: validationError });
      }

      const updatedProfile = await prisma.professional.update({
        where: { id: professionalId },
        data,
      });
      return res.json({
        message: "Professional updated",
        professional: updatedProfile,
      });
    }

    const professions = normalizeProfessionList(req.body.profession);
    const rawDesc = req.body.description;
    const descriptionNormalized =
      rawDesc == null || String(rawDesc).trim() === ""
        ? null
        : String(rawDesc).slice(0, 1000);

    let resolvedEmail =
      req.body.email != null && String(req.body.email).trim()
        ? String(req.body.email).trim()
        : "";
    if (!resolvedEmail) {
      resolvedEmail =
        (professional.email && String(professional.email).trim()) ||
        (
          await prisma.user.findUnique({
            where: { id: professional.userId },
            select: { email: true },
          })
        )?.email?.trim() ||
        "";
    }

    const updateData = {
      profession: professions.join(", "),
      specialty: req.body.specialty,
      experience: req.body.experience,
      location: req.body.location,
      phone: req.body.phone,
      email: resolvedEmail,
      description: descriptionNormalized,
      status: "PENDING",
      published: false,
      updatedAt: new Date(),
    };
    if (normalizedImage !== undefined) {
      updateData.image = normalizedImage;
    }

    const validationError = validateProfessionalData(updateData);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const updatedProfile = await prisma.professional.update({
      where: { id: professionalId },
      data: updateData,
    });

    res.json({
      message: "Professional updated successfully and set to PENDING for review",
      professional: updatedProfile,
    });
  } catch (error) {
    console.error("Error updating professional:", error);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/professionals", async (req, res) => {
  try {
    const professionals = await prisma.professional.findMany({
      where: { status: "APPROVED" },
    });
    res.json(professionals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Backend APIs for approval system

// Get pending businesses
app.get("/api/businesses/pending", async (req, res) => {
  try {
    const pendingBusinesses = await prisma.business.findMany({
      where: { status: "PENDING" },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingBusinesses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve business
app.put("/api/businesses/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.update({
      where: { id: parseInt(id) },
      data: { status: "APPROVED" },
    });

    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject business
app.put("/api/businesses/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get pending professionals
app.get("/api/professionals/pending", async (req, res) => {
  try {
    const pendingProfessionals = await prisma.professional.findMany({
      where: { status: "PENDING" },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingProfessionals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get professional's products
app.get("/api/professionals/:id/products", async (req, res) => {
  try {
    const { id } = req.params;

    const products = await prisma.product.findMany({
      where: {
        userId: parseInt(id),
        status: "APPROVED", // Only show approved products
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    const formattedProducts = products.map((product) => ({
      id: product.id,
      name: product.name,
      description: product.description,
      price: product.price,
      category: product.category,
      image: product.image,
      status: product.status,
      stockQuantity: product.stockQuantity || 0,
      location: product.location,
      specifications: product.specifications
        ? JSON.parse(product.specifications)
        : [],
      materials: product.materials ? JSON.parse(product.materials) : [],
      dimensions: product.dimensions,
      weight: product.weight,
      madeToOrder: product.madeToOrder || false,
      productionTime: product.productionTime,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    }));

    res.json(formattedProducts);
  } catch (error) {
    console.error("Error fetching professional products:", error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Get approved businesses
app.get("/api/businesses/approved", async (req, res) => {
  try {
    const approvedBusinesses = await prisma.business.findMany({
      where: {
        status: "APPROVED",
      },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "desc",
      },
    });

    res.json(approvedBusinesses);
  } catch (error) {
    console.error("Error fetching approved businesses:", error);
    res.status(500).json({ error: "Failed to fetch approved businesses" });
  }
});

// Get business by ID
app.get("/api/businesses/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.findUnique({
      where: { id: parseInt(id) },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    if (!business) {
      return res.status(404).json({ error: "Business not found" });
    }

    res.json(business);
  } catch (error) {
    console.error("Error fetching business:", error);
    res.status(500).json({ error: "Failed to fetch business" });
  }
});

app.delete("/api/businesses/:id", async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);

    if (isNaN(numericId)) {
      return res.status(400).json({ error: "Invalid business ID" });
    }

    const deletedBusiness = await prisma.business.delete({
      where: { id: numericId },
    });

    return res.json({
      message: "Business deleted successfully",
      business: deletedBusiness,
    });
  } catch (error) {
    console.error("Error deleting business:", error);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Business not found" });
    }

    return res.status(500).json({ error: "Failed to delete business" });
  }
});

app.get("/api/entity/:type/:id/products", async (req, res) => {
  try {
    const { id, type } = req.params;
    let ownerId;
    let entityName;

    // 1. Determine the ownerId based on the entity type
    if (type === "business") {
      const business = await prisma.business.findUnique({
        where: { id: parseInt(id) },
      });

      if (!business) {
        return res.status(404).json({ error: "Business not found" });
      }
      ownerId = business.ownerId; // Assuming Business has ownerId
      entityName = business.name;
    } else if (type === "professional") {
      const professional = await prisma.professional.findUnique({
        where: { id: parseInt(id) },
      });

      if (!professional) {
        return res.status(404).json({ error: "Professional not found" });
      }
      ownerId = professional.userId; // Assuming Professional has userId (the owner)
      entityName = professional.specialty; // Use specialty or profession as the name
    } else {
      return res.status(400).json({ error: "Invalid entity type specified" });
    }

    // Check if ownerId was successfully found
    if (!ownerId) {
      console.error(`[PRODUCTS] Owner ID not found for ${type} ${id}`);
      return res
        .status(404)
        .json({ error: `Owner not linked to this ${type}` });
    }

    // 2. Get products by the entity owner
    const products = await prisma.product.findMany({
      where: {
        userId: ownerId, // Fetch products linked to the owner's ID
        status: "APPROVED", // Only show approved products
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    console.log(
      `[PRODUCTS] Found ${products.length} products for ${entityName} (${type} ${id})`,
    );
    res.json(products);
  } catch (error) {
    console.error("Error fetching entity products:", error);
    res.status(500).json({ error: "Failed to fetch entity products" });
  }
});

// GET /api/professionals/user/:userId?status=APPROVED
app.get("/api/professionals/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.query;

    const whereClause = {
      userId: parseInt(userId),
    };

    // Add status filter if provided
    if (status) {
      whereClause.status = status.toUpperCase();
    }

    const professionals = await prisma.professional.findMany({
      where: whereClause,
      select: {
        id: true,
        profession: true,
        specialty: true,
        experience: true,
        location: true,
        status: true,
        published: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(professionals);
  } catch (error) {
    console.error("Error fetching user professionals:", error);
    res.status(500).json({ error: "Failed to fetch professionals" });
  }
});

// Reject professional
app.put("/api/professionals/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const professional = await prisma.professional.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get pending products
app.get("/api/products/pending", async (req, res) => {
  try {
    const pendingProducts = await prisma.product.findMany({
      where: { status: "PENDING" },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingProducts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const productId = parseInt(req.params.id);

    // Validate that the ID is a valid number
    if (isNaN(productId)) {
      return res.status(400).json({ error: "Invalid product ID" });
    }

    const product = await prisma.product.findUnique({
      where: {
        id: productId,
      },
      // 🔑 ADDED: Include the related 'user' data
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            phone: true,
          },
        },
      },
    });

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    const formattedProduct = {
      ...product,
      userName: product.user.name,
      userEmail: product.user.email,
      userPhone: product.user.phone ?? null,
    };

    // Remove the nested user object if you flattened it
    delete formattedProduct.user;

    res.json(formattedProduct); // Send the formatted product
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/products/:id", async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);

    if (isNaN(numericId)) {
      return res.status(400).json({ error: "Invalid product ID" });
    }

    const deletedProduct = await prisma.product.delete({
      where: { id: numericId },
    });

    return res.json({
      message: "Product deleted successfully",
      product: deletedProduct,
    });
  } catch (error) {
    console.error("Error deleting product:", error);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Product not found" });
    }

    return res.status(500).json({ error: "Failed to delete product" });
  }
});
// Approve product
app.put("/api/products/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const product = await prisma.product.update({
      where: { id: parseInt(id) },
      data: { status: "APPROVED" },
    });

    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Approve professional
app.put("/api/professionals/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;
    const pid = parseInt(id, 10);

    const existing = await prisma.professional.findUnique({
      where: { id: pid },
      include: {
        user: { include: { plan: true } },
      },
    });

    if (!existing) {
      return res.status(404).json({ error: "Professional not found" });
    }

    const allowPub = existing.user?.plan?.allowProfessionalPublish === true;

    const professional = await prisma.professional.update({
      where: { id: pid },
      data: {
        status: "APPROVED",
        published: allowPub,
      },
    });

    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject product
app.put("/api/products/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const product = await prisma.product.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/api/professionals/approved", async (req, res) => {
  try {
    const approvedProfessionals = await prisma.professional.findMany({
      where: {
        status: "APPROVED",
        published: true,
        user: {
          is: {
            plan: {
              is: { allowProfessionalPublish: true },
            },
          },
        },
      },
      include: {
        user: { select: { id: true, name: true, email: true } },
      },
      orderBy: { submittedDate: "desc" },
    });

    const formattedProfessionals = approvedProfessionals.map(
      (professional) => ({
        id: professional.id,
        userId: professional.userId,
        userName: professional.user.name,
        userEmail: professional.user.email,
        profession: professional.profession,
        specialty: professional.specialty,
        experience: professional.experience,
        location: professional.location,
        phone: professional.phone,
        email: professional.email,
        description: professional.description,
        image: professional.image,
        status: professional.status,
        published: professional.published,
        submittedDate: professional.submittedDate,
        createdAt: professional.createdAt,
        updatedAt: professional.updatedAt,
      }),
    );

    res.status(200).json(formattedProfessionals);
  } catch (error) {
    console.error("❌ Error fetching approved professionals:", error);
    res.status(500).json({ error: "Failed to fetch approved professionals" });
  }
});

// Publish professional profile (subscription-gated). Business/Product cannot use this.
app.post("/api/professionals/:id/publish", isAuthenticated, async (req, res) => {
  try {
    const profId = parseInt(req.params.id, 10);
    const userId = parseInt(req.headers["x-user-id"], 10);
    if (isNaN(profId) || isNaN(userId)) {
      return res.status(400).json({ error: "Invalid id" });
    }

    const professional = await prisma.professional.findUnique({
      where: { id: profId },
      include: { user: { include: { plan: true } } },
    });

    if (!professional) {
      return res.status(404).json({ error: "Professional not found" });
    }
    if (professional.userId !== userId) {
      return res.status(403).json({ error: "Not allowed to modify this profile" });
    }
    if (professional.status !== "APPROVED") {
      return res
        .status(400)
        .json({ error: "Profile must be approved before it can be published" });
    }
    if (!professional.user?.plan?.allowProfessionalPublish) {
      return res.status(403).json({
        error:
          "Your subscription plan does not include publishing a professional profile in the directory.",
      });
    }

    const updated = await prisma.professional.update({
      where: { id: profId },
      data: { published: true },
    });
    res.json({ success: true, professional: updated });
  } catch (error) {
    console.error("Publish professional error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/professionals/:id/unpublish", isAuthenticated, async (req, res) => {
  try {
    const profId = parseInt(req.params.id, 10);
    const userId = parseInt(req.headers["x-user-id"], 10);
    if (isNaN(profId) || isNaN(userId)) {
      return res.status(400).json({ error: "Invalid id" });
    }

    const professional = await prisma.professional.findUnique({
      where: { id: profId },
    });
    if (!professional) {
      return res.status(404).json({ error: "Professional not found" });
    }
    if (professional.userId !== userId) {
      return res.status(403).json({ error: "Not allowed to modify this profile" });
    }

    const updated = await prisma.professional.update({
      where: { id: profId },
      data: { published: false },
    });
    res.json({ success: true, professional: updated });
  } catch (error) {
    console.error("Unpublish professional error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/businesses/:id/publish", (req, res) => {
  res.status(403).json({
    error:
      "Business listings cannot be published via subscription. Visibility is managed through admin approval only.",
  });
});

app.post("/api/products/:id/publish", (req, res) => {
  res.status(403).json({
    error:
      "Product listings cannot be published via subscription. Visibility is managed through admin approval only.",
  });
});

app.get("/api/professionals/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid ID" });

    const professional = await prisma.professional.findUnique({
      where: { id },
      include: {
        user: { select: { id: true, name: true, email: true } },
      },
    });

    if (!professional)
      return res.status(404).json({ error: "Professional not found" });

    res.json(professional);
  } catch (error) {
    console.error("Error in professional API:", error);
    res.status(500).json({ error: "Failed to fetch professional" });
  }
});

app.delete("/api/professionals/:id", async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);

    if (isNaN(numericId)) {
      return res.status(400).json({ error: "Invalid professional ID" });
    }

    const deletedProfessional = await prisma.professional.delete({
      where: { id: numericId },
    });

    return res.json({
      message: "Professional deleted successfully",
      professional: deletedProfessional,
    });
  } catch (error) {
    console.error("Error deleting professional:", error);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Professional not found" });
    }

    return res.status(500).json({ error: "Failed to delete professional" });
  }
});

// Get all professionals (for admin)
app.get("/api/admin/professionals", async (req, res) => {
  try {
    const auth = await getAdminUserOrError(req);
    if (auth.error) {
      return res.status(auth.status).json({ error: auth.error });
    }
    const professionals = await prisma.professional.findMany({
      include: { user: { select: { name: true, email: true } } },
    });
    res.json(professionals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/professionals/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update professional status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const professional = await prisma.professional.update({
      where: { id },
      data: { status },
    });
    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Plan Upgrade Request APIs

// POST - Create upgrade request
app.post("/api/upgrade-requests", async (req, res) => {
  try {
    const {
      userId,
      currentPlanId,
      requestedPlanId,
      amount,
      paymentMethod,
      phoneNumber,
      screenshot,
    } = req.body;

    // Validate required fields
    if (
      !userId ||
      !currentPlanId ||
      !requestedPlanId ||
      !amount ||
      !paymentMethod ||
      !phoneNumber
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const upgradeRequest = await prisma.planUpgradeRequest.create({
      data: {
        userId: parseInt(userId),
        currentPlanId: parseInt(currentPlanId),
        requestedPlanId: parseInt(requestedPlanId),
        amount: parseFloat(amount),
        paymentMethod,
        phoneNumber,
        screenshot,
        status: "PENDING",
      },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
        currentPlan: true,
        requestedPlan: true,
      },
    });

    res.json(upgradeRequest);
  } catch (error) {
    console.error("Error creating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// Replace your current upgrade-requests endpoint with this:
app.post("/api/verify-purchase", async (req, res) => {
  try {
    const { userId, planId, receiptData, transactionId } = req.body;

    // Validate required fields
    if (!userId || !planId || !receiptData || !transactionId) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Verify receipt with Apple's servers
    const verificationResult = await verifyAppleReceipt(receiptData);

    if (verificationResult.valid) {
      // Check if this transaction was already processed (prevent duplicate upgrades)
      const existingTransaction = await prisma.transaction.findUnique({
        where: { transactionId: transactionId },
      });

      if (existingTransaction) {
        return res.status(400).json({
          error: "This transaction was already processed",
          transaction: existingTransaction,
        });
      }

      // Update user's plan immediately
      const updatedUser = await prisma.user.update({
        where: { id: parseInt(userId) },
        data: {
          planId: parseInt(planId),
          updatedAt: new Date(),
        },
        include: {
          plan: true,
        },
      });

      // Record the successful transaction
      const transaction = await prisma.transaction.create({
        data: {
          userId: parseInt(userId),
          planId: parseInt(planId),
          transactionId: transactionId,
          productId: verificationResult.productId,
          amount: verificationResult.amount,
          status: "COMPLETED",
          paymentMethod: "APPLE_IAP",
          purchaseDate: verificationResult.purchaseDate || new Date(),
        },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              plan: true,
            },
          },
          plan: true,
        },
      });

      // Optional: Send confirmation email or notification
      await sendUpgradeConfirmation(updatedUser, transaction);

      res.json({
        success: true,
        message: "Purchase verified and plan upgraded successfully",
        user: updatedUser,
        transaction: transaction,
      });
    } else {
      res.status(400).json({
        error: "Invalid receipt - purchase verification failed",
        appleError: verificationResult.error,
      });
    }
  } catch (error) {
    console.error("Purchase verification error:", error);
    res.status(500).json({ error: "Failed to verify purchase" });
  }
});

// Enhanced Apple receipt verification
async function verifyAppleReceipt(receiptData) {
  try {
    const verificationUrl =
      process.env.NODE_ENV === "production"
        ? "https://buy.itunes.apple.com/verifyReceipt"
        : "https://sandbox.itunes.apple.com/verifyReceipt";

    const response = await fetch(verificationUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        "receipt-data": receiptData,
        password: process.env.APPLE_SHARED_SECRET,
        "exclude-old-transactions": false,
      }),
    });

    const result = await response.json();

    if (result.status === 0) {
      // 0 = success
      const latestReceipt =
        result.latest_receipt_info?.[0] || result.receipt?.in_app?.[0];

      if (!latestReceipt) {
        return { valid: false, error: "No receipt info found" };
      }

      return {
        valid: true,
        amount: parseFloat(latestReceipt.price) || 0,
        productId: latestReceipt.product_id,
        purchaseDate: latestReceipt.purchase_date_ms
          ? new Date(parseInt(latestReceipt.purchase_date_ms))
          : new Date(),
      };
    } else {
      console.log("Apple verification failed with status:", result.status);
      return {
        valid: false,
        error: `Apple verification failed with status: ${result.status}`,
      };
    }
  } catch (error) {
    console.error("Apple verification error:", error);
    return {
      valid: false,
      error: `Verification failed: ${error.message}`,
    };
  }
}

// Optional: Helper function for confirmation email
async function sendUpgradeConfirmation(user, transaction) {
  try {
    // Implement your email service here (SendGrid, AWS SES, etc.)
    console.log(
      `Upgrade confirmation sent to ${user.email} for plan ${transaction.plan.name}`,
    );
  } catch (error) {
    console.error("Failed to send upgrade confirmation:", error);
  }
}

// Helper function to verify with Apple
async function verifyAppleReceipt(receiptData) {
  try {
    const verificationUrl =
      process.env.NODE_ENV === "production"
        ? "https://buy.itunes.apple.com/verifyReceipt"
        : "https://sandbox.itunes.apple.com/verifyReceipt";

    const response = await fetch(verificationUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        "receipt-data": receiptData,
        password: process.env.APPLE_SHARED_SECRET, // From App Store Connect
        "exclude-old-transactions": false,
      }),
    });

    const result = await response.json();

    if (result.status === 0) {
      // 0 = success
      const latestReceipt = result.latest_receipt_info[0];
      return {
        valid: true,
        amount: parseFloat(latestReceipt.price),
        productId: latestReceipt.product_id,
        purchaseDate: new Date(parseInt(latestReceipt.purchase_date_ms)),
      };
    } else {
      console.log("Apple verification failed with status:", result.status);
      return { valid: false, error: result.status };
    }
  } catch (error) {
    console.error("Apple verification error:", error);
    return { valid: false, error: "Verification failed" };
  }
}

// GET - All upgrade requests (for admin)
// User model has: id, name, email (no phone - use PlanUpgradeRequest.phoneNumber)
app.get("/api/upgrade-requests", async (req, res) => {
  try {
    const { status } = req.query;

    const where = {};
    if (status) {
      where.status = status;
    }

    const requests = await prisma.planUpgradeRequest.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        currentPlan: true,
        requestedPlan: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(requests);
  } catch (error) {
    console.error("Error fetching upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// PUT - Update upgrade request status (admin only)
app.put("/api/upgrade-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;

    if (!status) {
      return res.status(400).json({ error: "Status is required" });
    }

    const request = await prisma.planUpgradeRequest.update({
      where: { id: parseInt(id) },
      data: { status, adminNotes },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
        currentPlan: true,
        requestedPlan: true,
      },
    });

    // If approved, update user's plan
    if (status === "APPROVED") {
      await prisma.user.update({
        where: { id: request.userId },
        data: { plan_id: request.requestedPlanId },
      });

      // Here you can send notification to user about approval
      console.log(
        `User ${request.userId} plan upgraded to ${request.requestedPlanId}`,
      );
    }

    res.json(request);
  } catch (error) {
    console.error("Error updating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// GET - User's upgrade requests
app.get("/api/users/:userId/upgrade-requests", async (req, res) => {
  try {
    const { userId } = req.params;

    const requests = await prisma.planUpgradeRequest.findMany({
      where: { userId: parseInt(userId) },
      include: {
        currentPlan: true,
        requestedPlan: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(requests);
  } catch (error) {
    console.error("Error fetching user upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// GET - All upgrade requests with filtering (FIXED)
app.get("/api/admin/upgrade-requests", async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;

    const where = {};
    if (status && status !== "ALL") {
      where.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [requests, total] = await Promise.all([
      prisma.planUpgradeRequest.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
            },
          },
        },
        orderBy: { createdAt: "desc" },
        skip,
        take: parseInt(limit),
      }),
      prisma.planUpgradeRequest.count({ where }),
    ]);

    // Get plan details for each request
    const requestsWithPlans = await Promise.all(
      requests.map(async (request) => {
        const currentPlan = await prisma.plans.findUnique({
          where: { id: request.currentPlanId },
        });

        const requestedPlan = await prisma.plans.findUnique({
          where: { id: request.requestedPlanId },
        });

        return {
          ...request,
          currentPlan,
          requestedPlan,
        };
      }),
    );

    res.json({
      requests: requestsWithPlans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Error fetching upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// GET - Single upgrade request details (FIXED)
app.get("/api/admin/upgrade-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const request = await prisma.planUpgradeRequest.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            createdAt: true,
          },
        },
        currentPlan: true,
        requestedPlan: true,
      },
    });

    if (!request) {
      return res.status(404).json({ error: "Upgrade request not found" });
    }

    // Get plan details
    const currentPlan = await prisma.plans.findUnique({
      where: { id: request.currentPlanId },
    });

    const requestedPlan = await prisma.plans.findUnique({
      where: { id: request.requestedPlanId },
    });

    const response = {
      ...request,
      currentPlan,
      requestedPlan,
    };

    res.json(response);
  } catch (error) {
    console.error("Error fetching upgrade request:", error);
    res.status(500).json({ error: error.message });
  }
});
// Backend route - Get products by user ID
app.get("/api/users/:userId/products", async (req, res) => {
  try {
    const { userId } = req.params;

    const products = await prisma.product.findMany({
      where: {
        userId: parseInt(userId),
      },
      orderBy: {
        createdAt: "desc",
      },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    res.json(products);
  } catch (error) {
    console.error("Error fetching user products:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/admin/upgrade-requests/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;

    if (!status || !["APPROVED", "REJECTED"].includes(status)) {
      return res
        .status(400)
        .json({ error: "Valid status (APPROVED/REJECTED) is required" });
    }

    // Get the request first
    const upgradeRequest = await prisma.planUpgradeRequest.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
      },
    });

    if (!upgradeRequest) {
      return res.status(404).json({ error: "Upgrade request not found" });
    }

    if (upgradeRequest.status !== "PENDING") {
      return res
        .status(400)
        .json({ error: "Request has already been processed" });
    }

    // Update the request status
    const updatedRequest = await prisma.planUpgradeRequest.update({
      where: { id: parseInt(id) },
      data: {
        status,
        adminNotes: adminNotes || null,
      },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
        currentPlan: true,
        requestedPlan: true,
      },
    });

    // If approved, update user's plan
    if (status === "APPROVED") {
      await prisma.user.update({
        where: { id: upgradeRequest.userId },
        data: { plan_id: upgradeRequest.requestedPlanId },
      });

      // Create a notification or log the upgrade
      console.log(
        `User ${upgradeRequest.userId} plan upgraded from ${upgradeRequest.currentPlanId} to ${upgradeRequest.requestedPlanId}`,
      );

      // Here you can send email/notification to user about approval
    }

    // Get plan details for response
    const currentPlan = await prisma.plans.findUnique({
      where: { id: upgradeRequest.currentPlanId },
    });

    const requestedPlan = await prisma.plans.findUnique({
      where: { id: upgradeRequest.requestedPlanId },
    });

    const response = {
      ...updatedRequest,
      currentPlan,
      requestedPlan,
      message:
        status === "APPROVED"
          ? "Plan upgraded successfully"
          : "Request rejected",
    };

    res.json(response);
  } catch (error) {
    console.error("Error updating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// GET - Upgrade request statistics
app.get("/api/admin/upgrade-requests/stats", async (req, res) => {
  try {
    const stats = await prisma.planUpgradeRequest.groupBy({
      by: ["status"],
      _count: {
        id: true,
      },
    });

    const total = await prisma.planUpgradeRequest.count();

    const pendingCount =
      stats.find((s) => s.status === "PENDING")?._count?.id || 0;
    const approvedCount =
      stats.find((s) => s.status === "APPROVED")?._count?.id || 0;
    const rejectedCount =
      stats.find((s) => s.status === "REJECTED")?._count?.id || 0;

    res.json({
      total,
      pending: pendingCount,
      approved: approvedCount,
      rejected: rejectedCount,
    });
  } catch (error) {
    console.error("Error fetching upgrade stats:", error);
    res.status(500).json({ error: error.message });
  }
});

// --- Get Products by User ID (Already existed implicitly, but defined here) ---
app.get("/api/users/:userId/products", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here to ensure only the owner or an admin can view this

  try {
    const products = await prisma.product.findMany({
      where: { ownerId: userId },
      // Select fields to return to minimize data transfer
      select: {
        id: true,
        name: true,
        image: true,
        status: true,
        price: true,
        inStock: true,
        rating: true,
        description: true,
      },
    });

    // You might want to process the image field here if it's stored as a comma-separated string
    const processedProducts = products.map((p) => ({
      ...p,
      // Basic image processing if needed (e.g., getting only the first image URL)
      image: p.image ? p.image.split(",")[0].trim() : null,
    }));

    res.json(processedProducts);
  } catch (error) {
    console.error("Error fetching user products:", error);
    res.status(500).json({ error: "Failed to fetch user products." });
  }
});

app.get("/api/users/:userId/businesses", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    const businesses = await prisma.business.findMany({
      where: { ownerId: userId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        location: true,
        description: true,
        status: true,
        category: true,
        image: true,
      },
    });

    res.json(businesses);
  } catch (error) {
    console.error("Error fetching user businesses:", error);
    res.status(500).json({ error: "Failed to fetch user businesses." });
  }
});

// NEW ROUTE: Count the number of Professional profiles for a specific user
app.get("/api/users/:userId/profiles/count", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    // Use prisma.professional.count() to efficiently get the number of records
    const profileCount = await prisma.professional.count({
      where: { userId: userId },
    });

    // Return the count directly
    res.json({ count: profileCount });
  } catch (error) {
    console.error("Error fetching user professional count:", error);
    res.status(500).json({ error: "Failed to fetch user professional count." });
  }
});

app.get("/api/users/:userId/profiles", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    const businesses = await prisma.professional.findMany({
      where: { ownerId: userId },
      // Select fields to return to minimize data transfer
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        location: true,
        description: true,
        status: true,
        category: true,
        image: true,
      },
    });

    // You might want to process the image field here if it's stored as a comma-separated string
    const processedBusinesses = businesses.map((b) => ({
      ...b,
      image: b.image ? b.image.split(",")[0].trim() : null,
    }));

    res.json(processedBusinesses);
  } catch (error) {
    console.error("Error fetching user businesses:", error);
    res.status(500).json({ error: "Failed to fetch user businesses." });
  }
});

app.get("/api/businesses/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.query;

    const whereClause = {
      ownerId: parseInt(userId),
    };

    // Add status filter if provided
    if (status) {
      whereClause.status = status.toUpperCase();
    }

    const businesses = await prisma.business.findMany({
      where: whereClause,
      select: {
        id: true,
        name: true,
        category: true,
        location: true,
        status: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(businesses);
  } catch (error) {
    console.error("Error fetching user businesses:", error);
    res.status(500).json({ error: "Failed to fetch businesses" });
  }
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
