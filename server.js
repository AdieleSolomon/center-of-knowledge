import express from "express";
import { createPool as createMySqlPool } from "mysql2/promise";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import multer from "multer";
import { join, extname } from "path";
import cors from "cors";
import { existsSync, mkdirSync, unlinkSync, createReadStream } from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// Initialize dotenv
dotenv.config();

const { Pool: PostgresPool } = pg;

const app = express();
const PORT = process.env.PORT || 5501;
const SUPABASE_PROVIDER_ALIASES = new Set(["postgres", "postgresql", "supabase"]);
const MYSQL_PROVIDER_ALIASES = new Set(["mysql", "laragon"]);

const resolveDbProvider = () => {
  const rawProvider = (process.env.DB_PROVIDER || "mysql").toLowerCase().trim();

  if (SUPABASE_PROVIDER_ALIASES.has(rawProvider)) {
    return "postgres";
  }

  if (MYSQL_PROVIDER_ALIASES.has(rawProvider)) {
    return "mysql";
  }

  console.warn(
    `Unknown DB_PROVIDER "${rawProvider}". Falling back to mysql (Laragon).`,
  );
  return "mysql";
};

const DB_PROVIDER = resolveDbProvider();
const IS_POSTGRES = DB_PROVIDER === "postgres";

const parseBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
};

const JWT_SECRET = process.env.JWT_SECRET || "spiritual-center-secret-key-2024";
const PASSWORD_RESET_TOKEN_TTL_MINUTES = Number(
  process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES || 30,
);
const ALLOW_PLAINTEXT_RESET_TOKEN = parseBoolean(
  process.env.ALLOW_PLAINTEXT_RESET_TOKEN,
  true,
);

const normalizeEmail = (value = "") => String(value).trim().toLowerCase();
const normalizeUsername = (value = "") => String(value).trim();
const isValidEmail = (value = "") =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value).trim());
const isStrongPassword = (value = "") => String(value).length >= 8;

const hashRecoveryToken = (rawToken) =>
  crypto.createHash("sha256").update(String(rawToken)).digest("hex");

const createRecoveryToken = () => {
  const rawToken = crypto.randomBytes(24).toString("hex");
  const hashedToken = hashRecoveryToken(rawToken);
  const expiresAt = new Date(
    Date.now() + PASSWORD_RESET_TOKEN_TTL_MINUTES * 60 * 1000,
  );

  return {
    rawToken,
    hashedToken,
    expiresAt,
  };
};

const signAuthToken = (user) =>
  jwt.sign(
    {
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: "24h" },
  );

const parseCsvEnv = (value = "") =>
  String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

const configuredCorsOrigins = new Set(
  [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    process.env.FRONTEND_URL,
    ...parseCsvEnv(process.env.CORS_ORIGINS),
  ].filter(Boolean),
);

const isAllowedCorsOrigin = (origin) => {
  if (!origin) {
    return true;
  }

  if (configuredCorsOrigins.has(origin)) {
    return true;
  }

  try {
    const { hostname } = new URL(origin);
    if (hostname.endsWith(".vercel.app")) {
      return true;
    }
  } catch (error) {
    return false;
  }

  return false;
};

// Get __dirname equivalent for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedCorsOrigin(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
  }),
);

const mysqlConfig = {
  host:
    process.env.LARAGON_HOST ||
    process.env.DB_HOST ||
    process.env.MYSQLHOST ||
    "localhost",
  user:
    process.env.LARAGON_USER ||
    process.env.DB_USER ||
    process.env.MYSQLUSER ||
    "root",
  password:
    process.env.LARAGON_PASSWORD ||
    process.env.DB_PASSWORD ||
    process.env.MYSQLPASSWORD ||
    "",
  database:
    process.env.LARAGON_DATABASE ||
    process.env.DB_NAME ||
    process.env.MYSQLDATABASE ||
    "spiritual_center",
  port: Number(
    process.env.LARAGON_PORT ||
      process.env.DB_PORT ||
      process.env.MYSQLPORT ||
      3306,
  ),
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  queueLimit: 0,
  charset: "utf8mb4",
};

if (parseBoolean(process.env.DB_SSL, false)) {
  mysqlConfig.ssl = { rejectUnauthorized: false };
}

const postgresSslEnabled = parseBoolean(
  process.env.SUPABASE_DB_SSL ?? process.env.POSTGRES_SSL ?? process.env.DB_SSL,
  true,
);

const supabaseConnectionString =
  process.env.SUPABASE_DATABASE_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_CONNECTION_STRING;

const postgresConfig = supabaseConnectionString
  ? {
      connectionString: supabaseConnectionString,
      max: Number(process.env.DB_CONNECTION_LIMIT || 10),
      ssl: postgresSslEnabled ? { rejectUnauthorized: false } : false,
    }
  : {
      host:
        process.env.SUPABASE_DB_HOST ||
        process.env.POSTGRES_HOST ||
        process.env.PGHOST ||
        "localhost",
      user:
        process.env.SUPABASE_DB_USER ||
        process.env.POSTGRES_USER ||
        process.env.PGUSER ||
        "postgres",
      password:
        process.env.SUPABASE_DB_PASSWORD ||
        process.env.POSTGRES_PASSWORD ||
        process.env.PGPASSWORD ||
        "",
      database:
        process.env.SUPABASE_DB_NAME ||
        process.env.POSTGRES_DB ||
        process.env.PGDATABASE ||
        "postgres",
      port: Number(
        process.env.SUPABASE_DB_PORT ||
          process.env.POSTGRES_PORT ||
          process.env.PGPORT ||
          5432,
      ),
      max: Number(process.env.DB_CONNECTION_LIMIT || 10),
      ssl: postgresSslEnabled ? { rejectUnauthorized: false } : false,
    };

const toPostgresPlaceholders = (sql) => {
  let paramIndex = 0;
  return sql.replace(/\?/g, () => `$${++paramIndex}`);
};

const normalizePostgresSql = (sql) => {
  let normalized = sql;

  normalized = normalized.replace(
    /DATE_SUB\(\s*NOW\(\)\s*,\s*INTERVAL\s+(\d+)\s+DAY\s*\)/gi,
    "NOW() - INTERVAL '$1 day'",
  );

  normalized = normalized.replace(
    /DATE_FORMAT\(\s*([^,]+?)\s*,\s*'%Y-%m-%d %H:%i:%s'\s*\)/gi,
    "TO_CHAR($1, 'YYYY-MM-DD HH24:MI:SS')",
  );

  normalized = normalized.replace(
    /HOUR\(\s*([^)]+?)\s*\)/gi,
    "EXTRACT(HOUR FROM $1)",
  );

  return normalized;
};

const appendReturningId = (sql) => {
  if (!/^\s*INSERT\s+INTO/i.test(sql) || /\bRETURNING\b/i.test(sql)) {
    return sql;
  }

  return `${sql.trim().replace(/;$/, "")} RETURNING id`;
};

const executePostgresQuery = async (target, sql, params = []) => {
  const isInsert = /^\s*INSERT\s+INTO/i.test(sql);
  let transformedSql = normalizePostgresSql(sql);
  transformedSql = toPostgresPlaceholders(transformedSql);
  transformedSql = isInsert ? appendReturningId(transformedSql) : transformedSql;

  const result = await target.query(transformedSql, params);

  if (isInsert) {
    return [
      {
        insertId: result.rows[0]?.id ?? null,
        affectedRows: result.rowCount,
      },
    ];
  }

  return [result.rows];
};

const createDatabasePool = () => {
  if (IS_POSTGRES) {
    const postgresPool = new PostgresPool(postgresConfig);

    return {
      execute: (sql, params = []) => executePostgresQuery(postgresPool, sql, params),
      getConnection: async () => {
        const client = await postgresPool.connect();
        return {
          execute: (sql, params = []) => executePostgresQuery(client, sql, params),
          release: () => client.release(),
        };
      },
      end: () => postgresPool.end(),
    };
  }

  return createMySqlPool(mysqlConfig);
};

const pool = createDatabasePool();

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = "uploads";
    if (!existsSync(uploadDir)) {
      mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.]/g, "_");
    cb(null, `material-${uniqueSuffix}-${safeName}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "video/mp4",
      "video/mkv",
      "video/avi",
      "video/mov",
      "video/webm",
      "image/jpeg",
      "image/png",
      "image/gif",
      "image/webp",
      "image/svg+xml",
      "audio/mpeg",
      "audio/wav",
      "audio/ogg",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "text/plain",
      "application/zip",
      "application/x-rar-compressed",
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${file.mimetype}`), false);
    }
  },
});

// ==================== DATABASE INITIALIZATION ====================
const UPSERT_SETTING_SQL = IS_POSTGRES
  ? `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON CONFLICT (setting_key) DO UPDATE
      SET setting_value = EXCLUDED.setting_value,
          setting_type = EXCLUDED.setting_type
    `
  : `
      INSERT INTO settings (setting_key, setting_value, setting_type)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE
        setting_value = VALUES(setting_value),
        setting_type = VALUES(setting_type)
    `;

const postgresSchemaStatements = [
  `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      reset_password_token VARCHAR(128),
      reset_password_expires TIMESTAMP,
      role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      is_approved BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)",
  "CREATE INDEX IF NOT EXISTS idx_users_role ON users (role)",
  `
    CREATE TABLE IF NOT EXISTS materials (
      id SERIAL PRIMARY KEY,
      title VARCHAR(500) NOT NULL,
      description TEXT,
      category VARCHAR(100),
      type VARCHAR(20) NOT NULL CHECK (type IN ('document', 'image', 'video', 'audio', 'writeup')),
      file_url VARCHAR(1000),
      file_name VARCHAR(255),
      file_size INTEGER,
      is_public BOOLEAN DEFAULT TRUE,
      uploader_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      views INTEGER DEFAULT 0,
      downloads INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_materials_category ON materials (category)",
  "CREATE INDEX IF NOT EXISTS idx_materials_type ON materials (type)",
  "CREATE INDEX IF NOT EXISTS idx_materials_public ON materials (is_public)",
  "CREATE INDEX IF NOT EXISTS idx_materials_search ON materials USING GIN (to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(description, '')))",
  `
    CREATE TABLE IF NOT EXISTS prayer_requests (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255),
      request TEXT NOT NULL,
      is_anonymous BOOLEAN DEFAULT FALSE,
      status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'read', 'responded')),
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_prayer_status ON prayer_requests (status)",
  "CREATE INDEX IF NOT EXISTS idx_prayer_created ON prayer_requests (created_at)",
  `
    CREATE TABLE IF NOT EXISTS donations (
      id SERIAL PRIMARY KEY,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'USD',
      donor_name VARCHAR(255) NOT NULL,
      donor_email VARCHAR(255) NOT NULL,
      message TEXT,
      payment_method VARCHAR(50) NOT NULL,
      transaction_id VARCHAR(100) UNIQUE,
      status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_donations_status ON donations (status)",
  "CREATE INDEX IF NOT EXISTS idx_donations_email ON donations (donor_email)",
  `
    CREATE TABLE IF NOT EXISTS analytics (
      id SERIAL PRIMARY KEY,
      event_type VARCHAR(50) NOT NULL,
      event_data JSONB,
      user_id INTEGER,
      user_agent TEXT,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics (event_type)",
  "CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics (created_at)",
  `
    CREATE TABLE IF NOT EXISTS settings (
      id SERIAL PRIMARY KEY,
      setting_key VARCHAR(100) NOT NULL UNIQUE,
      setting_value TEXT,
      setting_type VARCHAR(20) DEFAULT 'string' CHECK (setting_type IN ('string', 'number', 'boolean', 'json')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `,
  "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings (setting_key)",
];

const ensureUserAuthColumns = async (connection) => {
  if (IS_POSTGRES) {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR(128)",
    );
    await connection.execute(
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_expires TIMESTAMP",
    );
    return;
  }

  try {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN reset_password_token VARCHAR(128) NULL",
    );
  } catch (error) {
    if (error?.code !== "ER_DUP_FIELDNAME") {
      throw error;
    }
  }

  try {
    await connection.execute(
      "ALTER TABLE users ADD COLUMN reset_password_expires TIMESTAMP NULL",
    );
  } catch (error) {
    if (error?.code !== "ER_DUP_FIELDNAME") {
      throw error;
    }
  }
};

const ensureDefaultAdminUser = async (connection) => {
  const adminEmail =
    process.env.DEFAULT_ADMIN_EMAIL || "Wisdomadiele57@gmail.com";
  const adminRawPassword = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";
  const adminPassword = await bcrypt.hash(adminRawPassword, 12);

  const [emailMatches] = await connection.execute(
    "SELECT id FROM users WHERE email = ? LIMIT 1",
    [adminEmail],
  );

  if (emailMatches.length > 0) {
    await connection.execute(
      `
        UPDATE users
        SET password = ?,
            role = ?,
            is_approved = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [adminPassword, "admin", true, emailMatches[0].id],
    );
    return {
      email: adminEmail,
      password: adminRawPassword,
    };
  }

  const [usernameMatches] = await connection.execute(
    "SELECT id FROM users WHERE username = ? LIMIT 1",
    ["admin"],
  );

  if (usernameMatches.length > 0) {
    await connection.execute(
      `
        UPDATE users
        SET email = ?,
            password = ?,
            role = ?,
            is_approved = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [adminEmail, adminPassword, "admin", true, usernameMatches[0].id],
    );
    return {
      email: adminEmail,
      password: adminRawPassword,
    };
  }

  await connection.execute(
    "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
    ["admin", adminEmail, adminPassword, "admin", true],
  );

  return {
    email: adminEmail,
    password: adminRawPassword,
  };
};

const initializePostgresDatabase = async () => {
  let connection;

  try {
    connection = await pool.getConnection();
    await connection.execute("BEGIN");

    for (const statement of postgresSchemaStatements) {
      await connection.execute(statement);
    }

    await ensureUserAuthColumns(connection);

    await ensureDefaultAdminUser(connection);

    const defaultSettings = [
      ["site_title", "Spiritual Center", "string"],
      [
        "site_description",
        "Center of Knowledge and Spiritual Enrichment",
        "string",
      ],
      ["contact_email", "admin@spiritualcenter.com", "string"],
      ["contact_phone", "+234 907 256 0420", "string"],
      ["whatsapp_number", "+2349072560420", "string"],
      ["max_upload_size", "104857600", "number"],
      [
        "allowed_file_types",
        '["pdf","doc","docx","jpg","jpeg","png","gif","mp4","avi","mov","mp3","wav"]',
        "json",
      ],
    ];

    for (const [key, value, type] of defaultSettings) {
      await connection.execute(UPSERT_SETTING_SQL, [key, value, type]);
    }

    await connection.execute("COMMIT");
    console.log("Database initialized successfully (postgres)");
    return true;
  } catch (error) {
    if (connection) {
      try {
        await connection.execute("ROLLBACK");
      } catch (rollbackError) {
        console.error("Rollback failed:", rollbackError.message);
      }
    }

    console.error("Database initialization failed:", error.message);
    return false;
  } finally {
    if (connection && typeof connection.release === "function") {
      connection.release();
    }
  }
};

const initializeDatabase = async () => {
  if (IS_POSTGRES) {
    return initializePostgresDatabase();
  }

  try {
    const connection = await pool.getConnection();

    // Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        reset_password_token VARCHAR(128) NULL,
        reset_password_expires TIMESTAMP NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        is_approved BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_role (role)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await ensureUserAuthColumns(connection);

    // Materials table (simplified - using this as main content table)
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS materials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        type ENUM('document', 'image', 'video', 'audio', 'writeup') NOT NULL,
        file_url VARCHAR(1000),
        file_name VARCHAR(255),
        file_size INT,
        is_public BOOLEAN DEFAULT TRUE,
        uploader_id INT,
        views INT DEFAULT 0,
        downloads INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_category (category),
        INDEX idx_type (type),
        INDEX idx_public (is_public),
        FULLTEXT idx_search (title, description)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Prayer requests table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS prayer_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        request TEXT NOT NULL,
        is_anonymous BOOLEAN DEFAULT FALSE,
        status ENUM('pending', 'read', 'responded') DEFAULT 'pending',
        user_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_status (status),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Donations table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS donations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        amount DECIMAL(10,2) NOT NULL,
        currency VARCHAR(10) DEFAULT 'USD',
        donor_name VARCHAR(255) NOT NULL,
        donor_email VARCHAR(255) NOT NULL,
        message TEXT,
        payment_method VARCHAR(50) NOT NULL,
        transaction_id VARCHAR(100) UNIQUE,
        status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_status (status),
        INDEX idx_email (donor_email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Analytics table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS analytics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        event_data JSON,
        user_id INT,
        user_agent TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_event_type (event_type),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Settings table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        setting_key VARCHAR(100) NOT NULL UNIQUE,
        setting_value TEXT,
        setting_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_key (setting_key)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Create default admin user
    await ensureDefaultAdminUser(connection);

    // Insert default settings
    const defaultSettings = [
      ["site_title", "Spiritual Center", "string"],
      [
        "site_description",
        "Center of Knowledge and Spiritual Enrichment",
        "string",
      ],
      ["contact_email", "admin@spiritualcenter.com", "string"],
      ["contact_phone", "+234 907 256 0420", "string"],
      ["whatsapp_number", "+2349072560420", "string"],
      ["max_upload_size", "104857600", "number"], // 100MB in bytes
      [
        "allowed_file_types",
        '["pdf","doc","docx","jpg","jpeg","png","gif","mp4","avi","mov","mp3","wav"]',
        "json",
      ],
    ];

    for (const [key, value, type] of defaultSettings) {
      await connection.execute(UPSERT_SETTING_SQL, [key, value, type]);
    }

    connection.release();
    console.log("✅ Database initialized successfully");
    return true;
  } catch (error) {
    console.error("❌ Database initialization failed:", error.message);
    return false;
  }
};

// ==================== ADMIN DASHBOARD ENDPOINTS ====================

// Get comprehensive dashboard stats
app.get("/api/admin/stats", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    // Get all stats in parallel
    const [
      [{ total_users } = { total_users: 0 }],
      [{ total_materials } = { total_materials: 0 }],
      [{ total_prayers } = { total_prayers: 0 }],
      [{ pending_prayers } = { pending_prayers: 0 }],
      [
        { total_donations, total_amount } = {
          total_donations: 0,
          total_amount: 0,
        },
      ],
      [{ recent_uploads } = { recent_uploads: 0 }],
      [{ active_users } = { active_users: 0 }],
    ] = await Promise.all([
      pool
        .execute("SELECT COUNT(*) as total_users FROM users")
        .then((r) => r[0]),
      pool
        .execute("SELECT COUNT(*) as total_materials FROM materials")
        .then((r) => r[0]),
      pool
        .execute("SELECT COUNT(*) as total_prayers FROM prayer_requests")
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as pending_prayers FROM prayer_requests WHERE status = 'pending'",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as total_donations, COALESCE(SUM(amount), 0) as total_amount FROM donations WHERE status = 'completed'",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(*) as recent_uploads FROM materials WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
        )
        .then((r) => r[0]),
      pool
        .execute(
          "SELECT COUNT(DISTINCT user_id) as active_users FROM analytics WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) AND user_id IS NOT NULL",
        )
        .then((r) => r[0]),
    ]);

    // Get storage used
    const [storageResult] = await pool.execute(
      "SELECT COALESCE(SUM(file_size), 0) as total_size FROM materials WHERE file_size IS NOT NULL",
    );
    const storage_used =
      Math.round(
        ((storageResult[0]?.total_size || 0) / (1024 * 1024 * 1024)) * 100,
      ) / 100; // GB

    // Get recent materials
    const [recentMaterials] = await pool.execute(`
      SELECT m.id, m.title, m.type, m.created_at, u.username as uploader
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      ORDER BY m.created_at DESC
      LIMIT 5
    `);

    // Get top materials by views
    const [topMaterials] = await pool.execute(`
      SELECT id, title, views, downloads
      FROM materials
      ORDER BY views DESC
      LIMIT 5
    `);

    res.json({
      success: true,
      stats: {
        total_users,
        total_materials,
        total_prayers,
        pending_prayers,
        total_donations,
        total_amount: parseFloat(total_amount),
        recent_uploads,
        active_users,
        storage_used: `${storage_used} GB`,
        engagement_rate:
          total_users > 0 ? Math.round((active_users / total_users) * 100) : 0,
      },
      recent_materials: recentMaterials,
      top_materials: topMaterials,
      updated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Dashboard stats error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch dashboard stats",
      details: error.message,
    });
  }
});

// ==================== MATERIALS ENDPOINTS ====================

// Upload material
app.post(
  "/api/materials/upload",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Admin access required" });
      }

      const {
        title,
        description,
        category,
        type,
        is_public = "true",
      } = req.body;
      const userId = req.user.userId;

      // Validation
      if (!title || !description || !category || !type) {
        if (req.file) {
          unlinkSync(req.file.path);
        }
        return res.status(400).json({
          success: false,
          error: "All fields are required",
        });
      }

      if (!req.file && type !== "writeup") {
        return res.status(400).json({
          success: false,
          error: "File is required for this material type",
        });
      }

      let fileUrl = null;
      let fileName = null;
      let fileSize = null;

      if (req.file) {
        fileUrl = `/uploads/${req.file.filename}`;
        fileName = req.file.originalname;
        fileSize = req.file.size;
      }

      // Insert material
      const [result] = await pool.execute(
        `
      INSERT INTO materials 
        (title, description, category, type, file_url, file_name, file_size, is_public, uploader_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
        [
          title,
          description,
          category,
          type,
          fileUrl,
          fileName,
          fileSize,
          is_public === "true",
          userId,
        ],
      );

      // Log analytics
      await pool.execute(
        "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
        [
          "material_upload",
          JSON.stringify({ material_id: result.insertId, title, type }),
          userId,
        ],
      );

      res.status(201).json({
        success: true,
        message: "Material uploaded successfully",
        material: {
          id: result.insertId,
          title,
          category,
          type,
          file_url: fileUrl,
          created_at: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error("Material upload error:", error);
      if (req.file && req.file.path) {
        unlinkSync(req.file.path);
      }
      res.status(500).json({
        success: false,
        error: "Failed to upload material",
        details: error.message,
      });
    }
  },
);

// Get all materials (for admin)
app.get("/api/materials", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const {
      search = "",
      category = "",
      type = "",
      page = 1,
      limit = 20,
    } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const parsedLimit = parseInt(limit);
    const parsedPage = parseInt(page);

    // Build WHERE clause conditions and params
    let whereConditions = "";
    const filterParams = [];

    if (search) {
      whereConditions += ` AND (m.title LIKE ? OR m.description LIKE ?)`;
      filterParams.push(`%${search}%`, `%${search}%`);
    }

    if (category) {
      whereConditions += ` AND m.category = ?`;
      filterParams.push(category);
    }

    if (type) {
      whereConditions += ` AND m.type = ?`;
      filterParams.push(type);
    }

    // Get total count first
    const countQuery = `
      SELECT COUNT(*) as total
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      WHERE 1=1 ${whereConditions}
    `;
    const [countResult] = await pool.execute(countQuery, filterParams);
    const total = countResult[0]?.total || 0;

    // Get paginated materials
    const query = `
      SELECT 
        m.*,
        u.username as uploader_name,
        u.email as uploader_email,
        DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i:%s') as formatted_date
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      WHERE 1=1 ${whereConditions}
      ORDER BY m.created_at DESC
      LIMIT ? OFFSET ?
    `;

    // Create params array for main query
    const mainQueryParams = [...filterParams, parsedLimit, offset];
    const [materials] = await pool.execute(query, mainQueryParams);

    res.json({
      success: true,
      materials,
      pagination: {
        page: parsedPage,
        limit: parsedLimit,
        total,
        pages: Math.ceil(total / parsedLimit),
      },
    });
  } catch (error) {
    console.error("Get materials error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch materials",
      details: error.message,
    });
  }
});

// Get single material
app.get("/api/materials/:id", authenticateToken, async (req, res) => {
  try {
    const materialId = req.params.id;

    const [materials] = await pool.execute(
      `
      SELECT 
        m.*,
        u.username as uploader_name,
        u.email as uploader_email
      FROM materials m
      LEFT JOIN users u ON m.uploader_id = u.id
      WHERE m.id = ?
    `,
      [materialId],
    );

    if (materials.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Increment view count
    await pool.execute("UPDATE materials SET views = views + 1 WHERE id = ?", [
      materialId,
    ]);

    res.json({
      success: true,
      material: materials[0],
    });
  } catch (error) {
    console.error("Get material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch material",
      details: error.message,
    });
  }
});

// Update material
app.put("/api/materials/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const materialId = req.params.id;
    const { title, description, category, type, is_public } = req.body;

    // Check if material exists
    const [existing] = await pool.execute(
      "SELECT id FROM materials WHERE id = ?",
      [materialId],
    );

    if (existing.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Update material
    await pool.execute(
      `
      UPDATE materials 
      SET title = ?, description = ?, category = ?, type = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
      [title, description, category, type, is_public === "true", materialId],
    );

    // Log analytics
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "material_update",
        JSON.stringify({ material_id: materialId }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Material updated successfully",
    });
  } catch (error) {
    console.error("Update material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update material",
      details: error.message,
    });
  }
});

// Delete material
app.delete("/api/materials/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const materialId = req.params.id;

    // Get material details
    const [materials] = await pool.execute(
      "SELECT file_url FROM materials WHERE id = ?",
      [materialId],
    );

    if (materials.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Material not found",
      });
    }

    // Delete file if exists
    if (materials[0].file_url) {
      const filePath = join(__dirname, materials[0].file_url);
      if (existsSync(filePath)) {
        unlinkSync(filePath);
      }
    }

    // Delete from database
    await pool.execute("DELETE FROM materials WHERE id = ?", [materialId]);

    // Log analytics
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "material_delete",
        JSON.stringify({ material_id: materialId }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Material deleted successfully",
    });
  } catch (error) {
    console.error("Delete material error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to delete material",
      details: error.message,
    });
  }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get comprehensive analytics
app.get("/api/analytics", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { period = "7d" } = req.query;
    let dateFilter = "";

    switch (period) {
      case "1d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)";
        break;
      case "7d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
        break;
      case "30d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
        break;
      case "90d":
        dateFilter = "AND created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)";
        break;
    }

    // Get user growth
    const [userGrowth] = await pool.execute(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as new_users
      FROM users 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    // Get material growth
    const [materialGrowth] = await pool.execute(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as new_materials,
        SUM(CASE WHEN type = 'video' THEN 1 ELSE 0 END) as videos,
        SUM(CASE WHEN type = 'document' THEN 1 ELSE 0 END) as documents,
        SUM(CASE WHEN type = 'image' THEN 1 ELSE 0 END) as images,
        SUM(CASE WHEN type = 'audio' THEN 1 ELSE 0 END) as audio
      FROM materials 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date
    `);

    // Get top materials by views
    const [topMaterials] = await pool.execute(`
      SELECT 
        id, title, type, views, downloads,
        ROUND(downloads * 100.0 / NULLIF(views, 0), 2) as conversion_rate
      FROM materials
      ORDER BY views DESC
      LIMIT 10
    `);

    // Get activity by hour
    const [activityByHour] = await pool.execute(`
      SELECT 
        HOUR(created_at) as hour,
        COUNT(*) as activity_count
      FROM analytics
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY HOUR(created_at)
      ORDER BY hour
    `);

    // Get event breakdown
    const [eventBreakdown] = await pool.execute(`
      SELECT 
        event_type,
        COUNT(*) as count
      FROM analytics
      WHERE 1=1 ${dateFilter}
      GROUP BY event_type
      ORDER BY count DESC
    `);

    // Get real-time stats (last 24 hours)
    const [realtimeStats] = await pool.execute(`
      SELECT 
        COUNT(DISTINCT user_id) as active_users_today,
        COUNT(CASE WHEN event_type = 'material_view' THEN 1 END) as views_today,
        COUNT(CASE WHEN event_type = 'material_download' THEN 1 END) as downloads_today,
        COUNT(CASE WHEN event_type = 'login' THEN 1 END) as logins_today
      FROM analytics
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
    `);

    res.json({
      success: true,
      analytics: {
        user_growth: userGrowth,
        material_growth: materialGrowth,
        top_materials: topMaterials,
        activity_by_hour: activityByHour,
        event_breakdown: eventBreakdown,
        realtime: realtimeStats[0] || {},
      },
      period,
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch analytics",
      details: error.message,
    });
  }
});

// Record analytics event
app.post("/api/analytics/event", async (req, res) => {
  try {
    const { event_type, event_data, user_id } = req.body;
    const userAgent = req.headers["user-agent"];
    const ip = req.ip || req.connection.remoteAddress;

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id, user_agent, ip_address) VALUES (?, ?, ?, ?, ?)",
      [event_type, JSON.stringify(event_data), user_id, userAgent, ip],
    );

    res.json({ success: true });
  } catch (error) {
    console.error("Analytics event error:", error);
    res.status(500).json({ success: false, error: "Failed to record event" });
  }
});

// ==================== SETTINGS ENDPOINTS ====================

// Get all settings
app.get("/api/settings", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const [settings] = await pool.execute(
      "SELECT setting_key, setting_value, setting_type FROM settings ORDER BY setting_key",
    );

    const formattedSettings = {};
    settings.forEach((setting) => {
      let value = setting.setting_value;
      if (setting.setting_type === "json") {
        try {
          value = JSON.parse(value);
        } catch (e) {
          value = value;
        }
      } else if (setting.setting_type === "number") {
        value = Number(value);
      } else if (setting.setting_type === "boolean") {
        value = value === "true";
      }
      formattedSettings[setting.setting_key] = value;
    });

    res.json({
      success: true,
      settings: formattedSettings,
    });
  } catch (error) {
    console.error("Get settings error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch settings",
      details: error.message,
    });
  }
});

// Update settings
app.put("/api/settings", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const settings = req.body;
    const updates = [];

    for (const [key, value] of Object.entries(settings)) {
      let settingType = "string";
      let settingValue = value;

      if (typeof value === "boolean") {
        settingType = "boolean";
        settingValue = value.toString();
      } else if (typeof value === "number") {
        settingType = "number";
        settingValue = value.toString();
      } else if (typeof value === "object") {
        settingType = "json";
        settingValue = JSON.stringify(value);
      }

      updates.push(
        pool.execute(
          UPSERT_SETTING_SQL,
          [key, settingValue, settingType],
        ),
      );
    }

    await Promise.all(updates);

    // Log settings change
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "settings_update",
        JSON.stringify({ settings: Object.keys(settings) }),
        req.user.userId,
      ],
    );

    res.json({
      success: true,
      message: "Settings updated successfully",
    });
  } catch (error) {
    console.error("Update settings error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update settings",
      details: error.message,
    });
  }
});

// ==================== NOTIFICATIONS ENDPOINTS ====================

// Get notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { unread = false } = req.query;

    let query = `
      SELECT 
        n.*,
        u.username as from_user,
        u.email as from_email
      FROM (
        -- Prayer request notifications
        SELECT 
          id as source_id,
          'prayer_request' as type,
          CONCAT('New prayer request from ', COALESCE(name, 'Anonymous')) as title,
          SUBSTRING(request, 1, 100) as message,
          created_at,
          FALSE as is_read,
          user_id as from_user_id
        FROM prayer_requests
        WHERE status = 'pending'
        
        UNION ALL
        
        -- User registration notifications
        SELECT 
          id as source_id,
          'user_registration' as type,
          CONCAT('New user registration: ', username) as title,
          email as message,
          created_at,
          FALSE as is_read,
          id as from_user_id
        FROM users
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) AND role = 'user'
        
        UNION ALL
        
        -- System notifications
        SELECT 
          id as source_id,
          'system' as type,
          'System Update' as title,
          'Your system is running smoothly' as message,
          NOW() as created_at,
          TRUE as is_read,
          NULL as from_user_id
        FROM (SELECT 1 as id) as dummy
        LIMIT 1
      ) as n
      LEFT JOIN users u ON n.from_user_id = u.id
    `;

    if (unread === "true") {
      query += " WHERE n.is_read = FALSE";
    }

    query += " ORDER BY n.created_at DESC LIMIT 50";

    const [notifications] = await pool.execute(query);

    // Count unread notifications
    const [unreadCountResult] = await pool.execute(`
      SELECT COUNT(*) as count FROM prayer_requests WHERE status = 'pending'
    `);
    const unread_count = unreadCountResult[0]?.count || 0;

    res.json({
      success: true,
      notifications,
      unread_count,
      total: notifications.length,
    });
  } catch (error) {
    console.error("Get notifications error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch notifications",
      details: error.message,
    });
  }
});

// Mark notification as read
app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const notificationId = req.params.id;
    const { type } = req.body;

    if (type === "prayer_request") {
      await pool.execute(
        "UPDATE prayer_requests SET status = 'read' WHERE id = ?",
        [notificationId],
      );
    }

    res.json({
      success: true,
      message: "Notification marked as read",
    });
  } catch (error) {
    console.error("Mark notification read error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to mark notification as read",
      details: error.message,
    });
  }
});

// Clear all notifications
app.delete("/api/notifications", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    // Mark all prayer requests as read
    await pool.execute(
      "UPDATE prayer_requests SET status = 'read' WHERE status = 'pending'",
    );

    res.json({
      success: true,
      message: "All notifications cleared",
    });
  } catch (error) {
    console.error("Clear notifications error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to clear notifications",
      details: error.message,
    });
  }
});

// ==================== AUTH ENDPOINTS ====================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    const normalizedEmail = normalizeEmail(email);
    const normalizedUsername = normalizeUsername(username);

    if (!normalizedUsername || !normalizedEmail || !password) {
      return res.status(400).json({
        success: false,
        error: "Username, email, and password are required",
      });
    }

    if (normalizedUsername.length < 3 || normalizedUsername.length > 100) {
      return res.status(400).json({
        success: false,
        error: "Username must be between 3 and 100 characters",
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters long",
      });
    }

    if (
      typeof confirmPassword === "string" &&
      confirmPassword.length > 0 &&
      password !== confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        error: "Password confirmation does not match",
      });
    }

    const [existingUsers] = await pool.execute(
      "SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1",
      [normalizedEmail, normalizedUsername],
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        error: "An account already exists with that email or username",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const [insertResult] = await pool.execute(
      "INSERT INTO users (username, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)",
      [normalizedUsername, normalizedEmail, passwordHash, "user", true],
    );

    let userId = insertResult?.insertId || null;
    if (!userId) {
      const [createdUsers] = await pool.execute(
        "SELECT id FROM users WHERE email = ? LIMIT 1",
        [normalizedEmail],
      );
      userId = createdUsers[0]?.id || null;
    }

    const user = {
      id: userId,
      username: normalizedUsername,
      email: normalizedEmail,
      role: "user",
      is_approved: true,
    };

    const token = signAuthToken(user);

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["register", JSON.stringify({ method: "email_password" }), user.id],
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user,
    });
  } catch (error) {
    if (error?.code === "ER_DUP_ENTRY" || error?.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "An account already exists with that email or username",
      });
    }

    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to create account",
      details: error.message,
    });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const normalizedEmail = normalizeEmail(req.body?.email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, email FROM users WHERE email = ? LIMIT 1",
      [normalizedEmail],
    );

    const genericResponse = {
      success: true,
      message:
        "If the account exists, password recovery instructions have been generated.",
    };

    if (users.length === 0) {
      return res.json(genericResponse);
    }

    const user = users[0];
    const { rawToken, hashedToken, expiresAt } = createRecoveryToken();

    await pool.execute(
      "UPDATE users SET reset_password_token = ?, reset_password_expires = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [hashedToken, expiresAt, user.id],
    );

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      [
        "password_reset_requested",
        JSON.stringify({ channel: "self_service", email: normalizedEmail }),
        user.id,
      ],
    );

    if (ALLOW_PLAINTEXT_RESET_TOKEN) {
      return res.json({
        ...genericResponse,
        recovery_code: rawToken,
        expires_at: expiresAt.toISOString(),
      });
    }

    return res.json(genericResponse);
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to process password recovery request",
      details: error.message,
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, recoveryCode, newPassword, confirmPassword } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid email address",
      });
    }

    if (!recoveryCode) {
      return res.status(400).json({
        success: false,
        error: "Recovery code is required",
      });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        error: "New password must be at least 8 characters long",
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: "Password confirmation does not match",
      });
    }

    const [users] = await pool.execute(
      "SELECT id, username, email, role, is_approved, reset_password_token, reset_password_expires FROM users WHERE email = ? LIMIT 1",
      [normalizedEmail],
    );

    if (users.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const user = users[0];
    const storedToken = user.reset_password_token;
    const storedExpiry = user.reset_password_expires;
    const hashedProvidedToken = hashRecoveryToken(recoveryCode);

    if (!storedToken || !storedExpiry) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const expiryDate = new Date(storedExpiry);
    const isExpired =
      Number.isNaN(expiryDate.getTime()) || expiryDate.getTime() < Date.now();

    if (isExpired || storedToken !== hashedProvidedToken) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired recovery code",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await pool.execute(
      "UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [hashedPassword, user.id],
    );

    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["password_reset", JSON.stringify({ method: "recovery_code" }), user.id],
    );

    const authUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      is_approved: user.is_approved,
    };
    const token = signAuthToken(authUser);

    res.json({
      success: true,
      message: "Password reset successful",
      token,
      user: authUser,
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to reset password",
      details: error.message,
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const rawIdentifier =
      typeof email === "string" && email.trim().length > 0 ? email : username;
    const normalizedIdentifier = String(rawIdentifier || "")
      .trim()
      .toLowerCase();

    if (!normalizedIdentifier || !password) {
      return res.status(400).json({
        error: "Email/username and password are required",
      });
    }

    const [users] = await pool.execute(
      "SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ? LIMIT 1",
      [normalizedIdentifier, normalizedIdentifier],
    );

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check if user is approved
    if (!user.is_approved && user.role !== "admin") {
      return res
        .status(401)
        .json({ error: "Your account is pending admin approval" });
    }

    // Generate JWT token
    const token = signAuthToken(user);

    // Log login event
    await pool.execute(
      "INSERT INTO analytics (event_type, event_data, user_id) VALUES (?, ?, ?)",
      ["login", JSON.stringify({ method: "email" }), user.id],
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_approved: user.is_approved,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

// Validate token
app.get("/api/auth/validate", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const [users] = await pool.execute(
      "SELECT id, username, email, role, is_approved FROM users WHERE id = ?",
      [userId],
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.json({
      success: true,
      user: users[0],
    });
  } catch (error) {
    console.error("Validate token error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to validate token",
      details: error.message,
    });
  }
});

// ==================== USERS ENDPOINTS ====================

app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const {
      search = "",
      role = "",
      status = "",
      page = 1,
      limit = 20,
    } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = `
      SELECT 
        id, username, email, role, is_approved,
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
        DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') as updated_at
      FROM users
      WHERE 1=1
    `;
    const params = [];

    if (search) {
      query += ` AND (username LIKE ? OR email LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }

    if (role) {
      query += ` AND role = ?`;
      params.push(role);
    }

    if (status === "approved") {
      query += ` AND is_approved = TRUE`;
    } else if (status === "pending") {
      query += ` AND is_approved = FALSE`;
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), offset);

    const [users] = await pool.execute(query, params);

    // Get total count
    const [countResult] = await pool.execute(
      query
        .split("ORDER BY")[0]
        .replace(
          "SELECT id, username, email, role, is_approved, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at, DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') as updated_at",
          "SELECT COUNT(*) as total",
        ),
      params.slice(0, -2),
    );
    const total = countResult[0]?.total || 0;

    res.json({
      success: true,
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch users",
      details: error.message,
    });
  }
});

// ==================== PRAYER REQUESTS ENDPOINTS ====================

app.get("/api/prayer-requests", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

    const { status = "", search = "", page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = `
      SELECT 
        pr.*,
        u.username as user_name,
        u.email as user_email,
        DATE_FORMAT(pr.created_at, '%Y-%m-%d %H:%i:%s') as created_at
      FROM prayer_requests pr
      LEFT JOIN users u ON pr.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      query += ` AND pr.status = ?`;
      params.push(status);
    }

    if (search) {
      query += ` AND (pr.name LIKE ? OR pr.request LIKE ? OR pr.email LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ` ORDER BY pr.created_at DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), offset);

    const [prayers] = await pool.execute(query, params);

    // Get counts by status
    const [counts] = await pool.execute(`
      SELECT 
        status,
        COUNT(*) as count
      FROM prayer_requests
      GROUP BY status
    `);

    const statusCounts = {};
    counts.forEach((item) => {
      statusCounts[item.status] = item.count;
    });

    res.json({
      success: true,
      prayer_requests: prayers,
      counts: statusCounts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: prayers.length,
      },
    });
  } catch (error) {
    console.error("Get prayer requests error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch prayer requests",
      details: error.message,
    });
  }
});

// ==================== HEALTH & MONITORING ====================

// Health check endpoint
app.get("/api/health", async (req, res) => {
  try {
    // Test database connection
    await pool.execute("SELECT 1");

    // Check uploads directory
    const uploadsDir = join(__dirname, "uploads");
    const uploadsExists = existsSync(uploadsDir);

    if (!uploadsExists) {
      mkdirSync(uploadsDir, { recursive: true });
    }

    // Get system info
    const systemInfo = {
      node_version: process.version,
      platform: process.platform,
      memory_usage: process.memoryUsage(),
      uptime: process.uptime(),
      database: `connected (${DB_PROVIDER})`,
      uploads_directory: uploadsExists ? "exists" : "created",
    };

    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      system: systemInfo,
    });
  } catch (error) {
    res.status(500).json({
      status: "unhealthy",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Connection test endpoint
app.get("/api/connection-test", (req, res) => {
  res.json({
    success: true,
    message: "Backend connection successful",
    backend: "Spiritual Center API",
    version: "2.0.0",
    database_provider: DB_PROVIDER,
    timestamp: new Date().toISOString(),
    endpoints: {
      admin: "/api/admin/stats",
      materials: "/api/materials",
      analytics: "/api/analytics",
      settings: "/api/settings",
      notifications: "/api/notifications",
      users: "/api/users",
      auth_login: "/api/auth/login",
      auth_register: "/api/auth/register",
      auth_forgot_password: "/api/auth/forgot-password",
      auth_reset_password: "/api/auth/reset-password",
    },
  });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
    path: req.path,
    method: req.method,
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("Global error:", error);

  if (error.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      success: false,
      error: "File too large. Maximum size is 100MB",
    });
  }

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      error: "File upload error",
      details: error.message,
    });
  }

  res.status(500).json({
    success: false,
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? error.message : undefined,
  });
});

// ==================== SERVER STARTUP ====================

process.on("uncaughtException", (error) => {
  console.error("💥 Uncaught Exception:", error);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("💥 Unhandled Rejection at:", promise, "reason:", reason);
});

// Initialize and start server
(async () => {
  console.log(`DB provider selected: ${DB_PROVIDER}`);
  console.log("🔄 Starting server initialization...");

  try {
    console.log("🔄 Initializing database...");
    const dbInitialized = await initializeDatabase();

    if (dbInitialized) {
      console.log("✅ Database initialization complete");
    } else {
      console.log("⚠️  Database initialization had issues");
    }

    // Create uploads directory if it doesn't exist
    const uploadsDir = join(__dirname, "uploads");
    if (!existsSync(uploadsDir)) {
      mkdirSync(uploadsDir, { recursive: true });
      console.log("✅ Created uploads directory");
    }

    const server = app.listen(PORT, () => {
      console.log(`✅ Server running on http://localhost:${PORT}`);
      console.log(
        `🚀 Admin Dashboard: http://localhost:${PORT}/admin-dashboard.html`,
      );
      console.log(`📊 API Base URL: http://localhost:${PORT}/api`);
      console.log(`📁 Uploads: http://localhost:${PORT}/uploads`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`DB provider: ${DB_PROVIDER}`);
      console.log("✨ Server is ready!");
    });

    server.on("error", (error) => {
      console.error("🔴 Server error:", error);
      if (error.code === "EADDRINUSE") {
        console.log(
          `Port ${PORT} is already in use. Trying ${Number(PORT) + 1}...`,
        );
        app.listen(Number(PORT) + 1);
      }
    });
  } catch (error) {
    console.error("🔴 Failed to start server:", error);
    process.exit(1);
  }
})();

