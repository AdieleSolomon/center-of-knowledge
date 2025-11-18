import express from 'express';
import { createConnection, createPool } from 'mysql2/promise';
import bcrypt from 'bcryptjs';
const { hash, compare } = bcrypt;
import jwt from "jsonwebtoken";
const { sign, verify } = jwt;
import multer from 'multer';
import { join, extname } from 'path';
import cors from 'cors';
import { existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// ES module equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();
app.set('trust proxy', 1);

// Render-specific configuration
const isRender = process.env.RENDER === 'true';
const uploadsDir = isRender 
    ? '/opt/render/project/src/uploads' 
    : join(__dirname, 'uploads');

console.log('🔧 Environment:', process.env.NODE_ENV || 'development');
console.log('🏗️  Platform:', isRender ? 'Render' : 'Local');
console.log('📁 Uploads directory:', uploadsDir);

// Enhanced error handling for production
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'production' ? 200 : 1000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Create uploads directory if it doesn't exist
if (!existsSync(uploadsDir)) {
    mkdirSync(uploadsDir, { recursive: true });
    console.log('✅ Created uploads directory:', uploadsDir);
}

// FIXED: UPDATED CORS Configuration - More permissive for Vercel frontend
const allowedOrigins = process.env.NODE_ENV === 'production' 
    ? [
        'https://spiritual-center.vercel.app',
        'https://spiritualcenter-*.vercel.app',
        /https:\/\/spiritualcenter-.*\.vercel\.app$/,
        /https:\/\/.*-solomon-adeles-projects\.vercel\.app$/,
        /\.vercel\.app$/,  // Allow all Vercel deployments
        'https://spiritual-center.onrender.com' // Allow Render backend itself
    ]
    : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5000', 'http://127.0.0.1:3000'];

console.log('🌐 CORS Configuration:', {
    environment: process.env.NODE_ENV,
    allowedOrigins: allowedOrigins
});

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
            console.log('🔧 Request with no origin - allowing');
            return callback(null, true);
        }
        
        console.log('🔍 Checking CORS for origin:', origin);
        
        // Check if origin matches any allowed origins or patterns
        const isAllowed = allowedOrigins.some(allowed => {
            if (typeof allowed === 'string') {
                return origin === allowed;
            } else if (allowed instanceof RegExp) {
                return allowed.test(origin);
            }
            return false;
        });
        
        if (isAllowed) {
            console.log('✅ CORS allowed for:', origin);
            return callback(null, true);
        } else {
            console.log('🚫 CORS blocked for:', origin);
            console.log('📋 Allowed patterns:', allowedOrigins);
            return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

// Handle preflight requests
app.options('*', cors());

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(uploadsDir));

// FIXED: UPDATED Railway MySQL configuration - USING PUBLIC NETWORKING FROM YOUR SCREENSHOT
const getDbConfig = () => {
    // Priority 1: Use Public Networking connection (from your Railway screenshot)
    console.log('🔧 Using Public Networking for Railway MySQL');
    return {
        host: 'crossover.proxy.rfwy.net', // PUBLIC host from your screenshot
        user: process.env.MYSQLUSER || 'root',
        password: process.env.MYSQLPASSWORD || 'ShwaedPFnJeSXSqlkGKxFrIwAHtETXBl',
        database: process.env.MYSQLDATABASE || process.env.MYSQL_DATABASE || 'railway',
        port: 22317, // PUBLIC port from your screenshot (not 3306)
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
        connectTimeout: 60000,
        acquireTimeout: 60000,
        timeout: 60000,
    };
};

const dbConfig = getDbConfig();

// FIXED: Better environment variable logging
console.log('🔧 Database Configuration:', {
    environment: process.env.NODE_ENV || 'development',
    platform: 'Render + Railway MySQL (Public Networking)',
    host: dbConfig.host,
    database: dbConfig.database,
    port: dbConfig.port,
    user: dbConfig.user
});

// FIXED: Debug environment variables
console.log('🔍 Environment Variables Check:', {
    NODE_ENV: process.env.NODE_ENV || 'Not set',
    MYSQLHOST: process.env.MYSQLHOST ? 'Set' : 'Not set',
    MYSQLUSER: process.env.MYSQLUSER ? 'Set' : 'Not set', 
    MYSQLPASSWORD: process.env.MYSQLPASSWORD ? 'Set' : 'Not set',
    MYSQLDATABASE: process.env.MYSQLDATABASE ? 'Set' : 'Not set',
    MYSQL_DATABASE: process.env.MYSQL_DATABASE ? 'Set' : 'Not set',
    MYSQLPORT: process.env.MYSQLPORT ? 'Set' : 'Not set',
    MYSQL_URL: process.env.MYSQL_URL ? 'Set' : 'Not set',
    JWT_SECRET: process.env.JWT_SECRET ? 'Set' : 'Not set',
    RENDER: process.env.RENDER ? 'Set' : 'Not set'
});

// FIXED: Test MySQL connection with PUBLIC networking
async function testMySQLConnection() {
    try {
        console.log('🔄 Testing MySQL connection via Public Networking...');
        console.log('🔧 Connection details:', {
            host: dbConfig.host,
            user: dbConfig.user,
            database: dbConfig.database,
            port: dbConfig.port
        });
        
        const connection = await createConnection(dbConfig);
        
        const [rows] = await connection.execute('SELECT 1 as test_value, NOW() as current_time, DATABASE() as db_name, USER() as current_user');
        console.log('✅ MySQL test query successful:', rows);
        
        await connection.end();
        return true;
    } catch (err) {
        console.error('❌ MySQL Connection Error:', err.message);
        console.error('🔍 Connection details:', {
            host: dbConfig.host,
            database: dbConfig.database,
            port: dbConfig.port,
            errorCode: err.code,
            errno: err.errno,
            sqlState: err.sqlState
        });
        
        console.log('💡 Troubleshooting tips:');
        console.log('   1. Check if Railway MySQL service is running');
        console.log('   2. Verify the public hostname: crossover.proxy.rfwy.net');
        console.log('   3. Verify the public port: 22317');
        console.log('   4. Check MySQL credentials in Railway variables');
        
        return false;
    }
}

// Initialize database connection pool
let pool;

async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database connection via Public Networking...');
        
        // Test connection first
        const connectionTest = await testMySQLConnection();
        if (!connectionTest) {
            console.log('❌ Initial MySQL connection test failed');
            throw new Error('MySQL connection failed');
        }
        
        // Create connection pool with PUBLIC networking
        pool = createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            acquireTimeout: 60000,
            timeout: 60000
        });

        // Test pool connection with retry logic
        let retries = 3;
        while (retries > 0) {
            try {
                const testConn = await pool.getConnection();
                console.log('✅ Database connection pool successful');
                const [result] = await testConn.execute('SELECT DATABASE() as db_name, NOW() as server_time, USER() as user');
                console.log('📊 Connected to database:', result[0].db_name);
                console.log('👤 Connected as user:', result[0].user);
                testConn.release();
                break;
            } catch (error) {
                retries--;
                if (retries === 0) {
                    console.error('❌ Database connection failed after all retries:', error.message);
                    throw error;
                }
                console.log(`⚠️  Database connection failed, retrying... (${retries} attempts left)`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }

        // Create tables if they don't exist
        await createTables();
        console.log('✅ Database initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        console.log('💡 The server will start in limited mode (database operations will fail)');
        console.log('💡 Please check your Railway MySQL Public Networking connection');
        return false;
    }
}

async function createTables() {
    const connection = await pool.getConnection();
    
    try {
        // Users table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                is_approved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_approved (is_approved)
            )
        `);

        // Content table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS content (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                type ENUM('video', 'image', 'writeup') NOT NULL,
                file_url VARCHAR(500),
                content_text TEXT,
                is_public BOOLEAN DEFAULT FALSE,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_type (type),
                INDEX idx_public (is_public),
                INDEX idx_created_at (created_at)
            )
        `);

        // Prayer requests table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS prayer_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                subject VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                status ENUM('pending', 'read', 'responded') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_status (status),
                INDEX idx_created_at (created_at),
                INDEX idx_email (email)
            )
        `);

        // Check if admin user exists, if not create one
        const [adminUsers] = await connection.execute('SELECT id FROM users WHERE role = "admin" LIMIT 1');
        if (adminUsers.length === 0) {
            const hashedPassword = await hash('admin123', 12);
            await connection.execute(
                'INSERT INTO users (username, email, password_hash, role, is_approved) VALUES (?, ?, ?, ?, ?)',
                ['admin', 'Wisdomadiele57@gmail.com', hashedPassword, 'admin', true]
            );
            console.log('✅ Default admin user created');
            console.log('📧 Admin email: Wisdomadiele57@gmail.com');
            console.log('🔑 Admin password: admin123');
            if (process.env.NODE_ENV === 'production') {
                console.log('🚨 SECURITY: Change default admin password immediately!');
            }
        }

        console.log('✅ All tables created/verified successfully');
    } catch (error) {
        console.error('❌ Table creation error:', error);
        throw error;
    } finally {
        connection.release();
    }
}

// FIXED: Health check endpoint
app.get('/health', async (req, res) => {
    const healthCheck = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        platform: isRender ? 'Render' : 'Local',
        database: 'Unknown',
        version: '1.0.0',
        mysqlConnection: 'Testing...'
    };

    try {
        if (pool) {
            const [result] = await pool.execute('SELECT 1 as test_value');
            healthCheck.database = 'Connected';
            healthCheck.mysqlConnection = 'Healthy';
        } else {
            healthCheck.database = 'No pool';
            healthCheck.mysqlConnection = 'No connection pool';
            healthCheck.status = 'Degraded';
        }
    } catch (error) {
        healthCheck.database = 'Error: ' + error.message;
        healthCheck.mysqlConnection = 'Failed: ' + error.message;
        healthCheck.status = 'Degraded';
    }

    res.status(healthCheck.status === 'OK' ? 200 : 503).json(healthCheck);
});

// Simple test endpoint
app.get('/test', (req, res) => {
    res.json({ 
        message: 'Backend is running!', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        platform: isRender ? 'Render' : 'Local'
    });
});

// Debug endpoint to check environment
app.get('/debug', (req, res) => {
    res.json({
        environment: process.env.NODE_ENV,
        mysqlHost: dbConfig.host,
        mysqlUser: dbConfig.user,
        mysqlDatabase: dbConfig.database,
        mysqlPort: dbConfig.port,
        mysqlConnection: 'Public Networking',
        platform: isRender ? 'Render' : 'Local',
        timestamp: new Date().toISOString(),
        render: isRender
    });
});

app.get('/api/test-mysql', async (req, res) => {
    try {
        const connection = await createConnection(dbConfig);
        
        const [rows] = await connection.execute('SELECT 1 as test_value, NOW() as current_time, DATABASE() as db_name, USER() as user');
        await connection.end();
        
        res.json({ 
            message: 'MySQL connection successful via Public Networking',
            data: rows,
            connection: 'public-networking',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('MySQL connection test error:', error);
        res.status(500).json({ 
            error: 'MySQL connection failed: ' + error.message,
            code: 'MYSQL_CONNECTION_ERROR',
            details: {
                host: dbConfig.host,
                port: dbConfig.port,
                database: dbConfig.database,
                errorCode: error.code,
                errno: error.errno
            }
        });
    }
});

// Authentication routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }
        
        const hashedPassword = await hash(password, 12);
        
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash, role, is_approved) VALUES (?, ?, ?, "user", FALSE)',
            [username, email, hashedPassword]
        );
        
        res.status(201).json({ 
            message: 'Registration successful! Please wait for admin approval.',
            userId: result.insertId
        });
    } catch (error) {
        console.error('Registration error:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            if (error.message.includes('username')) {
                return res.status(400).json({ error: 'Username already exists' });
            } else if (error.message.includes('email')) {
                return res.status(400).json({ error: 'Email already exists' });
            }
        }
        
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const user = users[0];
        
        if (!user.is_approved) {
            return res.status(401).json({ error: 'Your account is pending admin approval' });
        }
        
        const isValidPassword = await compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // FIXED: Use JWT_SECRET from your .env
        const token = sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role 
            },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Content routes
app.get('/api/content', async (req, res) => {
    try {
        const [content] = await pool.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            ORDER BY c.created_at DESC
        `);
        
        res.json(content);
    } catch (error) {
        console.error('Content fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch content' });
    }
});

app.get('/api/content/public', async (req, res) => {
    try {
        const [content] = await pool.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            WHERE c.is_public = TRUE
            ORDER BY c.created_at DESC
        `);
        
        res.json(content);
    } catch (error) {
        console.error('Public content fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch public content' });
    }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    }
});

app.post('/api/content', upload.single('file'), async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { title, description, type, is_public, content_text } = req.body;
        
        let file_url = null;
        if (req.file) {
            file_url = `/uploads/${req.file.filename}`;
        }
        
        const [result] = await pool.execute(
            'INSERT INTO content (title, description, type, file_url, content_text, is_public, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [title, description, type, file_url, content_text, is_public === 'true', decoded.id]
        );
        
        res.status(201).json({ 
            message: 'Content uploaded successfully',
            contentId: result.insertId
        });
    } catch (error) {
        console.error('Content upload error:', error);
        res.status(500).json({ error: 'Failed to upload content' });
    }
});

// Prayer requests routes
app.post('/api/prayer-requests', async (req, res) => {
    try {
        const { name, email, subject, message, userId } = req.body;
        
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const [result] = await pool.execute(
            'INSERT INTO prayer_requests (name, email, subject, message, user_id) VALUES (?, ?, ?, ?, ?)',
            [name, email, subject, message, userId || null]
        );
        
        res.status(201).json({ 
            message: 'Prayer request submitted successfully',
            requestId: result.insertId
        });
    } catch (error) {
        console.error('Prayer request error:', error);
        res.status(500).json({ error: 'Failed to submit prayer request' });
    }
});

// Admin routes
app.get('/api/users', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const [users] = await pool.execute('SELECT id, username, email, role, is_approved, created_at FROM users ORDER BY created_at DESC');
        
        res.json(users);
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/prayer-requests', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const [requests] = await pool.execute(`
            SELECT pr.*, u.username 
            FROM prayer_requests pr 
            LEFT JOIN users u ON pr.user_id = u.id 
            ORDER BY pr.created_at DESC
        `);
        
        res.json(requests);
    } catch (error) {
        console.error('Prayer requests fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch prayer requests' });
    }
});

app.put('/api/users/:id/approve', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        await pool.execute(
            'UPDATE users SET is_approved = TRUE WHERE id = ?',
            [req.params.id]
        );
        
        res.json({ message: 'User approved successfully' });
    } catch (error) {
        console.error('User approval error:', error);
        res.status(500).json({ error: 'Failed to approve user' });
    }
});

app.put('/api/prayer-requests/:id/read', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        await pool.execute(
            'UPDATE prayer_requests SET status = "read" WHERE id = ?',
            [req.params.id]
        );
        
        res.json({ message: 'Prayer request marked as read' });
    } catch (error) {
        console.error('Prayer request update error:', error);
        res.status(500).json({ error: 'Failed to update prayer request' });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('User deletion error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.delete('/api/prayer-requests/:id', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: 'Authorization header required' });
        }
        
        const token = authHeader.replace('Bearer ', '');
        const decoded = verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        await pool.execute('DELETE FROM prayer_requests WHERE id = ?', [req.params.id]);
        
        res.json({ message: 'Prayer request deleted successfully' });
    } catch (error) {
        console.error('Prayer request deletion error:', error);
        res.status(500).json({ error: 'Failed to delete prayer request' });
    }
});

const PORT = process.env.PORT || 5000;

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔄 SIGTERM received, starting graceful shutdown');
    if (pool) {
        await pool.end();
        console.log('✅ Database pool closed');
    }
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🔄 SIGINT received, starting graceful shutdown');
    if (pool) {
        await pool.end();
        console.log('✅ Database pool closed');
    }
    process.exit(0);
});

// Initialize database and start server
async function startServer() {
    console.log('🚀 Starting Spiritual Center Backend API...');
    console.log('📊 Environment:', process.env.NODE_ENV || 'development');
    console.log('🏗️  Platform:', isRender ? 'Render' : 'Local');
    console.log('🔧 Port:', PORT);
    console.log('🗄️ Database Config: Public Networking');
    console.log('🔑 JWT Secret:', process.env.JWT_SECRET ? 'Set' : 'Not set');
    console.log('🌐 MySQL Host: crossover.proxy.rfwy.net:22317');
    
    // Initialize database (but don't block server startup)
    initializeDatabase().then(success => {
        if (success) {
            console.log('✅ Database initialized successfully');
        } else {
            console.log('⚠️  Database not available, but server is running');
            console.log('💡 The server will start but database operations will fail');
            console.log('💡 Check your Railway MySQL Public Networking connection');
        }
    });

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Backend API running on port ${PORT}`);
        console.log(`📚 API Base URL: http://localhost:${PORT}/api`);
        console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
        console.log(`🔧 Debug Info: http://localhost:${PORT}/debug`);
        console.log(`🗄️  MySQL Test: http://localhost:${PORT}/api/test-mysql`);
        
        if (isRender) {
            console.log('🎯 Render Deployment Ready!');
            console.log('🌐 Live URL: https://spiritual-center.onrender.com');
        }
        
        console.log(`👤 Default Admin: Wisdomadiele57@gmail.com / admin123`);
    });
}

startServer().catch(error => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});