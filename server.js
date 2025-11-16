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

// Security middleware for production
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'"]
        }
    }
}));

// Rate limiting - stricter for production
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
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

// CORS configuration for production
const allowedOrigins = process.env.NODE_ENV === 'production' 
    ? [
        'https://spiritual-center.onrender.com',
        'https://spiritual-center.com',
        'https://www.spiritual-center.com'
      ].filter(Boolean)
    : ['http://localhost:3000', 'http://localhost:5000', 'http://localhost:3001'];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            console.log('🚫 CORS blocked origin:', origin);
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(uploadsDir));

// Serve static files from public directory
app.use(express.static(join(__dirname, 'public'), {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
    etag: true,
    lastModified: true
}));

// Database configuration for Render (compatible with external MySQL services)
const dbConfig = {
    host: process.env.DB_HOST || process.env.MYSQL_HOST || 'localhost',
    user: process.env.DB_USER || process.env.MYSQL_USER || 'root',
    password: process.env.DB_PASSWORD || process.env.MYSQL_PASSWORD || '',
    database: process.env.DB_NAME || process.env.MYSQL_DATABASE || 'spiritual_center',
    port: process.env.DB_PORT || process.env.MYSQL_PORT || 3306,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
};

console.log('🔧 Database Configuration:', {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database,
    port: dbConfig.port,
    environment: process.env.NODE_ENV || 'development'
});

// Initialize database connection pool
let pool;

async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database connection...');
        
        // First connect without database to create it if needed
        const tempConnection = await createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password,
            port: dbConfig.port,
            ssl: dbConfig.ssl
        });

        // Create database if it doesn't exist
        await tempConnection.execute(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
        console.log(`✅ Database '${dbConfig.database}' created/verified`);
        await tempConnection.end();

        // Now connect to the specific database
        pool = createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: process.env.NODE_ENV === 'production' ? 20 : 10,
            queueLimit: 0,
            acquireTimeout: 60000,
            timeout: 60000,
            reconnect: true
        });

        // Test connection with retry logic
        let retries = 5;
        while (retries > 0) {
            try {
                const testConn = await pool.getConnection();
                console.log('✅ Database connection successful');
                await testConn.execute('SELECT 1');
                testConn.release();
                break;
            } catch (error) {
                retries--;
                if (retries === 0) throw error;
                console.log(`⚠️  Database connection failed, retrying... (${retries} attempts left)`);
                await new Promise(resolve => setTimeout(resolve, 3000));
            }
        }

        // Create tables if they don't exist
        await createTables();
        console.log('✅ Database initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
        console.log('💡 Troubleshooting tips:');
        console.log('   - Make sure MySQL server is running');
        console.log('   - Check database credentials in environment variables');
        console.log('   - Verify MySQL port');
        console.log('   - Ensure MySQL user has proper permissions');
        
        if (isRender) {
            console.log('   - On Render: Use external MySQL service like PlanetScale');
            console.log('   - Add DB credentials as environment variables in Render');
        }
        
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

// File upload configuration with production considerations
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { 
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 5 // Limit number of files
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|mp4|avi|mov|pdf|doc|docx/;
        const fileExtname = allowedTypes.test(extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && fileExtname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images, videos, and documents are allowed.'));
        }
    }
});

// JWT configuration for production
const JWT_SECRET = process.env.JWT_SECRET || 'spiritual_center_secret_2024_production_fallback';
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
    console.warn('⚠️  WARNING: Using default JWT secret in production! Set JWT_SECRET environment variable.');
}

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Database connection middleware
const requireDatabase = (req, res, next) => {
    if (!pool) {
        return res.status(503).json({ 
            error: 'Database not available. Please try again later.',
            code: 'DATABASE_UNAVAILABLE'
        });
    }
    next();
};

// Request logging middleware for production
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
    }
    next();
});

// Routes

// Health check route with detailed info
app.get('/health', async (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        platform: isRender ? 'Render' : 'Local',
        database: pool ? 'Connected' : 'Disconnected',
        memory: process.memoryUsage(),
        version: '1.0.0'
    };

    // Test database connection if pool exists
    if (pool) {
        try {
            const connection = await pool.getConnection();
            await connection.execute('SELECT 1');
            connection.release();
            health.database = 'Healthy';
        } catch (error) {
            health.database = 'Unhealthy';
            health.dbError = error.message;
            health.status = 'Degraded';
        }
    }

    const statusCode = health.status === 'OK' ? 200 : 503;
    res.status(statusCode).json(health);
});

// Test routes
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API is working!',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        platform: isRender ? 'Render' : 'Local',
        version: '1.0.0',
        database: {
            host: dbConfig.host,
            database: dbConfig.database,
            connected: !!pool
        }
    });
});

app.get('/api/test-db', requireDatabase, async (req, res) => {
    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT 1 as test, NOW() as time');
        connection.release();
        res.json({ 
            message: 'Database connection successful', 
            data: rows,
            pool: true,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Database test error:', error);
        res.status(500).json({ 
            error: 'Database connection failed: ' + error.message,
            code: 'DATABASE_ERROR'
        });
    }
});

// User registration
app.post('/api/register', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { username, email, password } = req.body;
        
        console.log('Registration attempt:', { username, email });
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please provide a valid email address' });
        }

        connection = await pool.getConnection();

        const [existing] = await connection.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already exists with this email or username' });
        }

        const hashedPassword = await hash(password, 12);

        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash, is_approved) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, false]
        );

        res.status(201).json({ 
            message: 'Registration successful. Please wait for admin approval.',
            userId: result.insertId 
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error during registration' });
    } finally {
        if (connection) connection.release();
    }
});

// User login
app.post('/api/login', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;
        
        console.log('Login attempt for email:', email);
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        connection = await pool.getConnection();

        const [users] = await connection.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = users[0];

        // Check if approved (admin is always approved)
        if (!user.is_approved && user.role !== 'admin') {
            return res.status(400).json({ error: 'Account pending approval. Please contact administrator.' });
        }

        const validPassword = await compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const token = sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role || 'user'
            },
            JWT_SECRET,
            { expiresIn: process.env.NODE_ENV === 'production' ? '7d' : '24h' }
        );

        console.log('Login successful for user:', user.email, 'Role:', user.role);

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error during login' });
    } finally {
        if (connection) connection.release();
    }
});

// Get all content (requires authentication)
app.get('/api/content', requireDatabase, authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [content] = await connection.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            ORDER BY c.created_at DESC
        `);

        res.json(content);
    } catch (error) {
        console.error('Get content error:', error);
        res.status(500).json({ error: 'Failed to load content' });
    } finally {
        if (connection) connection.release();
    }
});

// Get public content
app.get('/api/content/public', requireDatabase, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [content] = await connection.execute(`
            SELECT c.*, u.username as author 
            FROM content c 
            LEFT JOIN users u ON c.created_by = u.id 
            WHERE c.is_public = TRUE
            ORDER BY c.created_at DESC
            LIMIT 50
        `);

        res.json(content);
    } catch (error) {
        console.error('Get public content error:', error);
        res.status(500).json({ error: 'Failed to load public content' });
    } finally {
        if (connection) connection.release();
    }
});

// Upload content (admin only)
app.post('/api/content', requireDatabase, authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
    let connection;
    try {
        const { title, description, type, content_text, is_public } = req.body;
        
        if (!title || !description || !type) {
            return res.status(400).json({ error: 'Title, description, and type are required' });
        }

        let fileUrl = null;
        if (req.file) {
            fileUrl = `/uploads/${req.file.filename}`;
        } else if (type !== 'writeup') {
            return res.status(400).json({ error: 'File is required for video and image content' });
        }

        if (type === 'writeup' && !content_text) {
            return res.status(400).json({ error: 'Content text is required for writeups' });
        }

        connection = await pool.getConnection();

        const [result] = await connection.execute(
            'INSERT INTO content (title, description, type, file_url, content_text, created_by, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [title, description, type, fileUrl, content_text || null, req.user.id, is_public === 'true']
        );

        res.status(201).json({ 
            message: 'Content uploaded successfully',
            contentId: result.insertId 
        });
    } catch (error) {
        console.error('Upload content error:', error);
        res.status(500).json({ error: 'Failed to upload content' });
    } finally {
        if (connection) connection.release();
    }
});

// Get users for admin (admin only)
app.get('/api/users', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute(
            'SELECT id, username, email, role, is_approved, created_at FROM users ORDER BY created_at DESC'
        );

        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    } finally {
        if (connection) connection.release();
    }
});

// Approve user (admin only)
app.put('/api/users/:id/approve', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE users SET is_approved = TRUE WHERE id = ?',
            [req.params.id]
        );

        res.json({ message: 'User approved successfully' });
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ error: 'Failed to approve user' });
    } finally {
        if (connection) connection.release();
    }
});

// Prayer request submission
app.post('/api/prayer-requests', requireDatabase, async (req, res) => {
    let connection;
    try {
        const { name, email, subject, message, userId } = req.body;
        
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please provide a valid email address' });
        }

        connection = await pool.getConnection();

        const [result] = await connection.execute(
            'INSERT INTO prayer_requests (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)',
            [userId || null, name, email, subject, message]
        );

        res.status(201).json({ 
            message: 'Prayer request submitted successfully',
            requestId: result.insertId 
        });
    } catch (error) {
        console.error('Prayer request error:', error);
        res.status(500).json({ error: 'Failed to submit prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Get prayer requests (admin only)
app.get('/api/prayer-requests', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [requests] = await connection.execute(`
            SELECT pr.*, u.username 
            FROM prayer_requests pr 
            LEFT JOIN users u ON pr.user_id = u.id 
            ORDER BY pr.created_at DESC
        `);

        res.json(requests);
    } catch (error) {
        console.error('Get prayer requests error:', error);
        res.status(500).json({ error: 'Failed to load prayer requests' });
    } finally {
        if (connection) connection.release();
    }
});

// Update prayer request status (admin only)
app.put('/api/prayer-requests/:id/status', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { status } = req.body;
        
        if (!['pending', 'read', 'responded'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE prayer_requests SET status = ? WHERE id = ?',
            [status, req.params.id]
        );

        res.json({ message: 'Prayer request status updated successfully' });
    } catch (error) {
        console.error('Update prayer request status error:', error);
        res.status(500).json({ error: 'Failed to update prayer request status' });
    } finally {
        if (connection) connection.release();
    }
});

// Add missing routes that frontend expects
app.put('/api/prayer-requests/:id/read', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE prayer_requests SET status = "read" WHERE id = ?',
            [req.params.id]
        );

        res.json({ message: 'Prayer request marked as read' });
    } catch (error) {
        console.error('Mark prayer as read error:', error);
        res.status(500).json({ error: 'Failed to update prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Add missing DELETE routes
app.delete('/api/users/:id', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/prayer-requests/:id', requireDatabase, authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.execute('DELETE FROM prayer_requests WHERE id = ?', [req.params.id]);
        res.json({ message: 'Prayer request deleted successfully' });
    } catch (error) {
        console.error('Delete prayer request error:', error);
        res.status(500).json({ error: 'Failed to delete prayer request' });
    } finally {
        if (connection) connection.release();
    }
});

// Get user profile
app.get('/api/profile', requireDatabase, authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute(
            'SELECT id, username, email, role, is_approved, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(users[0]);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Failed to load profile' });
    } finally {
        if (connection) connection.release();
    }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large (max 10MB)' });
        }
    }
    console.error('Unhandled error:', error);
    
    // Don't leak error details in production
    const message = process.env.NODE_ENV === 'production' 
        ? 'Something went wrong!' 
        : error.message;
    
    res.status(500).json({ error: message });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API route not found' });
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
    console.log('🚀 Starting Spiritual Center Server...');
    console.log('📊 Environment:', process.env.NODE_ENV || 'development');
    console.log('🏗️  Platform:', isRender ? 'Render' : 'Local');
    console.log('🔧 Port:', PORT);
    console.log('🗄️ Database Host:', dbConfig.host);
    
    // Initialize database (but don't block server start)
    initializeDatabase().then(success => {
        if (success) {
            console.log('✅ Database initialized successfully');
        } else {
            console.log('⚠️  Database not available, but server is running');
            console.log('💡 Some features may not work until database is connected');
        }
    });

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`📚 API Base URL: http://localhost:${PORT}/api`);
        console.log(`🌐 Frontend URL: http://localhost:${PORT}`);
        console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
        console.log(`🗄️ Test DB: http://localhost:${PORT}/api/test-db`);
        console.log(`📁 Uploads directory: ${uploadsDir}`);
        
        if (isRender) {
            console.log('🎯 Render Deployment Ready!');
            console.log('💡 Add these environment variables in Render:');
            console.log('   - NODE_ENV=production');
            console.log('   - JWT_SECRET=your-secure-secret-here');
            console.log('   - DB_HOST=your-mysql-host');
            console.log('   - DB_USER=your-mysql-user');
            console.log('   - DB_PASSWORD=your-mysql-password');
            console.log('   - DB_NAME=spiritual_center');
        }
        
        console.log(`👤 Default Admin: Wisdomadiele57@gmail.com / admin123`);
    });
}

startServer().catch(error => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
});