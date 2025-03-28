const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3');
const sharp = require('sharp');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const csrf = require('csrf');
const tokens = new csrf();
const https = require('https');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database('database/shop.db');

app.use(express.static('public'));

// Add these headers middleware before your routes
app.use((req, res, next) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Surrogate-Control': 'no-store'
    });
    next();
});

// Add CSP headers
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    );
    next();
});

// Update the session configuration
app.use(session({
    store: new SQLiteStore({
        db: 'database/sessions.db',
        concurrentDB: true,
    }),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    name: 'sessionId',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to false temporarily for testing
        httpOnly: true,
        sameSite: 'lax', // Change to 'lax' from 'strict'
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Then add session timeout middleware
const sessionTimeout = (req, res, next) => {
    if (req.session && req.session.user) {
        const now = Date.now();
        const lastActivity = req.session.lastActivity || now;
        
        if (now - lastActivity > 30 * 60 * 1000) {
            return req.session.destroy(() => {
                res.status(401).json({ error: 'Session expired due to inactivity' });
            });
        }
        req.session.lastActivity = now;
    }
    next();
};

// Update CSRF protection middleware
const csrfProtection = (req, res, next) => {
    // Skip CSRF for these paths
    const skipPaths = ['/api/csrf-token', '/api/login'];
    if (skipPaths.includes(req.path) || req.method === 'GET') {
        return next();
    }

    console.log('Debug CSRF:', {  // Add debug logging
        token: req.headers['x-csrf-token'],
        secret: !!req.session.csrfSecret,
        path: req.path,
        method: req.method,
        sessionID: req.sessionID
    });

    const token = req.headers['x-csrf-token'];
    if (!token || !req.session.csrfSecret) {
        return res.status(403).json({ error: 'CSRF token missing' });
    }

    if (!tokens.verify(req.session.csrfSecret, token)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next();
};

// Apply middleware in correct order
app.use(express.json());
app.use(sessionTimeout);
app.use(csrfProtection);

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { error: 'Too many login attempts. Please try again later.' }
});

// Generate CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
    if (!req.session.csrfSecret) {
        req.session.csrfSecret = tokens.secretSync();
    }
    const token = tokens.create(req.session.csrfSecret);
    res.json({ token });
});

// Authentication middleware with enhanced validation
const requireAuth = (req, res, next) => {
    if (!req.session.user || !req.session.user.userid) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // Validate session age
    const sessionAge = Date.now() - req.session.cookie._expires;
    if (sessionAge > 3 * 24 * 60 * 60 * 1000) { // 3 days max
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired' });
    }

    // Validate user still exists in database
    db.get('SELECT userid FROM users WHERE userid = ?', [req.session.user.userid], (err, user) => {
        if (err || !user) {
            req.session.destroy();
            return res.status(401).json({ error: 'Invalid session' });
        }
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (!req.session.user?.is_admin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    // Verify admin status in database
    db.get('SELECT userid FROM users WHERE userid = ? AND is_admin = 1', 
        [req.session.user.userid], (err, user) => {
        if (err || !user) {
            req.session.destroy();
            return res.status(403).json({ error: 'Invalid admin session' });
        }
        next();
    });
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images/products');
    },
    filename: (req, file, cb) => {
        // Get next product ID from database
        db.get('SELECT MAX(pid) as maxPid FROM products', (err, row) => {
            const nextPid = (row.maxPid || 0) + 1;
            cb(null, `product${nextPid}${path.extname(file.originalname)}`);
        });
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only images are allowed'));
        }
        cb(null, true);
    }
});

// Add this helper function at the top level
function hashPassword(password, salt) {
    return crypto.createHash('sha256')
        .update(salt + password)
        .digest('hex');
}

// Add input sanitization
const sanitizeInput = (input) => {
    return input
        .replace(/[<>]/g, '') 
        .trim();
};

// Helper function to create new users
async function createUser(email, password, isAdmin = false) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = hashPassword(password, salt);
    
    return new Promise((resolve, reject) => {
        db.run(
            'INSERT INTO users (email, password, salt, is_admin) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, salt, isAdmin ? 1 : 0],
            function(err) {
                if (err) reject(err);
                else resolve(this.lastID);
            }
        );
    });
}

// Serve the main HTML file for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Update login route with proper session handling
app.post('/api/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const hashedPassword = hashPassword(password, user.salt);
        if (hashedPassword !== user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Regenerate session for security
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: 'Session error' });

            req.session.user = {
                userid: user.userid,
                email: user.email,
                is_admin: user.is_admin
            };

            // Generate new CSRF token
            req.session.csrfSecret = tokens.secretSync();
            const csrfToken = tokens.create(req.session.csrfSecret);

            req.session.save((err) => {
                if (err) return res.status(500).json({ error: 'Session save error' });
                res.json({ 
                    success: true, 
                    is_admin: user.is_admin,
                    csrfToken: csrfToken
                });
            });
        });
    });
});

// Get current user
app.get('/api/user', (req, res) => {
    res.json(req.session.user || { email: 'guest' });
});

// Logout route
app.post('/api/logout', (req, res) => {
    // Store old session to destroy
    const oldSession = req.session;

    // Regenerate empty session
    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }

        // Destroy old session
        oldSession.destroy();

        // Clear all auth-related cookies
        res.clearCookie('sessionId', { 
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        res.json({ success: true });
    });
});

// Categories API
app.get('/api/categories', (req, res) => {
    db.all('SELECT * FROM categories', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categories', requireAuth, requireAdmin, (req, res) => {
    const name = sanitizeInput(req.body.name);
    db.run('INSERT INTO categories (name) VALUES (?)', [name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

app.delete('/api/categories/:catid', requireAuth, requireAdmin, (req, res) => {
    const catid = parseInt(req.params.catid);
    
    // Enable foreign key support
    db.run('PRAGMA foreign_keys = ON', (err) => {
        if (err) {
            console.error('Error enabling foreign keys:', err);
            return res.status(500).json({ error: 'Database configuration error' });
        }
        
        // Delete category (products will be deleted automatically via CASCADE)
        db.run('DELETE FROM categories WHERE catid = ?', [catid], function(err) {
            if (err) {
                console.error('Error deleting category:', err);
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Category not found' });
            }
            res.json({ success: true });
        });
    });
});

// Products API
app.get('/api/products', (req, res) => {
    const catid = req.query.catid;
    const query = catid 
        ? 'SELECT * FROM products WHERE catid = ?'
        : 'SELECT * FROM products';
    const params = catid ? [catid] : [];
    
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/products/:pid', (req, res) => {
    const pid = parseInt(req.params.pid);
    db.get('SELECT * FROM products WHERE pid = ?', [pid], (err, product) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.json(product);
    });
});

app.post('/api/products', requireAuth, requireAdmin, upload.single('image'), async (req, res) => {
    const name = sanitizeInput(req.body.name);
    const description = sanitizeInput(req.body.description);
    const { price, catid } = req.body;
    const file = req.file;

    try {
        const originalName = file.filename;
        const thumbnailName = 'thumb_' + originalName;
        
        // Generate thumbnail
        await sharp(file.path)
            .resize(200, 200)
            .toFile(path.join('public/images/products', thumbnailName));

        db.run(
            'INSERT INTO products (name, price, description, catid, image_original, image_thumbnail) VALUES (?, ?, ?, ?, ?, ?)',
            [name, price, description, catid, originalName, thumbnailName],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID });
            }
        );
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/products/:pid', requireAuth, requireAdmin, (req, res) => {
    const pid = parseInt(req.params.pid);
    db.run('DELETE FROM products WHERE pid = ?', [pid], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Add a specific middleware to protect admin routes
const adminPageProtection = (req, res, next) => {
    if (!req.session.user?.is_admin) {
        return res.redirect('/admin/login.html');
    }
    next();
};

// Apply the protection to admin routes
app.get('/admin/admin.html', adminPageProtection);
app.use('/admin/api/*', adminPageProtection);

// Add these routes before your existing routes
app.use('/admin/static', express.static(path.join(__dirname, '..', 'admin')));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin')));

// Add specific route for login page
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'login.html'));
});

// Add specific route for admin panel
app.get('/admin/panel', adminPageProtection, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'admin.html'));
});

// Change password route
app.post('/api/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userid = req.session.user.userid;

    db.get('SELECT * FROM users WHERE userid = ?', [userid], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const hashedCurrentPassword = hashPassword(currentPassword, user.salt);
        if (hashedCurrentPassword !== user.password) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const newSalt = crypto.randomBytes(16).toString('hex');
        const hashedNewPassword = hashPassword(newPassword, newSalt);

        db.run(
            'UPDATE users SET password = ?, salt = ? WHERE userid = ?',
            [hashedNewPassword, newSalt, userid],
            (err) => {
                if (err) return res.status(500).json({ error: err.message });
                
                // Logout user
                req.session.destroy(() => {
                    res.clearCookie('sessionId');
                    res.json({ success: true });
                });
            }
        );
    });
});

// Admin routes
app.get('/admin', (req, res) => {
    if (req.session.user?.is_admin) {
        res.redirect('/admin/panel');
    } else {
        res.redirect('/admin/login');
    }
});

app.get('/admin/login', (req, res) => {
    if (req.session.user?.is_admin) {
        res.redirect('/admin/panel');
    } else {
        res.sendFile(path.join(__dirname, '..', 'admin', 'login.html'));
    }
});

app.get('/admin/panel', adminPageProtection, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin', 'admin.html'));
});

// Serve admin static files
app.use('/admin/static', express.static(path.join(__dirname, '..', 'admin')));
app.use(express.static(path.join(__dirname, '..', 'public')));

// HTTPS Configuration
const httpsOptions = {
    cert: fs.readFileSync('/etc/letsencrypt/live/s16.ierg4210.ie.cuhk.edu.hk/fullchain.pem'),
    key: fs.readFileSync('/etc/letsencrypt/live/s16.ierg4210.ie.cuhk.edu.hk/privkey.pem'),
    minVersion: 'TLSv1.2',
    ciphers: [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384"
    ].join(':')
};

// Create both HTTP and HTTPS servers
const httpServer = app.listen(3000, () => {
    console.log('HTTP Server running on port 3000');
});

const httpsServer = https.createServer(httpsOptions, app).listen(3001, () => {
    console.log('HTTPS Server running on port 3001');
});

// Force HTTPS redirect
app.use((req, res, next) => {
    if (!req.secure) {
        return res.redirect(`https://${req.hostname}${req.url}`);
    }
    next();
});

// Debug route
app.get('/test', (req, res) => {
    res.json({
        secure: req.secure,
        protocol: req.protocol,
        hostname: req.hostname,
        url: req.url
    });
});
