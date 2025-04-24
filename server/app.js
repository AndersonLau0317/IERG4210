require('dotenv').config();
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
const http = require('http');
const fs = require('fs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
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

// Update CSP headers in app.js
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' https://*.stripe.com; " +
        "script-src 'self' https://*.stripe.com 'unsafe-inline'; " +
        "frame-src https://*.stripe.com; " +
        "connect-src 'self' https://*.stripe.com"
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
        secure: true, // Set to false temporarily for testing
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
    const skipPaths = ['/api/csrf-token', '/api/login', '/webhook'];
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

// Place this BEFORE any app.use(express.json()) or other middleware!
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        switch (event.type) {
            case 'payment_intent.succeeded':
                const paymentIntent = event.data.object;
                await handleSuccessfulPayment(paymentIntent);
                break;
            case 'payment_intent.payment_failed':
                const failedPayment = event.data.object;
                await handleFailedPayment(failedPayment);
                break;
        }

        res.json({received: true});
    } catch (err) {
        console.error('Webhook processing failed:', err);
        res.status(500).send(`Webhook processing failed: ${err.message}`);
    }
});

// Now add your middleware
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

const adminPageProtection = (req, res, next) => {
    if (!req.session.user?.is_admin) {
        return res.redirect('/admin/login.html');
    }
    next();
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

function generateOrderDigest(items, total) {
    const orderData = {
        currency: 'USD',
        merchant: process.env.STRIPE_MERCHANT_EMAIL || 'your-merchant@email.com',
        salt: crypto.randomBytes(16).toString('hex'),
        items,
        total
    };

    return crypto.createHash('sha256')
        .update(JSON.stringify(orderData))
        .digest('hex');
}

// Add with other helper functions in app.js
async function createOrder(orderId, userId, total, items, paymentIntentId, digest) {
    return new Promise((resolve, reject) => {
        db.run('BEGIN TRANSACTION', err => {
            if (err) return reject(err);

            db.run(
                'INSERT INTO orders (orderid, userid, total, status, payment_intent_id, digest) VALUES (?, ?, ?, ?, ?, ?)',
                [orderId, userId, total, 'pending', paymentIntentId, digest],
                err => {
                    if (err) {
                        db.run('ROLLBACK');
                        return reject(err);
                    }

                    const itemPromises = items.map(item => {
                        return new Promise((resolve, reject) => {
                            db.run(
                                'INSERT INTO order_items (orderid, pid, quantity, price) VALUES (?, ?, ?, ?)',
                                [orderId, item.pid, item.quantity, item.price],
                                err => {
                                    if (err) reject(err);
                                    else resolve();
                                }
                            );
                        });
                    });

                    Promise.all(itemPromises)
                        .then(() => {
                            db.run('COMMIT', err => {
                                if (err) return reject(err);
                                resolve();
                            });
                        })
                        .catch(err => {
                            db.run('ROLLBACK');
                            reject(err);
                        });
                }
            );
        });
    });
}

async function checkOrderProcessed(paymentIntentId) {
    return new Promise((resolve, reject) => {
        db.get(
            'SELECT orderid FROM orders WHERE payment_intent_id = ? AND status = ?',
            [paymentIntentId, 'completed'],
            (err, row) => {
                if (err) reject(err);
                else resolve(!!row);
            }
        );
    });
}

async function validateOrderDigest(orderId, digest) {
    return new Promise((resolve, reject) => {
        db.get(
            'SELECT digest FROM orders WHERE orderid = ?',
            [orderId],
            (err, row) => {
                if (err) reject(err);
                else resolve(row?.digest === digest);
            }
        );
    });
}

async function updateOrderStatus(orderId, status) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE orders SET status = ? WHERE orderid = ?',
            [status, orderId],
            err => {
                if (err) reject(err);
                else resolve();
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
// Add this near your other static file routes
app.get('/order-confirmation', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'order-confirmation.html'));
});

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

// Payment Routes
app.post('/api/create-payment-intent', requireAuth, async (req, res) => {
    try {
        const { items } = req.body;
        
        // Validate quantities
        for (const item of items) {
            if (item.quantity <= 0) {
                return res.status(400).json({ error: 'Invalid quantity' });
            }
        }

        // Calculate total from DB prices
        let total = 0;
        const validatedItems = await Promise.all(items.map(async (item) => {
            const product = await new Promise((resolve, reject) => {
                db.get('SELECT price FROM products WHERE pid = ?', [item.pid], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            total += product.price * item.quantity;
            return { ...item, price: product.price };
        }));

        const orderDigest = generateOrderDigest(validatedItems, total);
        const orderId = crypto.randomUUID();

        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(total * 100),
            currency: 'usd',
            metadata: {
                orderId,
                userId: req.session.user?.userid || 'guest',
                digest: orderDigest
            }
        });

        await createOrder(orderId, req.session.user?.userid, total, validatedItems, paymentIntent.id, orderDigest);

        res.json({
            clientSecret: paymentIntent.client_secret,
            orderId: orderId
        });
    } catch (err) {
        console.error('Payment Intent Error:', err);
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

async function handleSuccessfulPayment(paymentIntent) {
    const order = await new Promise((resolve, reject) => {
        db.get('SELECT * FROM orders WHERE payment_intent_id = ?', 
            [paymentIntent.id], 
            (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
    });

    if (!order) {
        throw new Error('Order not found');
    }

    if (order.status === 'completed') {
        return; // Prevent double processing
    }

    // Verify order digest
    if (order.digest !== paymentIntent.metadata.digest) {
        await updateOrderStatus(order.orderid, 'invalid');
        throw new Error('Order digest mismatch');
    }

    await updateOrderStatus(order.orderid, 'completed');
}

async function handleFailedPayment(paymentIntent) {
    await updateOrderStatus(paymentIntent.metadata.orderId, 'failed');
}

app.get('/api/orders', requireAuth, (req, res) => {
    const isAdmin = req.session.user.is_admin;
    const query = isAdmin
        ? 'SELECT * FROM orders ORDER BY created_at DESC'
        : 'SELECT * FROM orders WHERE userid = ? ORDER BY created_at DESC LIMIT 5';
    const params = isAdmin ? [] : [req.session.user.userid];

    db.all(query, params, async (err, orders) => {
        if (err) return res.status(500).json({ error: err.message });

        // For each order, fetch its items and attach to the order
        const ordersWithItems = await Promise.all(orders.map(order => {
            return new Promise((resolve) => {
                db.all(
                    `SELECT oi.*, p.name 
                     FROM order_items oi 
                     JOIN products p ON oi.pid = p.pid 
                     WHERE oi.orderid = ?`,
                    [order.orderid],
                    (err, items) => {
                        resolve({ ...order, items: items || [] });
                    }
                );
            });
        }));
        res.json(ordersWithItems);
    });
});

// Get order details and items by order ID
app.get('/api/orders/:orderid', (req, res) => {
    const orderId = req.params.orderid;
    db.get('SELECT * FROM orders WHERE orderid = ?', [orderId], (err, order) => {
        if (err || !order) return res.status(404).json({ error: 'Order not found' });

        db.all(
            `SELECT oi.*, p.name, p.image_thumbnail 
             FROM order_items oi 
             JOIN products p ON oi.pid = p.pid 
             WHERE oi.orderid = ?`,
            [orderId],
            (err, items) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ order, items });
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

// ====== Disable HTTPS for local testing ======

if (process.env.NODE_ENV === 'production') {
    // Production: HTTPS server on 3001, HTTP server on 3000 for redirect
    const httpsOptions = {
        cert: fs.readFileSync('/etc/letsencrypt/live/s16.ierg4210.ie.cuhk.edu.hk/fullchain.pem'),
        key: fs.readFileSync('/etc/letsencrypt/live/s16.ierg4210.ie.cuhk.edu.hk/privkey.pem'),
        minVersion: 'TLSv1.2'
    };

    // Start HTTPS server
    https.createServer(httpsOptions, app).listen(3001, '0.0.0.0', () => {
        console.log('HTTPS Server running on port 3001');
    });

    // Start HTTP server for redirect, or skip if using iptables
    http.createServer((req, res) => {
        // Redirect all HTTP traffic to HTTPS
        res.writeHead(301, { "Location": "https://" + req.headers['host'].replace(/:3000$/, ':3001') + req.url });
        res.end();
    }).listen(3000, '0.0.0.0', () => {
        console.log('HTTP redirect server running on port 3000');
    });

} else {
    // Development: HTTP only
    http.createServer(app).listen(3000, '0.0.0.0', () => {
        console.log('HTTP Server running on port 3000');
    });
}

// Debug route
app.get('/test', (req, res) => {
    res.json({
        secure: req.secure,
        protocol: req.protocol,
        hostname: req.hostname,
        url: req.url
    });
});

// Add to app.js
async function cleanupFailedOrders() {
    const CLEANUP_THRESHOLD = 24 * 60 * 60 * 1000; // 24 hours
    const cutoffTime = new Date(Date.now() - CLEANUP_THRESHOLD);

    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE orders SET status = ? WHERE status = ? AND created_at < ?',
            ['expired', 'pending', cutoffTime.toISOString()],
            err => {
                if (err) reject(err);
                else resolve();
            }
        );
    });
}

// Run cleanup periodically
setInterval(cleanupFailedOrders, 60 * 60 * 1000); // Every hour