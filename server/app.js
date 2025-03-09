const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3');
const sharp = require('sharp');
const path = require('path');

const app = express();
const db = new sqlite3.Database('database/shop.db');

app.use(express.static('public'));
app.use('/admin', express.static('admin')); // Add this line to serve admin files
app.use(express.json());

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

// Serve the main HTML file for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Categories API
app.get('/api/categories', (req, res) => {
    db.all('SELECT * FROM categories', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/categories', (req, res) => {
    const { name } = req.body;
    db.run('INSERT INTO categories (name) VALUES (?)', [name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

app.delete('/api/categories/:catid', (req, res) => {
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

app.post('/api/products', upload.single('image'), async (req, res) => {
    const { name, price, description, catid } = req.body;
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

app.delete('/api/products/:pid', (req, res) => {
    const pid = parseInt(req.params.pid);
    db.run('DELETE FROM products WHERE pid = ?', [pid], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
