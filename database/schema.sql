CREATE TABLE categories (
    catid INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE products (
    pid INTEGER PRIMARY KEY AUTOINCREMENT,
    catid INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    image_original VARCHAR(255),
    image_thumbnail VARCHAR(255),
    FOREIGN KEY (catid) REFERENCES categories(catid) ON DELETE CASCADE
);

CREATE TABLE users (
    userid INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE orders (
    orderid TEXT PRIMARY KEY,
    userid INTEGER,
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    payment_intent_id TEXT UNIQUE,
    digest TEXT NOT NULL,
    currency VARCHAR(3) DEFAULT 'HKD',
    FOREIGN KEY (userid) REFERENCES users(userid)
);

CREATE TABLE order_items (
    orderid TEXT,
    pid INTEGER,
    quantity INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (orderid) REFERENCES orders(orderid),
    FOREIGN KEY (pid) REFERENCES products(pid)
);

-- Clear existing data
DELETE FROM products;
DELETE FROM categories;
DELETE FROM users;

INSERT INTO categories (name) VALUES 
('Electronics'),
('Books'),
('Clothing'),
('Home & Garden');

INSERT INTO products (catid, name, price, description, image_original, image_thumbnail) VALUES 
(1, 'Smartphone XL', 599.99, 'Latest smartphone with 6.5" display and 5G capability', 'product1.jpg', 'thumb_product1.jpg'),
(1, 'Wireless Earbuds', 129.99, 'True wireless earbuds with noise cancellation', 'product2.jpg', 'thumb_product2.jpg'),
(1, 'Smart Watch', 199.99, 'Fitness tracker with heart rate monitoring', 'product3.jpg', 'thumb_product3.jpg'),
(2, 'Web Development Guide', 49.99, 'Complete guide to modern web development', 'product4.jpg', 'thumb_product4.jpg'),
(2, 'Mystery Novel', 19.99, 'Bestselling mystery thriller', 'product5.jpg', 'thumb_product5.jpg'),
(2, 'Cookbook', 29.99, 'International recipes collection', 'product6.jpg', 'thumb_product6.jpg'),
(3, 'Designer T-Shirt', 24.99, 'Cotton blend casual t-shirt', 'product7.jpg', 'thumb_product7.jpg'),
(3, 'Denim Jeans', 59.99, 'Classic fit blue jeans', 'product8.jpg', 'thumb_product8.jpg'),
(4, 'Indoor Plant', 34.99, 'Low-maintenance decorative plant', 'product9.jpg', 'thumb_product9.jpg'),
(4, 'LED Lamp', 45.99, 'Modern desk lamp with adjustable brightness', 'product10.jpg', 'thumb_product10.jpg');

-- Add sample users with salted passwords
INSERT INTO users (email, password, salt, is_admin) VALUES 
('admin@example.com', '0a8f9b35a35de3edb7a54981cf27385ad5ffe3ec56ca3904abe9c1f9ee17b41e', 'admin_salt_123', 1),
('user@example.com', 'b10732c886b5a4fc7badef08fb0b3a25bd80716fa2195ee9fa22e387a09876a6', 'user_salt_123', 0);
