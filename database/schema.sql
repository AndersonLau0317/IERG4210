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
    FOREIGN KEY (catid) REFERENCES categories(catid)
);

-- Clear existing data and add more sample categories
DELETE FROM products;
DELETE FROM categories;

INSERT INTO categories (name) VALUES 
('Electronics'),
('Books'),
('Clothing'),
('Home & Garden');

INSERT INTO products (catid, name, price, description) VALUES 
(1, 'Smartphone XL', 599.99, 'Latest smartphone with 6.5" display and 5G capability'),
(1, 'Wireless Earbuds', 129.99, 'True wireless earbuds with noise cancellation'),
(1, 'Smart Watch', 199.99, 'Fitness tracker with heart rate monitoring'),
(2, 'Web Development Guide', 49.99, 'Complete guide to modern web development'),
(2, 'Mystery Novel', 19.99, 'Bestselling mystery thriller'),
(2, 'Cookbook', 29.99, 'International recipes collection'),
(3, 'Designer T-Shirt', 24.99, 'Cotton blend casual t-shirt'),
(3, 'Denim Jeans', 59.99, 'Classic fit blue jeans'),
(4, 'Indoor Plant', 34.99, 'Low-maintenance decorative plant'),
(4, 'LED Lamp', 45.99, 'Modern desk lamp with adjustable brightness');
