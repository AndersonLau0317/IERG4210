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
