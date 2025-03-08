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

-- Insert sample data
INSERT INTO categories (name) VALUES 
('Electronics'),
('Books');

INSERT INTO products (catid, name, price, description) VALUES 
(1, 'Smartphone', 599.99, 'A powerful smartphone with great features'),
(1, 'Laptop', 999.99, 'High-performance laptop for work and gaming'),
(2, 'Programming Guide', 49.99, 'Learn programming from scratch'),
(2, 'Science Fiction', 19.99, 'Best-selling sci-fi novel');
