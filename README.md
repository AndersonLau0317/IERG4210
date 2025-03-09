# IERG4210
Static Website URL: https://andersonlau0317.github.io/IERG4210/

## Prerequisites

- Node.js (v18.x or v20.x)
- NPM (comes with Node.js)
- SQLite3

## Setup Instructions

1. Clone the repository:
```bash
git clone https://github.com/AndersonLau0317/IERG4210.git
cd IERG4210
```

2. Install dependencies:
```bash
npm install
```

3. Initialize the database:
```bash
# Initialize the SQLite database with schema
sqlite3 database/shop.db < database/schema.sql
```

## Running the Application

1. Start the server:
```bash
npm start
```

2. Access the application:
- Main website: http://localhost:3000
- Admin panel: http://localhost:3000/admin/admin.html

## Database Management

- The SQLite database file is located at `database/shop.db`
- To reset the database with sample data:
```bash
sqlite3 database/shop.db < database/schema.sql
```
- To access the database directly:
```bash
sqlite3 database/shop.db
```

## Development

- The server runs on port 3000 by default
- Product images are stored in `public/images/products/`
- API endpoints are available at:
  - GET /api/categories - List all categories
  - GET /api/products - List all products
  - GET /api/products?catid={id} - List products in category
  - GET /api/products/{pid} - Get specific product

## Note

Make sure to create a `.env` file if needed and update the `.gitignore` file to exclude sensitive information.
