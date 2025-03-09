## URL
http://54.253.38.227:3000
http://54.253.38.227:3000/admin/admin.html

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


