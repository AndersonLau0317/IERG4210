## URL
https://s16.ierg4210.ie.cuhk.edu.hk/

## Prerequisites

- Node.js (v18.x or v20.x)
- NPM (comes with Node.js)

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

4. Start the server:
```bash
npm start
```

5. Access the application:
- Main website: http://localhost:3000
- Admin panel: http://localhost:3000/admin/admin.html

## Notes:
Create a .env file:

STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
NODE_ENV=production

Change the NODE_ENV to development to only host a http

