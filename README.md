# ISMAAL Backend Server

This is the backend API server for the ISMAAL mobile application.

## Prerequisites

- Node.js (v14 or higher)
- MySQL database
- npm or yarn

## Setup Instructions

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Setup**
   Create a `.env` file in the backend directory:
   ```env
   DATABASE_URL="mysql://username:password@localhost:3306/ismaal_db"
   PORT=3000
   ```

3. **Database Setup**
   ```bash
   # Generate Prisma client
   npm run db:generate
   
   # Push schema to database
   npm run db:push
   
   # Seed database with admin user
   npm run db:seed
   ```

4. **Start the Server**
   ```bash
   # Development mode (with auto-restart)
   npm run dev
   
   # Production mode
   npm start
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/admin-login` - Admin login

### Businesses
- `GET /api/businesses` - Get approved businesses
- `POST /api/businesses` - Submit new business
- `PATCH /api/businesses/:id/status` - Update business status (admin only)

### Products
- `GET /api/products` - Get approved products
- `POST /api/products` - Submit new product
- `PATCH /api/products/:id/status` - Update product status (admin only)

### Professionals
- `GET /api/professionals` - Get approved professionals
- `POST /api/professionals` - Submit new professional
- `PATCH /api/professionals/:id/status` - Update professional status (admin only)

## Default Admin Credentials

- **Email:** admin@ismaal.com
- **Password:** admin123

## Default Test User Credentials

- **Email:** user@example.com
- **Password:** user123
