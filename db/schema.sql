-- Drop tables if they exist to ensure a clean slate for new setups.
DROP TABLE IF EXISTS items;
DROP TABLE IF EXISTS guards;
DROP TABLE IF EXISTS users;

-- Stores all registered user information.
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- Stores a secure bcrypt hash, not the plaintext password.
    phone_number VARCHAR(20), -- Optional contact number for finders.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Stores information about security guards who may hold found items.
CREATE TABLE guards (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20), -- Optional contact number for the guard.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- The central table for all lost and found item listings.
CREATE TABLE items (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id), -- Foreign key to the user who posted the item.
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(10) NOT NULL CHECK (category IN ('lost', 'found')), -- Ensures data integrity.
    location VARCHAR(255),
    is_claimed BOOLEAN DEFAULT FALSE,  
    claimed_by INTEGER REFERENCES users(id), -- Foreign key to the user who claimed the item.
    guard_id INTEGER REFERENCES guards(id), -- Foreign key to the guard holding the item.
    custody_status VARCHAR(20) CHECK (custody_status IN ('with_finder', 'with_guard')), -- Tracks who has the item.
    image_url VARCHAR(255), -- Path to the uploaded image.
    date_posted DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
