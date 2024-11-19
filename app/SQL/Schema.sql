-- User table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY, -- Unique ID for each user
    name VARCHAR(255) NOT NULL,        -- User's name
    email VARCHAR(255) NOT NULL UNIQUE, -- User's email (unique)
    phone VARCHAR(15) NOT NULL,        -- User's phone number
    password VARCHAR(255) NOT NULL,    -- Encrypted user password
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Record creation time
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP -- Record update time
);


-- Schedules TABLE
CREATE TABLE schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,            -- Unique ID for each schedule
    user_id INT NOT NULL,                         -- User ID (foreign key)
    orphanage_id INT NOT NULL,                    -- Orphanage ID (foreign key)
    scheduled_at DATETIME NOT NULL,               -- Scheduled date and time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Record creation timestamp
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- Record update timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,   -- Foreign key linking to users
    FOREIGN KEY (orphanage_id) REFERENCES orphanages(id) ON DELETE CASCADE -- Foreign key linking to orphanages
);


-- Admin 
CREATE TABLE admin (
    id INT PRIMARY KEY AUTO_INCREMENT,        -- Auto-incrementing ID
    username VARCHAR(255) NOT NULL UNIQUE,    -- Admin's username
    password VARCHAR(255) NOT NULL,           -- Admin's password (hashed)
    email VARCHAR(255) NOT NULL UNIQUE,       -- Admin's email
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Record creation timestamp
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- Record update timestamp
    UNIQUE KEY (id)                           -- Enforces only one row in the table
);

