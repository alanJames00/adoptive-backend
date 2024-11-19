<?php

namespace App\Controllers;

use App\Services\Database;
use Flight;

class AuthController {
    private $db;

    public function __construct() {
        $this->db = Database::getConnection(); // Get PDO connection
    }

    /**
     * Handle user registration
     */
    public function register() {
        $data = Flight::request()->data->getData();

        // Validate input
        if (empty($data['name']) || empty($data['email']) || empty($data['password']) || empty($data['phone'])) {
            Flight::json(['error' => 'All fields are required'], 400);
            return;
        }

        // Check if email already exists
        $query = $this->db->prepare("SELECT id FROM users WHERE email = :email");
        $query->bindParam(':email', $data['email']);
        $query->execute();
        if ($query->fetch()) {
            Flight::json(['error' => 'Email already exists'], 400);
            return;
        }

        // Insert new user
        $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
        $query = $this->db->prepare("INSERT INTO users (name, email, phone, password) VALUES (:name, :email, :phone, :password)");
        $query->bindParam(':name', $data['name']);
        $query->bindParam(':email', $data['email']);
        $query->bindParam(':phone', $data['phone']);
        $query->bindParam(':password', $hashedPassword);

        if ($query->execute()) {
            Flight::json(['message' => 'User registered successfully'], 201);
        } else {
            Flight::json(['error' => 'User registration failed'], 500);
        }
    }

    /**
     * Handle user login
     */
    public function login() {
        $data = Flight::request()->data->getData();

        // Validate input
        if (empty($data['email']) || empty($data['password'])) {
            Flight::json(['error' => 'Email and password are required'], 400);
            return;
        }

        // Fetch user by email
        $query = $this->db->prepare("SELECT id, password FROM users WHERE email = :email");
        $query->bindParam(':email', $data['email']);
        $query->execute();
        $user = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$user || !password_verify($data['password'], $user['password'])) {
            Flight::json(['error' => 'Invalid credentials'], 401);
            return;
        }

        // Generate jwt token
        $payload = [
            'id' => $user['id'],
            'email' => $data['email'],
            'iat' => time(),
            'exp' => time() + (60 * 60), // 1h expiration
        ];
        $secret = $_ENV['JWT_SECRET'];
        $token = base64_encode(json_encode($payload)) . '.' . hash_hmac('sha256', json_encode($payload), $secret);

        Flight::json(['token' => $token]);
    }

    /**
     * Verify jwt token
     */
    public function verifyToken($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return false;
        }

        $payload = json_decode(base64_decode($parts[0]), true);
        $signature = $parts[1];
        $secret = $_ENV['JWT_SECRET'];

        if (hash_hmac('sha256', json_encode($payload), $secret) === $signature) {
            // Check token expiration
            if ($payload['exp'] > time()) {
                return $payload;
            }
        }
        return false;
	}

	/**
     * Fetch the user's profile
     */
    public function getProfile() {
        // Retrieve the authenticated user from middleware
        $user = Flight::get('user');

        // Fetch user data from the database
        $query = $this->db->prepare("SELECT id, name, email, phone FROM users WHERE id = :id");
        $query->bindParam(':id', $user['id'], \PDO::PARAM_INT);
        $query->execute();

        $userData = $query->fetch(\PDO::FETCH_ASSOC);

        if (!$userData) {
            Flight::json(['error' => 'User not found'], 404);
            return;
        }

        // Return the user profile
        Flight::json($userData);
	}

	/**
     * Handle password change
     */
	public function changePassword() {
    // Get user information from the token middleware
    $user = Flight::get('user');
    
    // Check if user information exists
    if (!$user || !isset($user['id'])) {
        Flight::json(['error' => 'Unauthorized'], 401);
        return;
    }

    $userId = $user['id']; // Extract the user ID from the token payload

    $data = Flight::request()->data->getData();

    // Validate input
    if (empty($data['current_password']) || empty($data['new_password'])) {
        Flight::json(['error' => 'Current password and new password are required'], 400);
        return;
    }

    // Fetch user by ID
    $query = $this->db->prepare("SELECT password FROM users WHERE id = :id");
    $query->bindParam(':id', $userId);
    $query->execute();
    $userRecord = $query->fetch(\PDO::FETCH_ASSOC);

    if (!$userRecord || !password_verify($data['current_password'], $userRecord['password'])) {
        Flight::json(['error' => 'Invalid current password'], 401);
        return;
    }

    // Hash the new password
    $hashedPassword = password_hash($data['new_password'], PASSWORD_BCRYPT);

    // Update the password in the database
    $updateQuery = $this->db->prepare("UPDATE users SET password = :password WHERE id = :id");
    $updateQuery->bindParam(':password', $hashedPassword);
    $updateQuery->bindParam(':id', $userId);

    if ($updateQuery->execute()) {
        Flight::json(['message' => 'Password changed successfully'], 200);
    } else {
        Flight::json(['error' => 'Failed to update password'], 500);
    }
	}
 
	// ADMIN auth sub controller
	public function adminLogin() {
    $data = Flight::request()->data->getData();

    // Validate input
    if (empty($data['username']) || empty($data['password'])) {
        Flight::json(['error' => 'Username and password are required'], 400);
        return;
    }

    // Fetch admin by username
    $query = $this->db->prepare("SELECT id, username, password FROM admin WHERE username = :username");
    $query->bindParam(':username', $data['username']);
    $query->execute();
    $admin = $query->fetch(\PDO::FETCH_ASSOC);

    // Validate password
    if (!$admin || $admin['password'] !== $data['password']) {
        Flight::json(['error' => 'Invalid credentials'], 401);
        return;
    }

    // Generate a JWT token for the admin
    $payload = [
        'id' => $admin['id'],
        'username' => $admin['username'],
        'role' => 'admin',
        'iat' => time(),
        'exp' => time() + (60 * 60), // 1-hour expiration
    ];
    $secret = $_ENV['JWT_SECRET'];
    $token = base64_encode(json_encode($payload)) . '.' . hash_hmac('sha256', json_encode($payload), $secret);

    // Respond with the token
    Flight::json(['token' => $token]);
}
	//
	
}

