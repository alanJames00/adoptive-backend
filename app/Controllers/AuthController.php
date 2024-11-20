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

	/*
	 * User forgot password
	 */
	public function forgetPassword() {
    $data = Flight::request()->data->getData();

    // Validate input
    if (empty($data['email'])) {
        Flight::json(['error' => 'Email is required'], 400);
        return;
    }

    // Fetch user by email
    $query = $this->db->prepare("SELECT id FROM users WHERE email = :email");
    $query->bindParam(':email', $data['email']);
    $query->execute();
    $user = $query->fetch(\PDO::FETCH_ASSOC);

    if (!$user) {
        Flight::json(['error' => 'Email not found'], 404);
        return;
    }

    // Generate jwt token with 10 minutes validity
    $payload = [
        'id' => $user['id'],
        'email' => $data['email'],
        'iat' => time(),
        'exp' => time() + (10 * 60), // 10 minutes expiration
    ];
    $secret = $_ENV['JWT_SECRET'];
    $token = base64_encode(json_encode($payload)) . '.' . hash_hmac('sha256', json_encode($payload),	  $secret);

    // Simulated magic URL
    $magicUrl = $_ENV['APP_URL'] . '/auth/reset-password?token=' . urlencode($token);

    // Simulate sending an email
    $this->sendEmail($data['email'], 'Password Reset Link', "Click the link to reset your password: $magicUrl");

    Flight::json(['message' => 'Password reset link sent to your email'], 200);
	}

	
	private function sendEmail($to, $subject, $message) {
    // Elastic Email API URL
    $url = "https://api.elasticemail.com/v4/emails/transactional";

    // Prepare the payload
    $payload = [
        "Recipients" => [
            "To" => [$to]
        ],
        "Content" => [
            "Body" => [
                [
                    "ContentType" => "HTML",
                    "Content" => $message,
                    "Charset" => "utf-8"
                ]
            ],
            "Subject" => $subject,
			"From" => $_ENV['EMAIL_FROM'] 
		]
    ];

    // Initialize cURL
    $ch = curl_init($url);

    // Set cURL options
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json",
        "X-ElasticEmail-ApiKey: " . $_ENV['ELASTIC_EMAIL_API_KEY'] // Replace with your API key
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

    // Execute the API request
    $response = curl_exec($ch);

    // Check for errors
    if (curl_errno($ch)) {
        error_log('cURL error: ' . curl_error($ch));
    }

    // Close the cURL session
    curl_close($ch);

    // Log the response (for debugging purposes)
    error_log("Elastic Email Response: $response");
	}

// 	public function verifyToken($token) {
//     $parts = explode('.', $token);
//     if (count($parts) !== 2) {
//         return false;
//     }
//
//     $payload = json_decode(base64_decode($parts[0]), true);
//     $signature = $parts[1];
//     $secret = $_ENV['JWT_SECRET'];
//
//     if (hash_hmac('sha256', json_encode($payload), $secret) === $signature) {
//         // Check token expiration
//         if ($payload['exp'] > time()) {
//             return $payload;
//         }
//     }
//     return false;
// }

	public function resetPassword() {
    $data = Flight::request()->data->getData();

    // Validate input
    if (empty($data['token']) || empty($data['new_password'])) {
        Flight::json(['error' => 'Token and new password are required'], 400);
        return;
    }

    // Decode and verify the token
    $token = $data['token'];
    $decodedPayload = $this->verifyToken($token);

    if (!$decodedPayload) {
        Flight::json(['error' => 'Invalid or expired token'], 401);
        return;
    }

    $userId = $decodedPayload['id'];

    // Hash the new password
    $hashedPassword = password_hash($data['new_password'], PASSWORD_BCRYPT);

    // Update the user's password
    $query = $this->db->prepare("UPDATE users SET password = :password WHERE id = :id");
    $query->bindParam(':password', $hashedPassword);
    $query->bindParam(':id', $userId);

    if ($query->execute()) {
        Flight::json(['message' => 'Password reset successfully'], 200);
    } else {
        Flight::json(['error' => 'Failed to reset password'], 500);
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

	/**
 * Fetch all end users
 */
	public function getAllUsers() {
    // Check if the current user is an admin (Optional)
    $user = Flight::get('user');
    if (!$user || $user['role'] !== 'admin') {
        Flight::json(['error' => 'Unauthorized'], 401);
        return;
    }

    // Query to fetch all users
    $query = $this->db->prepare("SELECT id, name, email, phone FROM users");
    $query->execute();
    $users = $query->fetchAll(\PDO::FETCH_ASSOC);

    if ($users) {
        Flight::json($users, 200);
    } else {
        Flight::json(['message' => 'No users found'], 404);
    }
	}

}

