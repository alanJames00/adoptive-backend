<?php

namespace App\Middlewares;

use Flight;

class AuthMiddleware {
    // End user authentication middleware
	public static function authenticate() {

		error_log('AuthMiddleware: Starting authentication.');

        $headers = getallheaders();

        // Check if the Authorization header exists
		if (empty($headers['Authorization'])) {
			error_log('AuthMiddleware: Missing Authorization header.');

			header('Content-Type: application/json', true, 401);
			echo json_encode(['error' => 'Authorization header missing']);
			exit;
			error_log('This should not log'); // This should never be logged
		}

		error_log("not Returned above");

        // Extract the token from the header
        $authHeader = $headers['Authorization'];
        $parts = explode(' ', $authHeader); // Expected format: "Bearer <token>"
		if (count($parts) !== 2 || $parts[0] !== 'Bearer') {

			header('Content-Type: application/json', true, 401);
			echo json_encode(['error' => 'Invalid Authorization header format']);
			exit;
        }

        $token = $parts[1];
        $secret = $_ENV['JWT_SECRET'];

        try {
            // Decode and verify the token
            $parts = explode('.', $token);
            if (count($parts) !== 2) {
                throw new \Exception('Invalid token format');
            }

            // Decode payload
            $payload = json_decode(base64_decode($parts[0]), true);
            if ($payload === null || json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid or malformed token payload');
            }

            // Validate signature
            $signature = $parts[1];
            $validSignature = hash_hmac('sha256', json_encode($payload), $secret);

            if ($signature !== $validSignature) {
                throw new \Exception('Invalid token signature');
            }

            // Check token expiration
            if ($payload['exp'] < time()) {
                throw new \Exception('Token has expired');
            }

            // Attach user info to Flight for later use
            Flight::set('user', $payload);
        } catch (\Exception $e) {
            // Return detailed error message for debugging
			header('Content-Type: application/json', true, 401);
			echo json_encode(['error' => 'authentication failed, malformed token']);
			exit;
        }
    }
}

