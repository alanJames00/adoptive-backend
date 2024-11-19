<?php

namespace App\Services;

use PDO;
use PDOException;

class Database {
    private static $connection = null;

    /**
     * Get the PDO connection instance.
     *
     * @return PDO
     */
    public static function getConnection() {
        if (self::$connection === null) {
            try {
                // Read environment variables
                $host = $_ENV['DB_HOST'];
                $dbName = $_ENV['DB_NAME'];
                $username = $_ENV['DB_USER'];
				$password = $_ENV['DB_PASS'];
				$port = $_ENV['DB_PORT'];

                // Create the PDO connection
                self::$connection = new PDO(
                    "mysql:host=$host;port=$port;dbname=$dbName;charset=utf8mb4",
                    $username,
                    $password
                );
                self::$connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            } catch (PDOException $e) {
                // Handle connection errors
                die("Database connection failed: " . $e->getMessage());
            }
        }

        return self::$connection;
    }
}

