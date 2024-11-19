<?php

require '../vendor/autoload.php'; // Include Flight using Composer

use Dotenv\Dotenv;
use App\Middlewares\AuthMiddleware;


// Load environment variables
Dotenv::createImmutable(__DIR__ . '/../')->load();

// Add CORS Headers
header('Access-Control-Allow-Origin: *'); // Allow any origin
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS'); // Allow specific methods
header('Access-Control-Allow-Headers: Content-Type, Authorization'); // Allow custom headers

// Handle OPTIONS requests for preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204); // No Content
    exit;
}

// include api routes 
include '../routes/api.php';

Flight::route('GET /', function(){
	error_log("got '/' route"); // Log to terminal
    echo 'Welcome to Flight!';
});

Flight::start();
