<?php

use App\Controllers\AuthController;
use App\Middlewares\AuthMiddleware;
use App\Controllers\OrphanageController;


// User Authentication Routes
Flight::route('POST /register', [new AuthController(), 'register']);
Flight::route('POST /login', [new AuthController(), 'login']);

// Protected Routes by end user token
// get end user profile
Flight::route('GET /profile', function () {
    AuthMiddleware::authenticate(); // Middleware call
    (new AuthController())->getProfile(); 
});

// change end user password
Flight::route('POST /change-password', function () {
	AuthMiddleware::authenticate(); // auth middleware
	(new AuthController())->changePassword(); 
});


// admin Authentication Routes
Flight::route('POST /admin/login', [new AuthController(), 'adminLogin']);

// admin protected routes
// fetch all orphanages
Flight::route('GET /admin/orphanages', function () {
	AuthMiddleware::authenticate(); // Middleware call
	(new OrphanageController())->getOrphanages(); 
});

// add new orphanage
Flight::route('POST /admin/orphanages', function () {
	AuthMiddleware::authenticate(); // Middleware call
	(new OrphanageController())->addOrphanage(); 
});

// delete orphanage
Flight::route('DELETE /admin/orphanages/@id', function ($id) {
	AuthMiddleware::authenticate(); // Middleware call
	(new OrphanageController())->deleteOrphanage($id); 
});

// edit an orphanage

