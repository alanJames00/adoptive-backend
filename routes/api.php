<?php

use App\Controllers\AuthController;
use App\Middlewares\AuthMiddleware;
use App\Controllers\OrphanageController;
use App\Controllers\ScheduleController;


// User Authentication Routes
Flight::route('POST /register', [new AuthController(), 'register']);
Flight::route('POST /login', [new AuthController(), 'login']);
Flight::route('POST /forgot-password', [new AuthController(), 'forgetPassword']);
Flight::route('POST /reset-password', [new AuthController(), 'resetPassword']);

// Protected Routes by end user token
// get end user profile
Flight::route('GET /profile', function () {
    AuthMiddleware::authenticate(); // Middleware call
    (new AuthController())->getProfile(); 
});

// change end user password
Flight::route('POST /change-password', function () {
	AuthMiddleware::authenticate(); 
	(new AuthController())->changePassword(); 
});

// get all orphanage
Flight::route('GET /orphanages', function () {
	AuthMiddleware::authenticate(); 
	(new OrphanageController())->getOrphanages(); 
});

// get orphanage by id
Flight::route('GET /orphanages/@id', function ($id) {
	AuthMiddleware::authenticate(); 
	(new OrphanageController())->getOrphanageById($id); 
});

// scheduling a visit
Flight::route('POST /schedule', function () {
	AuthMiddleware::authenticate(); 
	(new ScheduleController())->addSchedule(); 
});

// get schedules of a user
Flight::route('GET /schedules', function () {
	AuthMiddleware::authenticate(); 
	(new ScheduleController())->getSchedules(); 
});

// delete a schedule of a user
Flight::route('DELETE /schedules/@id', function ($id) {
	AuthMiddleware::authenticate(); 
	(new ScheduleController())->deleteSchedule($id); 
});

// admin Authentication Routes
Flight::route('POST /admin/login', [new AuthController(), 'adminLogin']);

// admin protected routes
// fetch all orphanages
Flight::route('GET /admin/orphanages', function () {
	AuthMiddleware::authenticate(); 
	(new OrphanageController())->getOrphanages(); 
});

// add new orphanage
Flight::route('POST /admin/orphanages', function () {
	AuthMiddleware::authenticate(); 
	(new OrphanageController())->addOrphanage(); 
});

// delete orphanage
Flight::route('DELETE /admin/orphanages/@id', function ($id) {
	AuthMiddleware::authenticate(); 
	(new OrphanageController())->deleteOrphanage($id); 
});

// edit an orphanage


// get all schedules
Flight::route('GET /admin/schedules/all', function () {
	AuthMiddleware::authenticate();
	(new ScheduleController())->getAllSchedules(); 
});

// get orphanage schedules by id
Flight::route('GET /admin/orphanage/schedules/@id', function ($id) {
	AuthMiddleware::authenticate();
	(new ScheduleController())->getSchedulesByOrphanageId($id); 
});


// fetch all users
Flight::route('GET /admin/users', function () {
	AuthMiddleware::authenticate(); 
	(new AuthController())->getAllUsers(); 
});


