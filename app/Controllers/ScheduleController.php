<?php

namespace App\Controllers;

use App\Services\Database;
use Flight;

class ScheduleController {
    private $db;

    public function __construct() {
        $this->db = Database::getConnection(); // Get PDO connection
    }

    /**
     * Add a new schedule
     */
    public function addSchedule() {
        $data = Flight::request()->data->getData();

        // Validate input
        if (empty($data['user_id']) || empty($data['orphanage_id']) || empty($data['scheduled_at'])) {
            Flight::json(['error' => 'All fields (user_id, orphanage_id, scheduled_at) are required'], 400);
            return;
        }

        // Validate scheduled_at format (YYYY-MM-DD HH:MM:SS)
        if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $data['scheduled_at'])) {
            Flight::json(['error' => 'Invalid date-time format. Use YYYY-MM-DD HH:MM:SS'], 400);
            return;
        }

        // Insert new schedule
        $query = $this->db->prepare("
            INSERT INTO schedules (user_id, orphanage_id, scheduled_at)
            VALUES (:user_id, :orphanage_id, :scheduled_at)
        ");
        $query->bindParam(':user_id', $data['user_id'], \PDO::PARAM_INT);
        $query->bindParam(':orphanage_id', $data['orphanage_id'], \PDO::PARAM_INT);
        $query->bindParam(':scheduled_at', $data['scheduled_at']);

        if ($query->execute()) {
            Flight::json(['message' => 'Schedule added successfully'], 201);
        } else {
            Flight::json(['error' => 'Failed to add schedule'], 500);
        }
    }

    /**
     * View all schedules
     */
    public function viewSchedules() {
        $query = $this->db->prepare("
            SELECT 
                schedules.id,
                users.name AS user_name,
                orphanages.name AS orphanage_name,
                schedules.scheduled_at
            FROM schedules
            JOIN users ON schedules.user_id = users.id
            JOIN orphanages ON schedules.orphanage_id = orphanages.id
        ");
        $query->execute();
        $schedules = $query->fetchAll(\PDO::FETCH_ASSOC);

        Flight::json($schedules);
    }
}

