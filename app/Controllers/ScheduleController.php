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
        // Get authenticated user data from the JWT token
        $user = Flight::get('user');

        if (!$user || !isset($user['id'])) {
            Flight::json(['error' => 'Unauthorized'], 401);
            return;
        }

        $data = Flight::request()->data->getData();

        // Validate input
        if (empty($data['orphanage_id']) || empty($data['scheduled_at'])) {
            Flight::json(['error' => 'All fields (orphanage_id, scheduled_at) are required'], 400);
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
        $query->bindParam(':user_id', $user['id'], \PDO::PARAM_INT);
        $query->bindParam(':orphanage_id', $data['orphanage_id'], \PDO::PARAM_INT);
        $query->bindParam(':scheduled_at', $data['scheduled_at']);

        if ($query->execute()) {
            Flight::json(['message' => 'Schedule added successfully'], 201);
        } else {
            Flight::json(['error' => 'Failed to add schedule'], 500);
        }
    }
 

    /**
     * View all schedules of authenticated user
	 */
    public function getSchedules() {
        // Get authenticated user data from the JWT token
        $user = Flight::get('user');

        if (!$user || !isset($user['id'])) {
            Flight::json(['error' => 'Unauthorized'], 401);
            return;
        }

        $query = $this->db->prepare("
            SELECT 
                schedules.id,
				orphanages.name AS orphanage_name,
				orphanages.id AS orphanage_id,
                schedules.scheduled_at
            FROM schedules
            JOIN orphanages ON schedules.orphanage_id = orphanages.id
            WHERE schedules.user_id = :user_id
        ");
        $query->bindParam(':user_id', $user['id'], \PDO::PARAM_INT);
        $query->execute();
        $schedules = $query->fetchAll(\PDO::FETCH_ASSOC);

        Flight::json($schedules);
	}

	/**
 * View schedules for a specific orphanage by orphanage ID
 */
	public function getSchedulesByOrphanageId($orphanageId) {
	// Validate orphanage ID
		if (empty($orphanageId)) {
        Flight::json(['error' => 'Orphanage ID is required'], 400);
        return;
		}

    $query = $this->db->prepare("
        SELECT 
            schedules.id AS schedule_id,
            users.name AS user_name,
			users.email AS user_email,
			users.phone AS user_phone,
			users.id AS user_id,
            schedules.scheduled_at
        FROM schedules
        JOIN users ON schedules.user_id = users.id
        WHERE schedules.orphanage_id = :orphanage_id
    ");
    $query->bindParam(':orphanage_id', $orphanageId, \PDO::PARAM_INT);
    $query->execute();
    $schedules = $query->fetchAll(\PDO::FETCH_ASSOC);

    if ($schedules) {
        Flight::json($schedules, 200);
    } else {
        Flight::json(['message' => 'No schedules found for this orphanage'], 404);
    }
	}


	/**
	 * View All schedules
	 */
	public function getAllSchedules() {
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

	/**
     * Delete a schedule
     */
    public function deleteSchedule($scheduleId) {
        $user = Flight::get('user');
        if (!$user || !isset($user['id'])) {
            Flight::json(['error' => 'Unauthorized'], 401);
            return;
        }

        // Verify if the schedule belongs to the user
        $query = $this->db->prepare("
            SELECT id FROM schedules 
            WHERE id = :id AND user_id = :user_id
        ");
        $query->bindParam(':id', $scheduleId, \PDO::PARAM_INT);
        $query->bindParam(':user_id', $user['id'], \PDO::PARAM_INT);
        $query->execute();
        $schedule = $query->fetch();

        if (!$schedule) {
            Flight::json(['error' => 'Schedule not found or unauthorized'], 404);
            return;
        }

        // Delete the schedule
        $deleteQuery = $this->db->prepare("DELETE FROM schedules WHERE id = :id");
        $deleteQuery->bindParam(':id', $scheduleId, \PDO::PARAM_INT);

        if ($deleteQuery->execute()) {
            Flight::json(['message' => 'Schedule deleted successfully'], 200);
        } else {
            Flight::json(['error' => 'Failed to delete schedule'], 500);
        }
    }
}

