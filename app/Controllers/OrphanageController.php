<?php 
namespace App\Controllers;

use App\Services\Database;
use Flight;

class OrphanageController {
    private $db;

    public function __construct() {
        $this->db = Database::getConnection(); // Get PDO connection
    }

    /**
     * Add a new orphanage (Admin Only)
     */
	public function addOrphanage() {
    // Get request data
    $data = Flight::request()->data->getData();

    // Validate required input fields
    if (
        empty($data['name']) || 
        empty($data['email']) || 
        empty($data['phone']) || 
        empty($data['address']) || 
        empty($data['visiting_hours_start']) || 
        empty($data['visiting_hours_end'])
    ) {
        Flight::json(['error' => 'All fields are required'], 400);
        return;
    }

    // Validate email format
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        Flight::json(['error' => 'Invalid email format'], 400);
        return;
    }

    // Validate phone number format (optional)
    if (!preg_match('/^\+?[0-9]{10,15}$/', $data['phone'])) {
        Flight::json(['error' => 'Invalid phone number'], 400);
        return;
    }

    // Check if orphanage email already exists
    $query = $this->db->prepare("SELECT id FROM orphanages WHERE email = :email");
    $query->bindParam(':email', $data['email']);
    $query->execute();
    if ($query->fetch()) {
        Flight::json(['error' => 'Orphanage with this email already exists'], 400);
        return;
    }

    // Insert orphanage with optional fields
    $query = $this->db->prepare("
        INSERT INTO orphanages (
            name, email, phone, address, visiting_hours_start, visiting_hours_end, extra_note, media_links, verified
        ) VALUES (
            :name, :email, :phone, :address, :visiting_hours_start, :visiting_hours_end, :extra_note, :media_links, 1
        )
    ");

    // Bind required parameters
    $query->bindParam(':name', $data['name']);
    $query->bindParam(':email', $data['email']);
    $query->bindParam(':phone', $data['phone']);
    $query->bindParam(':address', $data['address']);
    $query->bindParam(':visiting_hours_start', $data['visiting_hours_start']);
    $query->bindParam(':visiting_hours_end', $data['visiting_hours_end']);

    // Bind optional parameters, or set to null if not provided
    $extraNote = isset($data['extra_note']) ? $data['extra_note'] : null;
    $mediaLinks = isset($data['media_links']) ? json_encode($data['media_links']) : null; // Convert array to JSON
    $query->bindParam(':extra_note', $extraNote);
    $query->bindParam(':media_links', $mediaLinks);

    if ($query->execute()) {
        Flight::json(['message' => 'Orphanage added successfully'], 201);
    } else {
        Flight::json(['error' => 'Failed to add orphanage'], 500);
    }
	}


	 /**
     * Get all orphanages or filtered list
     */
    public function getOrphanages() {
        $queryParams = Flight::request()->query->getData();
        
        $sql = "SELECT id, name, email, phone, address, visiting_hours_start, visiting_hours_end, extra_note, media_links, verified FROM orphanages WHERE 1=1";
        
        // Add filters dynamically if provided in the request
        if (isset($queryParams['name'])) {
            $sql .= " AND name LIKE :name";
        }
        if (isset($queryParams['verified'])) {
            $sql .= " AND verified = :verified";
        }

        $query = $this->db->prepare($sql);

        // Bind parameters if filters are provided
        if (isset($queryParams['name'])) {
            $query->bindValue(':name', '%' . $queryParams['name'] . '%');
        }
        if (isset($queryParams['verified'])) {
            $query->bindValue(':verified', (int)$queryParams['verified'], \PDO::PARAM_INT);
        }

        if ($query->execute()) {
            $orphanages = $query->fetchAll(\PDO::FETCH_ASSOC);
            Flight::json($orphanages, 200);
        } else {
            Flight::json(['error' => 'Failed to retrieve orphanages'], 500);
        }
	}

	public function deleteOrphanage($id) {
    // Validate ID
    if (empty($id) || !is_numeric($id)) {
        Flight::json(['error' => 'Invalid orphanage ID'], 400);
        return;
    }

    // Check if orphanage exists
    $query = $this->db->prepare("SELECT id FROM orphanages WHERE id = :id");
    $query->bindParam(':id', $id, \PDO::PARAM_INT);
    $query->execute();
    $orphanage = $query->fetch();

    if (!$orphanage) {
        Flight::json(['error' => 'Orphanage not found'], 404);
        return;
    }

    // Delete the orphanage
    $deleteQuery = $this->db->prepare("DELETE FROM orphanages WHERE id = :id");
    $deleteQuery->bindParam(':id', $id, \PDO::PARAM_INT);

    if ($deleteQuery->execute()) {
        Flight::json(['message' => 'Orphanage deleted successfully'], 200);
    } else {
        Flight::json(['error' => 'Failed to delete orphanage'], 500);
    }
}

 
}

