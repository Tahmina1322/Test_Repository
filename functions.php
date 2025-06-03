<?php
require_once 'config.php';

// Session timeout (30 minutes)
$timeout_duration = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout_duration)) {
    session_unset();
    session_destroy();
    header('Location: login.php?error=' . urlencode('Session timed out at ' . date('Y-m-d H:i:s', time()) . ' CEST'));
    exit;
}
$_SESSION['last_activity'] = time();

// Generate CSRF token
function generateCsrfToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Log staff actions
function logAction($action, $tableName, $recordID, $staffID, $details = null) {
    global $conn;
    $action = mysqli_real_escape_string($conn, $action);
    $tableName = mysqli_real_escape_string($conn, $tableName);
    $recordID = (int)$recordID;
    $staffID = (int)$staffID;
    $details = $details ? mysqli_real_escape_string($conn, $details) : null;
    $query = "INSERT INTO tblauditlogs (action, tableName, recordID, staffID, actionDate, details) VALUES ('$action', '$tableName', $recordID, $staffID, NOW(), " . ($details ? "'$details'" : "NULL") . ")";
    return mysqli_query($conn, $query);
}

// Notification functions
function addNotification($recipientID, $recipientType, $message) {
    global $conn;
    $message = mysqli_real_escape_string($conn, $message);
    $recipientID = (int)$recipientID;
    $userID = $recipientType === 'user' ? $recipientID : NULL;
    $staffID = $recipientType === 'staff' ? $recipientID : NULL;
    $query = "INSERT INTO tblnotifications (userID, staffID, message, createdDate, isRead) 
              VALUES (" . ($userID !== NULL ? $userID : 'NULL') . ", " . ($staffID !== NULL ? $staffID : 'NULL') . ", '$message', NOW(), 0)";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        error_log("Notification insert failed: " . mysqli_error($conn));
        return false;
    }
    return true;
}

function getNotifications($recipientID, $recipientType) {
    global $conn;
    $recipientID = (int)$recipientID;
    $column = $recipientType === 'user' ? 'userID' : 'staffID';
    $query = "SELECT * FROM tblnotifications WHERE $column = $recipientID ORDER BY createdDate DESC LIMIT 10";
    $result = mysqli_query($conn, $query);
    $notifications = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $notifications[] = $row;
    }
    return $notifications;
}

function getUnreadNotificationCount($recipientID, $recipientType) {
    global $conn;
    $recipientID = (int)$recipientID;
    $column = $recipientType === 'user' ? 'userID' : 'staffID';
    $query = "SELECT COUNT(*) FROM tblnotifications WHERE $column = $recipientID AND isRead = 0";
    $result = mysqli_query($conn, $query);
    return (int)mysqli_fetch_row($result)[0];
}

function markNotificationsAsRead($recipientID, $recipientType) {
    global $conn;
    $recipientID = (int)$recipientID;
    $column = $recipientType === 'user' ? 'userID' : 'staffID';
    $query = "UPDATE tblnotifications SET isRead = 1 WHERE $column = $recipientID AND isRead = 0";
    return mysqli_query($conn, $query);
}

// User functions
function userLogin($email, $password) {
    global $conn;
    $email = mysqli_real_escape_string($conn, $email);
    $query = "SELECT userID AS id, username, email, password, 'user' AS role FROM tblusers WHERE email = '$email'";
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    
    if ($user && password_verify($password, $user['password'])) {
        $id = $user['id'];
        $updateQuery = "UPDATE tblusers SET lastLogin = NOW() WHERE userID = $id";
        mysqli_query($conn, $updateQuery);
        return [
            'userID' => $id,
            'username' => $user['username'],
            'email' => $user['email'],
            'role' => $user['role']
        ];
    }
    return false;
}

function staffLogin($email, $password) {
    global $conn;
    $email = mysqli_real_escape_string($conn, $email);
    $query = "SELECT staffID AS id, staffName AS username, email, password, IF(isAdmin, 'admin', 'staff') AS role FROM tblstaff WHERE email = '$email'";
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    
    if ($user && password_verify($password, $user['password'])) {
        $id = $user['id'];
        return [
            'userID' => $id,
            'username' => $user['username'],
            'email' => $user['email'],
            'role' => $user['role']
        ];
    }
    return false;
}

function signup($username, $email, $password) {
    global $conn;
    $username = mysqli_real_escape_string($conn, $username);
    $email = mysqli_real_escape_string($conn, $email);
    $query = "SELECT COUNT(*) FROM tblusers WHERE username = '$username' OR email = '$email'";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false;
    }
    
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $query = "INSERT INTO tblusers (username, email, password, joinDate) 
              VALUES ('$username', '$email', '$hashedPassword', CURDATE())";
    return mysqli_query($conn, $query);
}

function getUsers() {
    global $conn;
    $query = "SELECT u.userID, u.username, u.email, u.joinDate, u.lastLogin, 
                     COUNT(bo.bookID) AS bookCount
              FROM tblusers u
              LEFT JOIN tblbook_ownership bo ON u.userID = bo.userID
              GROUP BY u.userID
              ORDER BY u.joinDate DESC";
    $result = mysqli_query($conn, $query);
    $users = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $users[] = $row;
    }
    return $users;
}

function updateUser($userID, $username, $email, $password = null) {
    global $conn;
    $userID = (int)$userID;
    $username = mysqli_real_escape_string($conn, $username);
    $email = mysqli_real_escape_string($conn, $email);

    $query = "SELECT COUNT(*) FROM tblusers WHERE (username = '$username' OR email = '$email') AND userID != $userID";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Username or email already exists for another user
    }

    $updateQuery = "UPDATE tblusers SET username = '$username', email = '$email'";
    if ($password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $updateQuery .= ", password = '$hashedPassword'";
    }
    $updateQuery .= " WHERE userID = $userID";

    if (mysqli_query($conn, $updateQuery)) {
        if ($_SESSION['role'] !== 'user') {
            logAction('Update User', 'tblusers', $userID, $_SESSION['userID'], "Updated user: $username");
        }
        return true;
    }
    return false;
}

function deleteUser($userID) {
    global $conn;
    $userID = (int)$userID;
    $query = "SELECT COUNT(*) FROM tblbook_ownership WHERE userID = $userID";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Cannot delete user with associated books
    }

    $query = "DELETE FROM tblusers WHERE userID = $userID";
    if (mysqli_query($conn, $query)) {
        $user = mysqli_fetch_assoc(mysqli_query($conn, "SELECT username FROM tblusers WHERE userID = $userID"));
        if ($_SESSION['role'] !== 'user') {
            logAction('Delete User', 'tblusers', $userID, $_SESSION['userID'], "Deleted user: {$user['username']}");
        }
        return true;
    }
    return false;
}

// Staff functions
function getStaff() {
    global $conn;
    $query = "SELECT staffID, staffName, email, IF(isAdmin, 'admin', 'staff') AS role, isAdmin, hireDate 
              FROM tblstaff 
              ORDER BY hireDate DESC";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        error_log("getStaff failed: " . mysqli_error($conn));
        return [];
    }
    $staff = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $staff[] = $row;
    }
    return $staff;
}

function addStaff($staffName, $email, $password, $role, $isAdmin) {
    global $conn;
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
        return false; // Only admin can add staff
    }
    $staffName = mysqli_real_escape_string($conn, $staffName);
    $email = mysqli_real_escape_string($conn, $email);
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $role = mysqli_real_escape_string($conn, $role);
    $isAdmin = (int)$isAdmin;

    $query = "SELECT COUNT(*) FROM tblstaff WHERE email = '$email'";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Email already exists
    }

    $query = "INSERT INTO tblstaff (staffName, email, password, role, isAdmin, hireDate) 
              VALUES ('$staffName', '$email', '$hashedPassword', '$role', $isAdmin, CURDATE())";
    if (mysqli_query($conn, $query)) {
        $staffID = mysqli_insert_id($conn);
        logAction('Add Staff', 'tblstaff', $staffID, $_SESSION['userID'], "Added staff: $staffName");
        return true;
    }
    return false;
}

function updateStaff($staffID, $staffName, $email, $password, $role, $isAdmin) {
    global $conn;
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
        return false; // Only admin can update staff
    }
    $staffID = (int)$staffID;
    $staffName = mysqli_real_escape_string($conn, $staffName);
    $email = mysqli_real_escape_string($conn, $email);
    $role = mysqli_real_escape_string($conn, $role);
    $isAdmin = (int)$isAdmin;

    $query = "SELECT COUNT(*) FROM tblstaff WHERE email = '$email' AND staffID != $staffID";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Email already exists for another staff
    }

    $updateQuery = "UPDATE tblstaff SET staffName = '$staffName', email = '$email', role = '$role', isAdmin = $isAdmin";
    if ($password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $updateQuery .= ", password = '$hashedPassword'";
    }
    $updateQuery .= " WHERE staffID = $staffID";

    if (mysqli_query($conn, $updateQuery)) {
        logAction('Update Staff', 'tblstaff', $staffID, $_SESSION['userID'], "Updated staff: $staffName");
        return true;
    }
    return false;
}

function deleteStaff($staffID) {
    global $conn;
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
        return false; // Only admin can delete staff
    }
    $staffID = (int)$staffID;
    $query = "SELECT COUNT(*) FROM tblgenres WHERE createdBy = $staffID";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Cannot delete staff with associated genres
    }

    $query = "DELETE FROM tblstaff WHERE staffID = $staffID";
    if (mysqli_query($conn, $query)) {
        $staff = mysqli_fetch_assoc(mysqli_query($conn, "SELECT staffName FROM tblstaff WHERE staffID = $staffID"));
        logAction('Delete Staff', 'tblstaff', $staffID, $_SESSION['userID'], "Deleted staff: {$staff['staffName']}");
        return true;
    }
    return false;
}

// Book functions
function getBooks($userID = null, $search = '', $genreID = '', $status = '', $minRating = '', $userIDFilter = '') {
    global $conn;
    $query = "SELECT b.*, g.genreName, bs.status, COALESCE(AVG(r.rating), 0) AS avgRating
              FROM tblbooks b
              LEFT JOIN tblgenres g ON b.genreID = g.genreID
              LEFT JOIN tblbookstatus bs ON b.bookID = bs.bookID
              LEFT JOIN tblbook_ownership bo ON b.bookID = bo.bookID
              LEFT JOIN tblusers u ON bo.userID = u.userID
              LEFT JOIN tblratings r ON b.bookID = r.bookID
              WHERE 1=1";
    
    $params = [];
    $types = '';
    
    if ($userID && $_SESSION['role'] === 'user') {
        $query .= " AND bo.userID = ?";
        $params[] = $userID;
        $types .= 'i';
    }
    if (!empty($search)) {
        $query .= " AND (LOWER(b.title) LIKE LOWER(?) OR LOWER(b.author) LIKE LOWER(?))";
        $params[] = "%$search%";
        $params[] = "%$search%";
        $types .= 'ss';
    }
    if (!empty($genreID)) {
        $query .= " AND b.genreID = ?";
        $params[] = $genreID;
        $types .= 'i';
    }
    if (!empty($status)) {
        $query .= " AND bs.status = ?";
        $params[] = $status;
        $types .= 's';
    }
    if (!empty($userIDFilter) && $_SESSION['role'] !== 'user') {
        $query .= " AND bo.userID = ?";
        $params[] = $userIDFilter;
        $types .= 'i';
    }
    
    $query .= " GROUP BY b.bookID";
    
    if ($minRating !== '') {
        $query .= " HAVING avgRating >= ?";
        $params[] = (float)$minRating;
        $types .= 'd';
    }

    error_log("getBooks Query: $query");
    error_log("getBooks Params: " . print_r($params, true));

    $stmt = $conn->prepare($query);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $books = [];
    while ($row = $result->fetch_assoc()) {
        $books[] = $row;
    }
    $stmt->close();
    
    error_log("getBooks Returned: " . count($books) . " books");
    return $books;
}

function getBookById($bookID) {
    global $conn;
    $bookID = (int)$bookID;
    $query = "SELECT b.*, g.genreName, bs.status, COALESCE(AVG(r.rating), 0) AS avgRating
              FROM tblbooks b
              LEFT JOIN tblgenres g ON b.genreID = g.genreID
              LEFT JOIN tblbookstatus bs ON b.bookID = bs.bookID
              LEFT JOIN tblbook_ownership bo ON b.bookID = bo.bookID
              LEFT JOIN tblusers u ON bo.userID = u.userID
              LEFT JOIN tblratings r ON b.bookID = r.bookID
              WHERE b.bookID = $bookID
              GROUP BY b.bookID";
    $result = mysqli_query($conn, $query);
    return mysqli_fetch_assoc($result);
}

function getBookOwners($bookID) {
    global $conn;
    $bookID = (int)$bookID;
    $query = "SELECT u.username, bo.ownershipType, bo.addedDate
              FROM tblbook_ownership bo
              JOIN tblusers u ON bo.userID = u.userID
              WHERE bo.bookID = $bookID
              ORDER BY bo.addedDate DESC";
    $result = mysqli_query($conn, $query);
    $owners = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $owners[] = $row;
    }
    return $owners;
}

function addBook($title, $author, $genreID, $assignedUserID, $imagePath = null) {
    global $conn;
    $title = mysqli_real_escape_string($conn, $title);
    $author = mysqli_real_escape_string($conn, $author);
    $genreID = (int)$genreID;
    $assignedUserID = $assignedUserID ? (int)$assignedUserID : null;
    $imagePath = $imagePath ? mysqli_real_escape_string($conn, $imagePath) : null;

    // Check for existing book with the same title and author
    $checkQuery = "SELECT bookID FROM tblbooks WHERE LOWER(title) = LOWER('$title') AND LOWER(author) = LOWER('$author')";
    $result = mysqli_query($conn, $checkQuery);
    if ($result && mysqli_num_rows($result) > 0) {
        $existingBook = mysqli_fetch_assoc($result);
        $bookID = $existingBook['bookID'];

        // Check if the assigned user already owns this book
        if ($assignedUserID) {
            $ownershipQuery = "SELECT COUNT(*) FROM tblbook_ownership bo WHERE bo.bookID = $bookID AND bo.userID = $assignedUserID";
            $ownershipResult = mysqli_query($conn, $ownershipQuery);
            if (mysqli_fetch_row($ownershipResult)[0] > 0) {
                return "Error: User already owns this book titled '$title' by $author.";
            }

            $insertOwnershipQuery = "INSERT INTO tblbook_ownership (bookID, userID, ownershipType, addedDate) VALUES ($bookID, $assignedUserID, 'Co-owner', CURDATE())";
            if (!mysqli_query($conn, $insertOwnershipQuery)) {
                return "Error: Failed to add user as co-owner for '$title' by $author.";
            }

            $statusQuery = "INSERT INTO tblbookstatus (bookID, status, statusDate, updatedBy) VALUES ($bookID, 'Available', CURDATE(), $assignedUserID)";
            if (!mysqli_query($conn, $statusQuery)) {
                return "Error: Failed to update status for '$title' by $author.";
            }

            $notification = "You are now a co-owner of '$title' by $author!";
            if (!addNotification($assignedUserID, 'user', $notification)) {
                return "Error: Book added, but notification failed for '$title'.";
            }
            if ($_SESSION['role'] !== 'user') {
                logAction('Add Book', 'tblbooks', $bookID, $_SESSION['userID'], "Added as co-owner: $title, userID: $assignedUserID");
            }
            return "Success: Added as co-owner of '$title' by $author!";
        }
        return "Error: Book '$title' by $author already exists and cannot be unassigned.";
    }

    // Insert new book if no duplicate found
    $insertBookQuery = "INSERT INTO tblbooks (title, author, genreID, addedDate" . ($imagePath ? ", imagePath" : "") . ") 
                        VALUES ('$title', '$author', $genreID, CURDATE()" . ($imagePath ? ", '$imagePath'" : "") . ")";
    if (!mysqli_query($conn, $insertBookQuery)) {
        return "Error: Failed to add new book '$title' by $author.";
    }

    $bookID = mysqli_insert_id($conn);

    // Insert ownership record
    $userID = $assignedUserID ?: $_SESSION['userID'];
    $ownershipType = $assignedUserID ? 'Co-owner' : 'Owner';
    $insertOwnershipQuery = "INSERT INTO tblbook_ownership (bookID, userID, ownershipType, addedDate) VALUES ($bookID, $userID, '$ownershipType', CURDATE())";
    if (!mysqli_query($conn, $insertOwnershipQuery)) {
        return "Error: Failed to set ownership for new book '$title' by $author.";
    }

    $statusQuery = "INSERT INTO tblbookstatus (bookID, status, statusDate, updatedBy) VALUES ($bookID, 'Available', CURDATE(), $userID)";
    if (!mysqli_query($conn, $statusQuery)) {
        return "Error: Failed to set status for new book '$title' by $author.";
    }

    $notification = "Book '$title' by $author added successfully!";
    if (!addNotification($userID, 'user', $notification)) {
        return "Error: Book added, but notification failed for '$title'.";
    }
    if ($_SESSION['role'] !== 'user') {
        logAction('Add Book', 'tblbooks', $bookID, $_SESSION['userID'], "Added new book: $title, userID: $userID");
    }
    return "Success: Added new book '$title' by $author!";
}

function updateBook($bookID, $title, $author, $genreID, $imagePath = null) {
    global $conn;
    $bookID = (int)$bookID;
    $title = mysqli_real_escape_string($conn, $title);
    $author = mysqli_real_escape_string($conn, $author);
    $genreID = (int)$genreID;
    $imagePath = $imagePath ? mysqli_real_escape_string($conn, $imagePath) : null;
    
    $query = "UPDATE tblbooks SET title = '$title', author = '$author', genreID = $genreID";
    if ($imagePath) {
        $query .= ", imagePath = '$imagePath'";
    }
    $query .= " WHERE bookID = $bookID";
    
    if (mysqli_query($conn, $query)) {
        if ($_SESSION['role'] !== 'user') {
            logAction('Update Book', 'tblbooks', $bookID, $_SESSION['userID'], "Updated book: $title");
        }
        return true;
    }
    return false;
}

function deleteBook($bookID) {
    global $conn;
    $bookID = (int)$bookID;
    $book = getBookById($bookID);
    mysqli_begin_transaction($conn);
    try {
        $query = "DELETE FROM tblbookstatus WHERE bookID = $bookID";
        mysqli_query($conn, $query);
        $query = "DELETE FROM tblratings WHERE bookID = $bookID";
        mysqli_query($conn, $query);
        $query = "DELETE FROM tblreviews WHERE bookID = $bookID";
        mysqli_query($conn, $query);
        $query = "DELETE FROM tblbook_ownership WHERE bookID = $bookID";
        mysqli_query($conn, $query);
        $query = "DELETE FROM tblbooks WHERE bookID = $bookID";
        mysqli_query($conn, $query);
        if ($_SESSION['role'] !== 'user') {
            logAction('Delete Book', 'tblbooks', $bookID, $_SESSION['userID'], "Deleted book: {$book['title']}");
        }
        mysqli_commit($conn);
        return true;
    } catch (Exception $e) {
        mysqli_rollback($conn);
        return false;
    }
}

function updateBookStatus($bookID, $status, $updatedBy) {
    global $conn;
    // Restrict status updates to users only
    if ($_SESSION['role'] !== 'user') {
        return false;
    }
    
    $bookID = (int)$bookID;
    $status = mysqli_real_escape_string($conn, $status);
    $updatedBy = (int)$updatedBy;
    
    // Verify the user owns the book
    $query = "SELECT COUNT(*) FROM tblbook_ownership WHERE bookID = ? AND userID = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('ii', $bookID, $updatedBy);
    $stmt->execute();
    $stmt->bind_result($ownershipCount);
    $stmt->fetch();
    $stmt->close();
    
    if ($ownershipCount == 0) {
        return false; // User does not own the book
    }
    
    $query = "SELECT COUNT(*) FROM tblbookstatus WHERE bookID = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('i', $bookID);
    $stmt->execute();
    $stmt->bind_result($statusCount);
    $stmt->fetch();
    $stmt->close();
    
    if ($statusCount > 0) {
        $query = "UPDATE tblbookstatus SET status = ?, statusDate = CURDATE(), updatedBy = ? WHERE bookID = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param('sii', $status, $updatedBy, $bookID);
    } else {
        $query = "INSERT INTO tblbookstatus (bookID, status, statusDate, updatedBy) VALUES (?, ?, CURDATE(), ?)";
        $stmt = $conn->prepare($query);
        $stmt->bind_param('isi', $bookID, $status, $updatedBy);
    }
    
    $result = $stmt->execute();
    if ($result) {
        $book = getBookById($bookID);
        logAction('Update Status', 'tblbookstatus', $bookID, $updatedBy, "Changed status to $status for book: {$book['title']}");
    }
    $stmt->close();
    return $result;
}

function rateBook($bookID, $userID, $rating) {
    global $conn;
    $bookID = (int)$bookID;
    $userID = (int)$userID;
    $rating = (int)$rating;

    // Check if the user exists
    $checkUserQuery = "SELECT COUNT(*) FROM tblusers WHERE userID = ?";
    $stmt = $conn->prepare($checkUserQuery);
    $stmt->bind_param('i', $userID);
    $stmt->execute();
    $stmt->bind_result($userCount);
    $stmt->fetch();
    $stmt->close();

    if ($userCount == 0) {
        error_log("Attempt to rate book with non-existent userID: $userID");
        return false;
    }

    if ($rating < 1 || $rating > 5) {
        return false;
    }

    $query = "SELECT COUNT(*) FROM tblratings WHERE bookID = ? AND userID = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('ii', $bookID, $userID);
    $stmt->execute();
    $stmt->bind_result($ratingCount);
    $stmt->fetch();
    $stmt->close();

    if ($ratingCount > 0) {
        $query = "UPDATE tblratings SET rating = ?, ratedDate = CURDATE() WHERE bookID = ? AND userID = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param('iii', $rating, $bookID, $userID);
    } else {
        $query = "INSERT INTO tblratings (bookID, userID, rating, ratedDate) VALUES (?, ?, ?, CURDATE())";
        $stmt = $conn->prepare($query);
        $stmt->bind_param('iii', $bookID, $userID, $rating);
    }

    $result = $stmt->execute();
    $stmt->close();
    return $result;
}

// Review functions
function addReview($bookID, $userID, $reviewText) {
    global $conn;
    $bookID = (int)$bookID;
    $userID = (int)$userID;
    $reviewText = mysqli_real_escape_string($conn, $reviewText);
    $query = "INSERT INTO tblreviews (bookID, userID, reviewText, reviewDate) 
              VALUES ($bookID, $userID, '$reviewText', CURDATE())";
    return mysqli_query($conn, $query);
}

function getReviews($bookID) {
    global $conn;
    $bookID = (int)$bookID;
    $query = "SELECT r.*, u.username FROM tblreviews r 
              JOIN tblusers u ON r.userID = u.userID 
              WHERE r.bookID = $bookID 
              ORDER BY r.reviewDate DESC";
    $result = mysqli_query($conn, $query);
    $reviews = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $reviews[] = $row;
    }
    return $reviews;
}

// Genre functions
function getGenres() {
    global $conn;
    $query = "SELECT g.*, COUNT(b.bookID) AS bookCount 
              FROM tblgenres g 
              LEFT JOIN tblbooks b ON g.genreID = b.genreID 
              WHERE g.isActive = 1 
              GROUP BY g.genreID";
    $result = mysqli_query($conn, $query);
    if (!$result) {
        return [];
    }
    $genres = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $genres[] = $row;
    }
    return $genres;
}

function addGenre($genreName, $description, $createdBy) {
    global $conn;
    $genreName = mysqli_real_escape_string($conn, $genreName);
    $description = mysqli_real_escape_string($conn, $description);
    $createdBy = (int)$createdBy;

    // Check if an inactive genre with the same name exists
    $query = "SELECT genreID FROM tblgenres WHERE genreName = '$genreName' AND isActive = 0";
    $result = mysqli_query($conn, $query);
    if ($result && mysqli_num_rows($result) > 0) {
        $genre = mysqli_fetch_assoc($result);
        // Reactivate the existing genre
        $query = "UPDATE tblgenres SET isActive = 1, description = '$description', createdBy = $createdBy WHERE genreID = " . $genre['genreID'];
        if (mysqli_query($conn, $query)) {
            if ($_SESSION['role'] !== 'user') {
                logAction('Reactivate Genre', 'tblgenres', $genre['genreID'], $createdBy, "Reactivated genre: $genreName");
            }
            return true;
        }
        return false;
    }

    // If no inactive genre, insert a new one
    $query = "INSERT INTO tblgenres (genreName, description, createdDate, isActive, createdBy) 
              VALUES ('$genreName', '$description', CURDATE(), 1, $createdBy)";
    if (mysqli_query($conn, $query)) {
        $genreID = mysqli_insert_id($conn);
        if ($_SESSION['role'] !== 'user') {
            logAction('Add Genre', 'tblgenres', $genreID, $createdBy, "Added genre: $genreName");
        }
        return true;
    }
    return false;
}

function updateGenre($genreID, $genreName, $description) {
    global $conn;
    $genreID = (int)$genreID;
    $genreName = mysqli_real_escape_string($conn, $genreName);
    $description = mysqli_real_escape_string($conn, $description);
    $query = "UPDATE tblgenres SET genreName = '$genreName', description = '$description' 
              WHERE genreID = $genreID";
    if (mysqli_query($conn, $query)) {
        if ($_SESSION['role'] !== 'user') {
            logAction('Update Genre', 'tblgenres', $genreID, $_SESSION['userID'], "Updated genre: $genreName");
        }
        return true;
    }
    return false;
}

function deleteGenre($genreID) {
    global $conn;
    $genreID = (int)$genreID;
    $query = "SELECT COUNT(*) FROM tblbooks WHERE genreID = $genreID";
    $result = mysqli_query($conn, $query);
    if (mysqli_fetch_row($result)[0] > 0) {
        return false; // Cannot delete genre with associated books
    }
    $query = "UPDATE tblgenres SET isActive = 0 WHERE genreID = $genreID";
    if (mysqli_query($conn, $query)) {
        if ($_SESSION['role'] !== 'user') {
            $genre = mysqli_fetch_assoc(mysqli_query($conn, "SELECT genreName FROM tblgenres WHERE genreID = $genreID"));
            logAction('Delete Genre', 'tblgenres', $genreID, $_SESSION['userID'], "Deleted genre: {$genre['genreName']}");
        }
        return true;
    }
    return false;
}

// Image upload function with GD fallback
function uploadImage($file) {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($file['type'], $allowedTypes)) {
        return null;
    }
    $maxSize = 5 * 1024 * 1024; // 5MB
    if ($file['size'] > $maxSize) {
        return null;
    }

    $uploadDir = 'Uploads/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $filename = uniqid() . '-' . basename($file['name']);
    $destination = $uploadDir . $filename;

    if (function_exists('imagecreatetruecolor')) {
        list($width, $height) = getimagesize($file['tmp_name']);
        $targetWidth = 200;
        $targetHeight = 300;
        $newImage = imagecreatetruecolor($targetWidth, $targetHeight);

        if ($file['type'] === 'image/png' || $file['type'] === 'image/gif') {
            imagealphablending($newImage, false);
            imagesavealpha($newImage, true);
            $transparent = imagecolorallocatealpha($newImage, 255, 255, 255, 127);
            imagefilledrectangle($newImage, 0, 0, $targetWidth, $targetHeight, $transparent);
        }

        switch ($file['type']) {
            case 'image/jpeg':
                $source = imagecreatefromjpeg($file['tmp_name']);
                imagecopyresampled($newImage, $source, 0, 0, 0, 0, $targetWidth, $targetHeight, $width, $height);
                imagejpeg($newImage, $destination, 80);
                break;
            case 'image/png':
                $source = imagecreatefrompng($file['tmp_name']);
                imagecopyresampled($newImage, $source, 0, 0, 0, 0, $targetWidth, $targetHeight, $width, $height);
                imagepng($newImage, $destination);
                break;
            case 'image/gif':
                $source = imagecreatefromgif($file['tmp_name']);
                imagecopyresampled($newImage, $source, 0, 0, 0, 0, $targetWidth, $targetHeight, $width, $height);
                imagegif($newImage, $destination);
                break;
        }
        imagedestroy($source);
        imagedestroy($newImage);
    } else {
        // Fallback if GD is not available
        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            return null;
        }
    }

    return $destination;
}
?>