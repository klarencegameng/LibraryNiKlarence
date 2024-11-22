<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';

session_start();

if (!isset($_SESSION['used_tokens'])) {
    $_SESSION['used_tokens'] = [];
}

$app = new \Slim\App;

// Middleware for JWT validation and token rotation
$authMiddleware = function (Request $request, Response $response, callable $next) {
    $authHeader = $request->getHeader('Authorization');

    if ($authHeader) {
        $token = str_replace('Bearer ', '', $authHeader[0]);

        // Check if token has been used
        if (in_array($token, $_SESSION['used_tokens'])) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
        }

        try {
            $decoded = JWT::decode($token, new Key('server_hack', 'HS256'));
            $request = $request->withAttribute('decoded', $decoded);
        } catch (\Exception $e) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Unauthorized: " . $e->getMessage()))));
        }

        // Revoke the token after using it
        $_SESSION['used_tokens'][] = $token;

        // Generate a new token
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $decoded->data->userId)
        ];
        $new_jwt = JWT::encode($payload, $key, 'HS256');

        // Add new token to the request attributes for further processing
        $request = $request->withAttribute('new_jwt', $new_jwt);
    } else {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "data" => array("title" => "Token not provided"))));
    }

    return $next($request, $response);
};

// User registration
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    $usr = trim($data->username);
    $pass = trim($data->password);

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if username already exists
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute([':username' => $usr]);

        if ($stmt->rowCount() > 0) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Username already exists")));
        }

        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

        // Generate JWT token for the new user
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $conn->lastInsertId())
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
});

// User authentication
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->username) || !isset($data->password)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid input data"))));
    }

    $usr = trim($data->username);
    $pass = trim($data->password);

    $servername = "localhost";
    $db_username = "root";
    $db_password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $db_username, $db_password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $checkUserStmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
        $checkUserStmt->execute([':username' => $usr]);

        if ($checkUserStmt->rowCount() == 0) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect username"))));
        }

        $checkPassStmt = $conn->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
        $checkPassStmt->execute([':username' => $usr, ':password' => hash('SHA256', $pass)]);

        if ($checkPassStmt->rowCount() == 0) {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Incorrect password"))));
        }

        // Generate JWT token
        $data = $checkPassStmt->fetch(PDO::FETCH_ASSOC);
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600, 
            'data' => array("userId" => $data['userId'])
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "token" => $jwt, "data" => null)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
});

// Read all users
$app->get('/user/read', function (Request $request, Response $response, array $args) {
    // Get the userId from the token for authentication
    $userId = $request->getAttribute('decoded')->data->userId;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all users from the users table
        $stmt = $conn->prepare("SELECT userId, username FROM users");
        $stmt->execute();

        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Generate a new token for the response
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $userId) // Include userId of the authenticated user
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "message" => "User data retrieved successfully", "token" => $jwt, "data" => $users)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);


// Update user account
$app->put('/user/update/{userId}', function (Request $request, Response $response, array $args) {
    $userId = $args['userId']; // Get user ID from the URL
    $data = json_decode($request->getBody());

    if (!isset($data->new_username) || !isset($data->new_password)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid input data"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update user information
        $updateStmt = $conn->prepare("UPDATE users SET username = :new_username, password = :new_password WHERE userId = :userId");
        $updateStmt->execute([
            ':new_username' => $data->new_username,
            ':new_password' => hash('SHA256', $data->new_password),
            ':userId' => $userId
        ]);

        if ($updateStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "User account updated successfully", "token" => $jwt, "data" => null)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No changes made or user not found"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);


// Delete user account
$app->delete('/user/delete/{userId}', function (Request $request, Response $response, array $args) {
    $userId = $args['userId']; // Get user ID from the URL

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $deleteStmt = $conn->prepare("DELETE FROM users WHERE userId = :userId");
        $deleteStmt->execute([':userId' => $userId]);

        if ($deleteStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "User account deleted successfully", "token" => $jwt, "data" => null)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "User not found or already deleted"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);




// Create new author
$app->post('/author/create', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->name)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Insert new author into authors table
        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':name' => $data->name]);

        // Generate a new token for the response
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author created successfully", "token" => $jwt)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Read all authors
$app->get('/author/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all authors from the authors table
        $stmt = $conn->prepare("SELECT authorId, name FROM authors");
        $stmt->execute();

        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Generate a new token for the response
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Authors retrieved successfully", "token" => $jwt, "data" => $authors)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Update author
$app->put('/author/update/{authorId}', function (Request $request, Response $response, array $args) {
    $authorId = $args['authorId']; // Get author ID from the URL
    $data = json_decode($request->getBody());

    if (!isset($data->name)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author name is required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update author information
        $updateStmt = $conn->prepare("UPDATE authors SET name = :name WHERE authorId = :authorId");
        $updateStmt->execute([
            ':name' => $data->name,
            ':authorId' => $authorId
        ]);

        if ($updateStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author updated successfully", "token" => $jwt)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No author found with that ID"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Delete author
$app->delete('/author/delete/{authorId}', function (Request $request, Response $response, array $args) {
    $authorId = $args['authorId']; // Get author ID from the URL

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete author from authors table
        $deleteStmt = $conn->prepare("DELETE FROM authors WHERE authorId = :authorId");
        $deleteStmt->execute([':authorId' => $authorId]);

        if ($deleteStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author deleted successfully", "token" => $jwt)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No author found with that ID"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);



// Create new book
$app->post('/book/create', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    if (!isset($data->title) || !isset($data->authorId)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book title and author ID are required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Insert new book into books table
        $sql = "INSERT INTO books (title, authorId) VALUES (:title, :authorId)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':title' => $data->title, ':authorId' => $data->authorId]);

        // Generate a new token for the response
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book created successfully", "token" => $jwt)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Read all books
$app->get('/book/read', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Fetch all books from the books table
        $stmt = $conn->prepare("SELECT bookId, title, authorId FROM books");
        $stmt->execute();

        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Generate a new token for the response
        $key = 'server_hack';
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat,
            'exp' => $iat + 3600,
            'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
        ];
        $jwt = JWT::encode($payload, $key, 'HS256');

        return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Books retrieved successfully", "token" => $jwt, "data" => $books)));

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Update book
$app->put('/book/update/{bookId}', function (Request $request, Response $response, array $args) {
    $bookId = $args['bookId']; // Get book ID from the URL
    $data = json_decode($request->getBody());

    if (!isset($data->title) || !isset($data->authorId)) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Book title and author ID are required"))));
    }

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Update book information
        $updateStmt = $conn->prepare("UPDATE books SET title = :title, authorId = :authorId WHERE bookId = :bookId");
        $updateStmt->execute([
            ':title' => $data->title,
            ':authorId' => $data->authorId,
            ':bookId' => $bookId
        ]);

        if ($updateStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book updated successfully", "token" => $jwt)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No book found with that ID"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

// Delete book
$app->delete('/book/delete/{bookId}', function (Request $request, Response $response, array $args) {
    $bookId = $args['bookId']; // Get book ID from the URL

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "klarence_library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Delete book from books table
        $deleteStmt = $conn->prepare("DELETE FROM books WHERE bookId = :bookId");
        $deleteStmt->execute([':bookId' => $bookId]);

        if ($deleteStmt->rowCount() > 0) {
            // Generate a new token for the response
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array("userId" => $request->getAttribute('decoded')->data->userId)
            ];
            $jwt = JWT::encode($payload, $key, 'HS256');

            return $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book deleted successfully", "token" => $jwt)));
        } else {
            return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No book found with that ID"))));
        }

    } catch (PDOException $e) {
        return $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
})->add($authMiddleware);

$app->run();
