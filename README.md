# 📚 Library API Documentation

## 🔍 Description

The **Library API** provides endpoints for managing a library system where users can register, authenticate, and manage their account information. The API also allows interaction with `Author` and `Book` data in the library system. It is secured using **JWT (JSON Web Tokens)** to ensure that only authorized users can perform certain actions. 

## ⚙️ Technologies Used

- **PHP**: Server-side scripting language.
- **Slim Framework**: PHP micro-framework for building REST APIs.
- **JWT (JSON Web Token)**: Used for authentication and authorization.
- **MySQL**: Database to store users, authors, and books information.
- **PDO**: For database interaction.
- **PHP dotenv**: For managing environment variables (if applicable).
- **Firebase JWT**: Library used to generate and decode JWTs.

## 🛠️ API Endpoints

### 1. User Endpoints

#### 1.1 Register User

- **Endpoint**: `/user/register`
- **Method**: `POST`
- **Description**: Registers a new user by creating a new account.

##### Sample Payload:
```json
{
  "username": "john_doe",
  "password": "password123"
}
```

##### Sample Response:
```json
{
  "status": "success",
  "data": null
}
```
##### Fail Response:
```json
{
  "status": "success",
  "data": null
}
```

#### 1.2 Authenticate User

- **Endpoint**: `/user/authenticate`
- **Method**: `POST`
- **Description**: Authenticates a user and returns a JWT token.

#### Sample Payload:
```json
{
  "username": "john_doe",
  "password": "password123"
}
```

#### Sample Response:
```json
{
  "status": "success",
  "token": "<AUTH_TOKEN>",
  "data": null
}
```

#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Incorrect username"
  }
}
```

#### 1.3 Read All Users

- **Endpoint**: `/user/read`
- **Method**: `GET`
- **Description**: Retrieves a list of all users.

#### Sample Payload:
```json
  {
    "status": "success",
    "message": "User data retrieved successfully",
    "token": "<AUTH_TOKEN>",
    "data": [
      {
        "userId": 1,
        "username": "john_doe"
      },
      {
        "userId": 2,
        "username": "jane_doe"
      }
    ]
  }
```

#### Sample Payload:
```json
  {
    "status": "fail",
    "data": {
      "title": "Unauthorized"
    }
  }

```




#### 1.4 Update User

- **Endpoint**: `/user/update/{userId}`
- **Method**: `POST`
- **Description**: Updates an existing user's account information (username and password).

#### Sample Payload:
```json
{
  "new_username": "johnny_doe",
  "new_password": "newpassword123"
}
```

#### Sample Response:
```json
{
  "status": "success",
  "message": "User account updated successfully",
  "token": "<AUTH_TOKEN>",
  "data": null
}
```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Invalid input data"
  }
}
```


#### 1.5 Delete User

- **Endpoint**: `/user/delete/{userId}`
- **Method**: `POST`
- **Description**: Deletes an existing user account.


#### Sample Response:
```json
{
  "status": "success",
  "message": "User account deleted successfully",
  "token": "NEW_JWT_TOKEN_HERE",
  "data": null
}

```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "User not found or already deleted"
  }
}
```


### 2. Author Endpoints

#### 2.1 Register Author

- **Endpoint**: `/author/create`
- **Method**: `POST`
- **Description**: Creates a new author in the system.

##### Sample Payload:
```json
{
  "name": "J.K. Rowling"
}
```

##### Sample Response:
```json
{
  "status": "success",
  "message": "Author created successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
##### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Author name is required"
  }
}
```

#### 2.2 Read All Authors

- **Endpoint**: `/author/read`
- **Method**: `GET`
- **Description**: Retrieves a list of all authors from the database.

##### Sample Response:
```json
{
  "status": "success",
  "message": "Authors retrieved successfully",
  "token": "JWT_TOKEN_HERE",
  "data": [
    {
      "authorId": 1,
      "name": "J.K. Rowling"
    },
    {
      "authorId": 2,
      "name": "George R.R. Martin"
    }
  ]
}

```
##### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Unauthorized"
  }
}
```

#### 2.3 Update Author

- **Endpoint**: `/author/update/{authorId}`
- **Method**: `PUT`
- **Description**: Updates an existing author's name in the database.

#### Sample Payload:
```json
{
  "name": "J.K. Rowling Updated"
}

```

#### Sample Response:
```json
{
  "status": "success",
  "message": "Author updated successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "No author found with that ID"
  }
}
```

#### 2.4 Delete Author

- **Endpoint**: `/author/delete/{authorId}`
- **Method**: `DELETE`
- **Description**: Deletes an author from the database.


#### Sample Response:
```json
{
  "status": "success",
  "message": "Author deleted successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "No author found with that ID"
  }
}
```


### 3. Author Endpoints

#### 3.1 Create Book

- **Endpoint**: `/book/create`
- **Method**: `POST`
- **Description**: Creates a new book by associating it with an author.

##### Sample Payload:
```json
{
  "title": "Harry Potter and the Sorcerer's Stone",
  "authorId": 1
}
```

##### Sample Response:
```json
{
  "status": "success",
  "message": "Book created successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
##### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Book title and author ID are required"
  }
}
```

#### 3.2 Read All Books

- **Endpoint**: `/book/read`
- **Method**: `GET`
- **Description**: Retrieves a list of all books, including their associated authors.

##### Sample Response:
```json
{
  "status": "success",
  "message": "Books retrieved successfully",
  "token": "JWT_TOKEN_HERE",
  "data": [
    {
      "bookId": 1,
      "title": "Harry Potter and the Sorcerer's Stone",
      "authorId": 1
    },
    {
      "bookId": 2,
      "title": "Game of Thrones",
      "authorId": 2
    }
  ]
}

```
##### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "Unauthorized"
  }
}
```

#### 3.3 Update Author

- **Endpoint**: `/book/update/{authorId}`
- **Method**: `PUT`
- **Description**: Updates the information of an existing book, including title and author.

#### Sample Payload:
```json
{
  "title": "Harry Potter and the Chamber of Secrets",
  "authorId": 1
}


```

#### Sample Response:
```json
{
  "status": "success",
  "message": "Book updated successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "No book found with that ID"
  }
}
```

#### 3.4 Delete Book

- **Endpoint**: `/author/delete/{authorId}`
- **Method**: `DELETE`
- **Description**: Deletes a book from the system by its bookId.

#### Sample Response:
```json
{
  "status": "success",
  "message": "Book deleted successfully",
  "token": "JWT_TOKEN_HERE",
  "data": null
}
```
#### Fail Response:
```json
{
  "status": "fail",
  "data": {
    "title": "No book found with that ID"
  }
}
```




