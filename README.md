# Web_Server_R
This project is a basic web server implemented in JavaScript using the Express.js framework. It provides user registration, login, and post creation functionalities, with authentication using JSON Web Tokens (JWTs) and data storage in a MySQL database.

## Getting Started - Setting up the environment
**After extracting the JavaScript file**

1. **Start with MySQL Database configuration**

You can find the exported MySQL databse in this repository, you can simply import it to your system.
Else, ensure that the tables naming are set the same, because the javascript has predefined Queries.

3. **Run the server**

You can Execute the javascript file to start the web server.

4. **ensure that there are no errors encountered during the setup before starting with the End point testing**

Hopefully no issues are encountered here :)

# API Endpoint Testing - Using Postman for testing
**Use the following URL in Postman to interract with the endpoints:**
**http://localhost:3000/[Path_Or_Endpoint]**


## User Registration
- **Endpoint:** '/signup'
- **Method:** 'POST'
- **Description:** 'Register a new user by sending a POST request with name, username, and password.'
- **JSON Payload:** 
{
  "name": "[Your name]",
  "username": "[Your_Username]",
  "password": "[Your_Password]"
}

## User Login
- **Endpoint:** '/login'
- **Method:** 'POST'
- **Description:** 'Log in with an existing user by sending a POST request with username and password.'
- **JSON Payload:** 
{
  "username": "[Your_Username]",
  "password": "[Your_Password]"
}
### additional instructions
**Output**
  you will get an output of a token, use the token in post man in the **'Authorization'** tab as a bearer Token Type. Then proceed with the following steps of testing...


## Creating A Post
- **Endpoint:** '/createpost'
- **Method:** 'POST'
- **Description:** 'Create a new post by sending a POST request with the post title and details. Requires authentication using a valid token.'
- **JSON Payload:** 
{
  "title": "[Post Title]",
  "details": "[Post Description]"
}

## Getting a Post
- **Endpoint:** '/getpost'
- **Method:** 'GET'
- **Description:** 'Retrieve posts associated with the authenticated user. Requires authentication using a valid token.'
- **JSON Payload is not required here**


# Authentication
- The server uses JWTs for authentication.
- Token expiration time is set to 1 hour (can be changed).

# Secuirty Measures
- Passwords are hashed using bcrypt to enhance security.
- SQL injection prevention is implemented using parameterized queries.
