from flask import Flask, jsonify, request, session
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import secrets 
from flasgger import Swagger

key = secrets.token_urlsafe(32)

app = Flask(__name__)
Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "InfoSecBD API Lab 1",
        "description": "Broken Object Level Authorization Lab 1: bola",
        "version": "1.0.0",
        "contact": {
            "url": "https://github.com/MirajulHaque",
        },        
    },
    "host": "",
    "basePath": "/",
})
app.config['JWT_SECRET_KEY'] = key  
jwt = JWTManager(app)
app.secret_key = 'miraj@infosecbd.org'


# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return(jsonify({'Status': 'UP', 'Lab':'01'}))



## USER LIST
users_db = [
    {"id": 0, "name": "Root User", "email": "root@gmail.com", "username": "root", "password": "sjrwoierjoiwejroiwer68498", "Balance": 9999, "role": "admin"},
    {"id": 1, "name": "Demo User", "email": "user@gmail.com", "username": "user", "password": "pass", "Balance": 1100, "role": "user"},
    {"id": 2, "name": "Md Mirajul Haque Miraj", "email": "miraj@gmail.com", "username": "MirajulHaque", "password": "miraj541", "Balance": 1100, "role": "admin"},
    {"id": 3, "name": "Md Rupok", "email": "rupok@gmail.com", "username": "rupok967", "password": "rupok967", "Balance": 2300, "role": "user"},
    {"id": 4, "name": "Kamal Hossain", "email": "kamal@gmail.com", "username": "kamal", "password": "kamal123", "Balance": 6100, "role": "user"},
    {"id": 5, "name": "Md Jakir", "email": "jakir@gmail.com", "username": "jakir342", "password": "jakir420", "Balance": 5100, "role": "user"},
    {"id": 6, "name": "Md Minhaz", "email": "minhaz@gmail.com", "username": "minhaz", "password": "minhaz541", "Balance": 1100, "role": "user"},
    {"id": 7, "name": "Foysal Hossain", "email": "foysal@gmail.com", "username": "foysal99", "password": "foysal547", "Balance": 9999, "role": "user"},
    {"id": 8, "name": "Farhan Masuk", "email": "farhan@gmail.com", "username": "farhan", "password": "farhan123", "Balance": 5478, "role": "user"},
    {"id": 9, "name": "Khalid Ahmed", "email": "khalid@gmail.com", "username": "khalid", "password": "khalid123", "Balance": 1547, "role": "user"},
    {"id": 10, "name": "Nasum Ahmed", "email": "nasum@gmail.com", "username": "nasum", "password": "nasum123", "Balance": 9874, "role": "user"},
    {"id": 11, "name": "Abdullah", "email": "abdullah@gmail.com", "username": "abdullah", "password": "abdullah123", "Balance": 6487, "role": "user"},
    {"id": 12, "name": "Mohammad", "email": "mohammad@gmail.com", "username": "mohammad", "password": "mohammad", "Balance": 3165, "role": "user"},
    {"id": 13, "name": "AL Mamun", "email": "mamun@gmail.com", "username": "mamun", "password": "mamun123", "Balance": 8100, "role": "user"},
    
]

# Authentication route - Creating JWT token

@app.route('/api/v1/login', methods=['POST'])
def login():
    """
    User Login
    ---
    parameters:
      - in: body
        name: user
        required: true
        schema:
          id: UserLogin
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: User's username
            password:
              type: string
              description: User's password
    responses:
      200:
        description: Login successful
        schema:
          id: LoginResponse
          properties:
            message:
              type: string
              description: Success message
            access_token:
              type: string
              description: JWT access token
      401:
        description: Invalid username or password
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
    """
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validating username and password => Access Token
    user = next((item for item in users_db if item["username"] == username and item["password"] == password), None)

    if user:
        access_token = create_access_token(identity=user["id"])
        return jsonify({"message": "Login Success!", "access_token":access_token}), 200
    else:
        return jsonify({"message": "Invalid Username or Password"}), 401


# Secured with using JWT token

@app.route('/api/v1/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """
    Get User by ID (Secured)
    ---
    security:
      - JWT: []
    parameters:
      - in: path
        name: user_id
        required: true
        type: integer
        description: ID of the user
    responses:
      200:
        description: User information
        schema:
          id: UserResponse
          properties:
            message:
              type: string
              description: Success message
            user:
              type: object
              description: User information
              properties:
                id:
                  type: integer
                  description: User ID
                username:
                  type: string
                  description: User's username
                name:
                  type: string
                  description: User's name
                email:
                  type: string
                  description: User's email
                role:
                  type: string
                  description: User's role
                Balance:
                  type: integer
                  description: User's balance
      401:
        description: Unauthorized access
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
      404:
        description: User not found
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
    """
    
    authenticated_user_id = get_jwt_identity()

    if user_id == authenticated_user_id:
        user = next((item for item in users_db if item["id"] == user_id), None)
        if user:
            if user['role'] == "admin":
                return jsonify({'message': 'Welcome to Admin Panel'}, {"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200
            else:
                return jsonify({'message': 'Your Profile'}, {"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200
    
    return jsonify({"message": "Unauthorized Attempt"}), 404


# Route for user registration
@app.route('/api/v2/register', methods=['POST'])
def register_user():
    """
    Register a new user
    ---
    parameters:
      - in: body
        name: user
        required: true
        schema:
          id: User
          required:
            - name
            - username
            - password
            - email
          properties:
            name:
              type: string
              description: User's name
            username:
              type: string
              description: User's username
            password:
              type: string
              description: User's password
            email:
              type: string
              format: email
              description: User's email
    responses:
      201:
        description: User registered successfully
        schema:
          id: RegistrationResponse
          properties:
            message:
              type: string
              description: Registration success message
      400:
        description: Bad Request, missing required fields or username already exists
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
    """
    
    data = request.get_json()

    # Check if all required fields are present
    required_fields = ['name', 'username', 'password', 'email']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'You must provide name, username, password, and email'}), 400

    username = data.get('username')
    
    # Check if the username already exists
    if any(user["username"] == username for user in users_db):
        return jsonify({'error': 'Username already exists'}), 400

    # Create a new user
    new_user = {
        "id": len(users_db),
        "name": data.get('name'),
        "email": data.get('email'),
        "username": username,
        "password": data.get('password'),
        "Balance": 0,  
        "role": "user" 
    }

    # Add the new user to the users_db
    users_db.append(new_user)

    return jsonify({'message': 'User registered successfully. Please log in.'}), 201


@app.route('/api/v2', methods=['GET'])
def path():
    return jsonify({'message':'You are on the way'})

# Insecure Access Point using POST Method
@app.route('/api/v2/login', methods=['POST'])
def logins():
    """
    User Login
    ---
    parameters:
      - in: body
        name: user
        required: true
        schema:
          id: UserLogin
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: User's username
            password:
              type: string
              description: User's password
    responses:
      200:
        description: Login successful
        schema:
          id: LoginResponse
          properties:
            message:
              type: string
              description: Login success message
            Set-Cookie:
              type: string
              description: Session token
      401:
        description: Unauthorized access, invalid username or password
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
    """
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validating username and password => Access Token
    user = next((item for item in users_db if item["username"] == username and item["password"] == password), None)
    if user:
    	session['username'] = user['username']
    	return jsonify(user)
    else:
    	return jsonify({"message": "Invalid Username or Password"}), 401


# Insecure Access Point using GET Method
@app.route('/api/v2/users/', methods=['GET'])
def user():
    """
    Get User Profile
    ---
    parameters:
      - in: query
        name: id
        type: integer
        description: User ID
    responses:
      200:
        description: User profile retrieved successfully
        schema:
          id: UserProfileResponse
          properties:
            message:
              type: string
              description: Success message
            user:
              type: object
              description: User profile information
              properties:
                id:
                  type: integer
                  description: User ID
                username:
                  type: string
                  description: User's username
                name:
                  type: string
                  description: User's name
                email:
                  type: string
                  format: email
                  description: User's email
                role:
                  type: string
                  description: User's role (admin/user)
                Balance:
                  type: integer
                  description: User's balance
      401:
        description: Unauthorized access, user not logged in
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
      404:
        description: User not found
        schema:
          id: ErrorResponse
          properties:
            error:
              type: string
              description: Error message
    """
    
    user_id = request.args.get('id', type=int)
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if user_id is not None:
    	user = next((item for item in users_db if item["id"] == user_id), None)
    	if user['role']=="admin":
    		return jsonify({'message': 'Admin Profile'}, {"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200
    	else:
    		return jsonify({'message': 'User Profile'}, {"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200
    return jsonify({"message": "User not found"}), 404



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
