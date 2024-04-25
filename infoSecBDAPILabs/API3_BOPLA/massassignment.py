from flask import Flask, jsonify, request, session, make_response, redirect, url_for
import pyotp, secrets, base64


app = Flask(__name__)

# Secret key for session management
app.secret_key = 'infosecbd'



# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return(jsonify({'Status': 'UP', 'Lab':'Mass Assignment(Direct)'}))

# USER LIST
users_db = [
    {"id": 0, "name": "Root User", "email": "root@gmail.com", "username": "root", "password": "r7EyqZdUTN07e6vuisjv3", "Balance": 9999, "role": "admin"},
    {"id": 1, "name": "Demo User", "email": "user@gmail.com", "username": "user", "password": "o3HjoTVFVN6U1B9PhELCu", "Balance": 1100, "role": "user"},
    {"id": 2, "name": "Md Mirajul Haque Miraj", "email": "miraj@gmail.com", "username": "MirajulHaque", "password": "miraj5415487!", "Balance": 1100, "role": "admin"},
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

# Function to retrieve user by username
def get_user_by_username(username):
    return next((item for item in users_db if item["username"] == username), None)

# Sensitive business Action
def sensitive_business_action(username):
    user = next((item for item in users_db if item["username"] == username), None)
    
    if user and user['role'] == 'admin':
        return "Admin-specific action performed."
    else:
        return "User-specific action performed"

# Route for user registration
@app.route('/api/register', methods=['POST'])
def register_user():
    
    
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
    
    resp = make_response(redirect(url_for('login')))
    resp.headers['Success'] = 'User registered successfully. Please log in.'
    
    #return redirect(url_for('login', message='User registered successfully. Please log in.'))
    return resp
    #return jsonify({'message': 'User registered successfully. Please log in.'}), 201


# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((item for item in users_db if item["username"] == username and item["password"] == password), None)

    if user:
        # Successful login
        session['username'] = user['username']
        return jsonify({'message': 'Login successful. Now you can perform actions. Your Profile'},{"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200
    else:
        return jsonify({'error': 'Invalid username or password! Register first to login!'}), 401

# Vulnerable: Mass Assignment (Direct)
@app.route('/api/v1/update', methods=['PUT'])
def update_profile():
    data = request.get_json()
    username = data.get('username')
    new_data = request.json
    
    # Check if the user is authenticated
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('username')
    user = next((item for item in users_db if item["username"] == username), None)
    
    if user and user['username'] == username:
        
        user.update(new_data)
        return jsonify({'message': 'Profile updated successfully'},{"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200, {'Content-Type': 'application/json'}
    else:
        return jsonify({'error': 'User not found'}), 404



# Route for performing sensitive action 
@app.route('/api/action', methods=['POST'])
def perform_sensitive_action():
    # Retrieve user and OTP secret from session
    username = session.get('username')
    user = get_user_by_username(username)
    

    if user:
        # Perform sensitive action
        result = sensitive_business_action(username)
        return jsonify({'message': result})
    else:
        return jsonify({'message': 'Unauthorized! Please Login to perform actions!'}), 401


# Fitering Which fields are changebale, we are only allowing email, name and password are chageable 
ALLOWED_FIELDS = ['email', 'name', 'password']

@app.route('/api/v2/update', methods=['PUT'])
def secure_update_profile():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    name = data.get('name')
    uid = data.get('id')
    Balance = data.get('Balance')
    role = data.get('role')    
    new_data = {key: value for key, value in request.json.items() if key in ALLOWED_FIELDS}

    # Check if the user is authenticated
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session.get('username')
    user = next((item for item in users_db if item["username"] == username), None)

    #rdata = jsonify({'message': 'Your Profile'},{"id":user['id'],"username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance'], "password":user['password']}), 200, {'Content-Type': 'application/json'}
    
    
    if user:        
        if user_id or Balance or role:    
            return jsonify({'Error': 'You can only update email, name, and password'}), 403
        elif password != user["password"] or email != user["email"] or name != user["name"]:
            user.update(new_data)
            return jsonify({'message': 'Profile updated successfully'},{"id":user['id'],"username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200, {'Content-Type': 'application/json'}
        else:
            return jsonify({'message': 'Your Profile'},{"id":user['id'],"username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance']}), 200, {'Content-Type': 'application/json'}
    else:
        return jsonify({'error': 'User not found'}), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
