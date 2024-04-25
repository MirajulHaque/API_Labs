# Broken User Authentication 
# Lab 2_2: Secure Cookie

from flask import Flask, request, jsonify, session
import base64, random
from flask_bcrypt import Bcrypt
from secrets import token_hex 

app = Flask(__name__)
bcrypt = Bcrypt(app)

key = "infoSecBD"


# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return(jsonify({'Status': 'UP'}))

# USER LIST
users_db = [
    {"id": 0, "name": "Root User", "email": "root@gmail.com", "username": "root", "password": "r00t", "Balance": 9999, "role": "admin"},
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

        

# Insecure State api/v1
 
vul_session = ["",1]

# Random Character Generator
characters = "abcdefghijklmnopqrstuvwxyz"
random_characters = ''.join(random.choice(characters) for _ in range(3))


# Sensitive business Action
def sensitive_business_action(username):
    user = next((item for item in users_db if item["username"] == username), None)
    
    if user and user['role'] == 'admin':
        return "Admin-specific action performed"
    else:
        return "User-specific action performed"


@app.route('/api/v1/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((item for item in users_db if item["username"] == username), None)
    

    if user and user['password'] == password:
        # Successful login
        vul_session.append(username)
        token_text= username + key + random_characters
        encoded_token = str(base64.b64encode(token_text.encode()))
        session_token = encoded_token[2:-1]
        response = {'message': 'Login successful', 'Set-Cookie': session_token}
        return jsonify(response)
    else:
        # Incorrect password 
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/v1/perform_sensitive_action', methods=['POST'])
def perform_sensitive_action():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username not in vul_session:
        return jsonify({'error': 'Unauthorized access, Please log in'}), 401
    else:        
        result = sensitive_business_action(username)
        return jsonify({'message': result})


# Secure State api/v2

## Update the users_db with password hashes
for user in users_db:
    if 'password' in user:
        user['hashed_password'] = bcrypt.generate_password_hash(user['password']).decode('utf-8')

# Secret key for session management
app.secret_key = "miraj@infoSecBD.org"

# secure_token
def generate_session_token():
    return token_hex(16)

@app.route('/api/v2/login', methods=['POST'])
def secure_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((item for item in users_db if item["username"] == username), None)

    if user and bcrypt.check_password_hash(user['hashed_password'], password):
        # Successful login Status
        session['token'] = generate_session_token()
        session['username'] = username
        return jsonify({'message': 'Login successful'})
    else:
        # Incorrect password or username Handling 
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/v2/perform_sensitive_action', methods=['POST'])
def securely_perform_sensitive_action():
    if 'token' not in session or 'username' not in session:
        return jsonify({'error': 'Unauthorized access, Please log in'}), 401
    else:
        result = sensitive_business_action(session['username'])
        return jsonify({'message': result})

    

if __name__ == '__main__':
    app.run(debug=True)
