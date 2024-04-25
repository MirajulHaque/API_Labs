# Broken User Authentication 
# Lab 2_1: Brute Force

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)

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

# Type 1: Brute-Force Attack
@app.route('/api/v1/login', methods=['POST'])
def brute_force_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((item for item in users_db if item["username"] == username), None)

    if user and user['password'] == password:
        # Successful login
        return jsonify({'Message': 'Login successful', 'role': user['role']})
    else:
        # Incorrect password
        return jsonify({'Error': 'Invalid username or password'}), 401
        

# Prevention 1: Brute-Force Protection
failed_login_attempts2 = {}

@app.route('/api/v2/login', methods=['POST'])
def brute_force_prevented_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Prevention 1: Brute-Force Protection
    if username in failed_login_attempts2 and failed_login_attempts2[username] >= 3:
        return jsonify({'Error': 'Your Account has been locked due to too many failed login attempts'}), 403

    user = next((item for item in users_db if item["username"] == username), None)

    if user and user['password'] == password:
        # Successful login
        # Reset failed login attempts
        failed_login_attempts2.clear()
        return jsonify({'Message': 'Login successful', 'role': user['role']})
    else:
        # Incorrect password
        # Brute-Force Protection
        failed_login_attempts2[username] = failed_login_attempts2.get(username, 0) + 1
        return jsonify({'Error': 'Invalid username or password'}), 401

# Type 2: Enhanced Brute-Force Prevention

failed_login_attempts3 = {}
@app.route('/api/v3/login', methods=['POST'])
def enhanced_brute_force_prevention():
    data = request.get_json() 
    username = data.get('username') 
    password = data.get('password')

    # Brute-Force Prevention
    if username in failed_login_attempts3 and failed_login_attempts3[username]['attempts'] >= 3:
        return jsonify({'Error': 'Your Account has been locked due to too many failed login attempts'}), 403 

    user = next((item for item in users_db if item["username"] == username), None)

    if user and user['password'] == password:
        # Successful login
        # Reset failed login attempts 
        failed_login_attempts3.pop(username, None)
        return jsonify({'Message': 'Login successful', 'role': user['role']})
    else:
        # Incorrect password
        # Brute-Force Prevention
        if username in failed_login_attempts3:
            failed_login_attempts3[username]['attempts'] += 1
        else:
            failed_login_attempts3[username] = {'attempts': 1, 'last_attempt_time': time.time()}
        return jsonify({'Error': 'Invalid username or password'}), 401


if __name__ == '__main__':
    app.run(debug=True)
