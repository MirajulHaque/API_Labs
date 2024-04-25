import os
import secrets
import requests
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)

# Updated user list
users_db = [
    {"id": 0, "name": "Administrator", "email": "admin@gmail.com", "username": "admin", "password": "admin", "Balance": 9999, "role": "admin", "phone": "+1 (555) 123-4567"},
    {"id": 1, "name": "Demo User", "email": "user@gmail.com", "username": "user", "password": "pass", "Balance": 1100, "role": "user", "phone": "+49 176 12345678"},
    {"id": 2, "name": "Md Mirajul Haque Miraj", "email": "miraj@gmail.com", "username": "MirajulHaque", "password": "miraj541", "Balance": 1100, "role": "admin", "phone": "+44 7700 900077"},
    {"id": 3, "name": "Md Rupok", "email": "rupok@gmail.com", "username": "rupok967", "password": "rupok967", "Balance": 2300, "role": "user", "phone": "+81 90-1234-5678"},
    {"id": 4, "name": "Kamal Hossain", "email": "kamal@gmail.com", "username": "kamal", "password": "kamal123", "Balance": 6100, "role": "user", "phone": "+61 412 345 678"},
    {"id": 5, "name": "Md Jakir", "email": "jakir@gmail.com", "username": "jakir342", "password": "jakir420", "Balance": 5100, "role": "user", "phone": "+33 6 12 34 56 78"},
    {"id": 6, "name": "Md Minhaz", "email": "minhaz@gmail.com", "username": "minhaz", "password": "minhaz541", "Balance": 1954, "role": "user", "phone": "+61 423 456 789"},
    {"id": 7, "name": "Foysal Hossain", "email": "foysal@gmail.com", "username": "foysal99", "password": "foysal547", "Balance": 9999, "role": "user", "phone": "+91 98765 43210"},
    {"id": 8, "name": "Farhan Masuk", "email": "farhan@gmail.com", "username": "farhan", "password": "farhan123", "Balance": 5478, "role": "user", "phone": "+1 (555) 987-6543"},
    {"id": 9, "name": "Khalid Ahmed", "email": "khalid@gmail.com", "username": "khalid", "password": "khalid123", "Balance": 1547, "role": "user", "phone": "+86 132 1234 5678"},
    {"id": 10, "name": "Nasum Ahmed", "email": "nasum@gmail.com", "username": "nasum", "password": "nasum123", "Balance": 9874, "role": "user", "phone": "+91 98765 43210"},
    {"id": 11, "name": "Abdullah", "email": "abdullah@gmail.com", "username": "abdullah", "password": "abdullah123", "Balance": 6487, "role": "user", "phone": "+44 7700 123456"},
    {"id": 12, "name": "Mohammad", "email": "mohammad@gmail.com", "username": "mohammad", "password": "mohammad", "Balance": 3165, "role": "user", "phone": "+61 478 965 123"},
    {"id": 13, "name": "AL Mamun", "email": "mamun@gmail.com", "username": "mamun", "password": "mamun123", "Balance": 8100, "role": "user", "phone": "+1 (555) 321-9876"},
]


# API B URL [External API that using for storing data securely] (for demonstration)
API_B_URL = "http://localhost:5002" 

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((user for user in users_db if user['username'] == username and user['password'] == password), None)
    if user:
        # Create JWT token
        access_token = create_access_token(identity=user['username'])
        # Redirect to profile
        resp = make_response(redirect(url_for('profile')))
        resp.headers['X-Access-Token'] = access_token
        return resp
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Profile endpoint
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user_info = next((user for user in users_db if user['username'] == current_user), None)
    return jsonify({"message": "Your Profile", "user_info": user_info}), 200

# Endpoint to interact with API B for storing patient information [Insecure]
@app.route('/api/v1/record', methods=['POST'])
@jwt_required()
def store_patient_insecure():
    data = request.get_json()
    access_token = request.headers.get('X-Access-Token')

    response = requests.post(f"{API_B_URL}/api/v1/user/record", json=data, headers={'X-Access-Token': access_token})
    
    if response.status_code == 200:
        return jsonify({"message": response.json()}), 200
        #return jsonify({"message": "Patient information stored successfully"}), 200
    else:
        return jsonify({"error": "Failed to store patient information"}), response.status_code


# Endpoint to interact with API B for storing patient information [Secure]
@app.route('/api/v2/record', methods=['POST'])
@jwt_required()
def store_patient_info():
    data = request.get_json()
    access_token = request.headers.get('X-Access-Token')

    response = requests.post(f"{API_B_URL}/api/v2/user/record", json=data, headers={'X-Access-Token': access_token})
    
    if response.status_code == 200:
        return jsonify({"message": response.json()}), 200
        #return jsonify({"message": "Patient information stored successfully"}), 200
    else:
        return jsonify({"error": "Failed to store patient information"}), response.status_code

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
