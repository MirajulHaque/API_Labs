import os
import secrets
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)


# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return jsonify({'Status': 'UP'})

# USER LIST 
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

# Reset password tokens database
reset_tokens_db = {}

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Validate credentials
    user = next((user for user in users_db if user['username'] == username and user['password'] == password), None)
    if user:
        # Create JWT token
        access_token = create_access_token(identity=username)
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
    return jsonify({"message":"Your Profile"},user_info), 200

# Vulnerable password reset endpoint
@app.route('/api/v1/reset_password', methods=['POST'])
def reset_password_v1():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    new_password = data.get('new_password')
    
    # Check if all required fields are present
    if not (username and password and new_password):
        if not username:
            return jsonify({"error":"Please enter your username"}), 400
        if not new_password:
            return jsonify({"error":"Please enter your new_password"}), 400
    
    # Check if user exists and credentials match
    user = next((user for user in users_db if user['username'] == username), None)
    if not user:
        return jsonify({"error": "User not found or incorrect credentials"}), 404
    
    # Reset password without checking token
    user['password'] = new_password
    return jsonify({"message": "Password reset successfully"}), 200


# Secure password reset endpoint
@app.route('/api/v2/reset_password', methods=['POST'])
@jwt_required()
def reset_password_v2():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    new_password = data.get('new_password')
    token = data.get('token')

    # Check if all required fields are present
    if not (username and password and new_password and token):
        if not username:
            return jsonify({"error":"Please enter your username"}), 400
        if not password:
            return jsonify({"error":"Please enter your password"}), 400
        if not new_password:
            return jsonify({"error":"Please enter your new_password"}), 400
        if not token:
            return jsonify({"error":"Authorization token is not present"}), 400


    # Verify token
    if token not in reset_tokens_db or reset_tokens_db[token] != username:
        return jsonify({"error": "Invalid or expired token"}), 401

    # Reset password
    user = next((user for user in users_db if user['username'] == username and user['password'] == password), None)
    if user:
        user['password'] = new_password
        # Remove token after successful password reset
        del reset_tokens_db[token]
        return jsonify({"message": "Password reset successfully"}), 200
    else:
        return jsonify({"error": "User not found or incorrect credentials"}), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
