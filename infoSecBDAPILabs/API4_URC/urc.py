import secrets
import requests
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)
limiter = Limiter(app=app, key_func=get_remote_address)
#limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["3 per minute"])

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




# API costs
SMS_COST = 1

requests_db1 = []
requests_db2 = []

# Function to calculate total cost for a user
def calculate_total_cost(username, version):
    total_cost = 0
    v = version
    if v == "v1":
        for request_data in requests_db1:
            if request_data["username"] == username:
                total_cost += request_data["cost"]
        return total_cost
    else:
        for request_data in requests_db2:
            if request_data["username"] == username:
                total_cost += request_data["cost"]
        return total_cost

# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return jsonify({'Status': 'UP'})

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
        # Redirect to dashboard
        resp = make_response(redirect(url_for('dashboard')))
        resp.headers['X-Access-Token'] = access_token
        return resp
        
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Dashboard route
@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    user_role = next((user['role'] for user in users_db if user['username'] == current_user), None)
    if user_role == 'admin':
        # Calculate total cost for admin
        total_costv1 = calculate_total_cost(current_user,"v1")
        total_costv2 = calculate_total_cost(current_user,"v2")
        return jsonify({"Total Cost for v1": total_costv1, "Total Cost for v2": total_costv2}), 200
    else:
        # For regular users, redirect to profile
        return redirect(url_for('profile'))

# Profile route
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user_info = next((user for user in users_db if user['username'] == current_user), None)
    return jsonify(user_info), 200

# Vulnerable endpoint for initiating forgot password flow
@app.route('/api/v1/forgot_password', methods=['POST'])
def initiate_forgot_password_vulnerable():
    username = request.json.get('username')
    user = next((user for user in users_db if user['username'] == username), None) 
    if not user:
        return jsonify({"error":"username is required"}), 400
    #user_number = request.json.get('user_number')
    #if not user_number:
    #    return jsonify({"error": "User number is required"}), 400

    user_number = user.get('phone')
    # Send SMS code without authentication
    response = requests.post("http://127.0.0.1:5050/sms/send_reset_pass_code", json={"phone_number": user_number})
    
    # Log the cost
    requests_db1.append({"username": "admin", "cost": SMS_COST})
    
    return jsonify({"message": "SMS code sent successfully to your Phone Number!"}), 200

# Secure endpoint for initiating forgot password flow with rate limiting
@app.route('/api/v2/forgot_password', methods=['POST'])
@limiter.limit("3/minute")
def initiate_forgot_password_secure():
    username = request.json.get('username')
    user = next((user for user in users_db if user['username'] == username), None) 
    if not user:
        return jsonify({"error":"username is required"}), 400
    #user_number = request.json.get('user_number')
    #if not user_number:
    #    return jsonify({"error": "User number is required"}), 400

    user_number = user.get('phone')
    # Send SMS code without authentication
    response = requests.post("http://127.0.0.1:5050/sms/send_reset_pass_code", json={"phone_number": user_number})
    
    # Log the cost
    requests_db2.append({"username": "admin", "cost": SMS_COST})
    
    return jsonify({"message": "SMS code sent successfully to your Phone Number!"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
