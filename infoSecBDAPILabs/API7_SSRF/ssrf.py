import secrets
import requests
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)

# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return(jsonify({'Status': 'UP'}))

# USER LIST
users_db = [
    {"id": 0, "name": "Administrator", "email": "admin@gmail.com", "username": "admin", "password": "admin", "Balance": 9999, "role": "admin"},
    {"id": 1, "name": "Demo User", "email": "user@gmail.com", "username": "user", "password": "pass", "Balance": 1100, "role": "user"},
    {"id": 2, "name": "Md Mirajul Haque Miraj", "email": "miraj@gmail.com", "username": "MirajulHaque", "password": "miraj541", "Balance": 1100, "role": "admin"},
    {"id": 3, "name": "Md Rupok", "email": "rupok@gmail.com", "username": "rupok967", "password": "rupok967", "Balance": 2300, "role": "user"},
    {"id": 4, "name": "Kamal Hossain", "email": "kamal@gmail.com", "username": "kamal", "password": "kamal123", "Balance": 6100, "role": "user"},
    {"id": 5, "name": "Md Jakir", "email": "jakir@gmail.com", "username": "jakir342", "password": "jakir420", "Balance": 5100, "role": "user"},
    {"id": 6, "name": "Md Minhaz", "email": "minhaz@gmail.com", "username": "minhaz", "password": "minhaz541", "Balance": 1954, "role": "user"},
    {"id": 7, "name": "Foysal Hossain", "email": "foysal@gmail.com", "username": "foysal99", "password": "foysal547", "Balance": 9999, "role": "user"},
    {"id": 8, "name": "Farhan Masuk", "email": "farhan@gmail.com", "username": "farhan", "password": "farhan123", "Balance": 5478, "role": "user"},
    {"id": 9, "name": "Khalid Ahmed", "email": "khalid@gmail.com", "username": "khalid", "password": "khalid123", "Balance": 1547, "role": "user"},
    {"id": 10, "name": "Nasum Ahmed", "email": "nasum@gmail.com", "username": "nasum", "password": "nasum123", "Balance": 9874, "role": "user"},
    {"id": 11, "name": "Abdullah", "email": "abdullah@gmail.com", "username": "abdullah", "password": "abdullah123", "Balance": 6487, "role": "user"},
    {"id": 12, "name": "Mohammad", "email": "mohammad@gmail.com", "username": "mohammad", "password": "mohammad", "Balance": 3165, "role": "user"},
    {"id": 13, "name": "AL Mamun", "email": "mamun@gmail.com", "username": "mamun", "password": "mamun123", "Balance": 8100, "role": "user"},
    
]

# Iterate through the user list and update each dictionary
for user in users_db:
    # Extract the username from the dictionary
    username = user["username"]
    # Add the website field with the formatted value
    user["website"] = f"www.{username}.com"

# Login 
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = authenticate_user(username, password)

    # Validate credentials
    if user:
        access_token = create_access_token(identity=username)
        resp = make_response(redirect(url_for('view_profile')))
        resp.headers['X-Access-Token'] = access_token
        return resp
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Route for accessing user's own profile
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def view_profile():
    current_user = get_jwt_identity()
    user_profile = next((user for user in users_db if user['username'] == current_user), None)
    return jsonify({"message":"Your Profile"},user_profile), 200


# Vulnerable endpoint for updating user profile with SSRF vulnerability
@app.route('/api/v1/update', methods=['POST'])
@jwt_required()
def update_profile_v1():
    current_user = get_jwt_identity()
    profile_data = request.json

    # Check if the current user is allowed to update their own profile
    if current_user == profile_data.get('username'):
        # Extract the URL from the profile data
        url = profile_data.get('website')
        #url = "www.google.com"
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        # response = requests.get(url)

        # Perform SSRF by making a request to the provided URL
        response = requests.get(url)

        # Return the response content
        return jsonify({"message": "Website url updated", "content": response.text}), 200
    else:
        return jsonify({"error": "Unauthorized"}), 403

# Secure endpoint for updating user profile
@app.route('/api/v2/update', methods=['POST'])
@jwt_required()
def update_profile_v2():
    current_user = get_jwt_identity()
    profile_data = request.json

    # Check if the current user is allowed to update their own profile
    if current_user == profile_data.get('username'):
        # Update user profile with the provided data
        for user in users_db:
            if user['username'] == current_user:
                user.update(profile_data)
                return jsonify({"message": "Profile updated successfully"},{ "data": user}), 200
        return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Unauthorized"}), 403


# Function to authenticate user
def authenticate_user(username, password):
    user = next((u for u in users_db if u['username'] == username and u['password'] == password), None)
    return user

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)



