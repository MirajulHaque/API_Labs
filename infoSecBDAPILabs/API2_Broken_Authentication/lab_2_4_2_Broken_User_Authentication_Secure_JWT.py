# Broken User Authentication 
# Lab 2.4(2): Secure JWT 

import secrets
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)

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
    {"id": 6, "name": "Md Minhaz", "email": "minhaz@gmail.com", "username": "minhaz", "password": "minhaz541", "Balance": 1954, "role": "user"},
    {"id": 7, "name": "Foysal Hossain", "email": "foysal@gmail.com", "username": "foysal99", "password": "foysal547", "Balance": 9999, "role": "user"},
    {"id": 8, "name": "Farhan Masuk", "email": "farhan@gmail.com", "username": "farhan", "password": "farhan123", "Balance": 5478, "role": "user"},
    {"id": 9, "name": "Khalid Ahmed", "email": "khalid@gmail.com", "username": "khalid", "password": "khalid123", "Balance": 1547, "role": "user"},
    {"id": 10, "name": "Nasum Ahmed", "email": "nasum@gmail.com", "username": "nasum", "password": "nasum123", "Balance": 9874, "role": "user"},
    {"id": 11, "name": "Abdullah", "email": "abdullah@gmail.com", "username": "abdullah", "password": "abdullah123", "Balance": 6487, "role": "user"},
    {"id": 12, "name": "Mohammad", "email": "mohammad@gmail.com", "username": "mohammad", "password": "mohammad", "Balance": 3165, "role": "user"},
    {"id": 13, "name": "AL Mamun", "email": "mamun@gmail.com", "username": "mamun", "password": "mamun123", "Balance": 8100, "role": "user"},
    
]


# Route for Secure User login
@app.route('/api/v2/login', methods=['POST'])
def secure_login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = secure_authenticate_user(username, password)

    if user:
        # Create JWT token with user's identity
        token = create_access_token(identity=username)
        return jsonify({'message':'Login Success'}, {'token': token}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

# Sensitive action route that requires a valid JWT token
@app.route('/api/v2/info', methods=['GET'])
@jwt_required()
def secure_info():
    # Retrieve the identity from the token
    current_user = get_jwt_identity()

    # Find the user in the database
    user = next((u for u in users_db if u['username'] == current_user), None)

    if user:
        return jsonify({'message': 'Your Profile'}, {"id":user['id'], "username":user['username'], "name":user['name'], "email":user['email'], "role":user['role'], "Balance":user['Balance'], "password":user['password']}), 200
    else:
        return jsonify({'Error': 'Unauthorized, Please Log in.'}), 404

# User authentication
def secure_authenticate_user(username, password):
    user = next((u for u in users_db if u['username'] == username and u['password'] == password), None)
    return user



if __name__ == '__main__':
    app.run(debug=True)
