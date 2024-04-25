import secrets
from flask import Flask, jsonify, request, redirect, url_for, make_response
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

# Vulnerable State: API v1 Endpoints
@app.route('/api/v1/profile', methods=['GET'])
@jwt_required()
def get_user_data_v1():
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)
    return jsonify({"message": "Your Profile"},{"data": user_data}), 200


@app.route('/api/v1/admin_data', methods=['GET'])
@jwt_required()
def get_admin_data_v1():
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)

    # Check if the user is an admin before providing admin data
    if user_data:
        return jsonify({'Welcome to Admin Panel':'Here is your User List'},{"data": users_db}), 200
    else:
        return jsonify({"error": "Unauthorized"}), 403

# Vulnerable State: Deleting or Updating User in API v1
@app.route('/api/v1/user/<int:user_id>', methods=['DELETE', 'PUT'])
@jwt_required()
def delete_or_update_user_v1(user_id):
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)

    # Only admins can delete or update users in the secure state
    if user_data:
        user_index = next((index for index, u in enumerate(users_db) if u["id"] == user_id), None)
        if user_index is not None:
            if request.method == 'DELETE':
                del users_db[user_index]
                return jsonify({"message": f"User with ID {user_id} deleted successfully"}), 200
            elif request.method == 'PUT':
                # Update user data based on the request
                data = request.get_json()
                new_user_data = {
                    "id": user_id,
                    "name": data.get("name", users_db[user_index]["name"]),
                    "email": data.get("email", users_db[user_index]["email"]),
                    "username": data.get("username", users_db[user_index]["username"]),
                    "password": data.get("password", users_db[user_index]["password"]),
                    "Balance": data.get("Balance", users_db[user_index]["Balance"]),
                    "role": data.get("role", users_db[user_index]["role"])
                }
                users_db[user_index] = new_user_data
                return jsonify({"message": f"User with ID {user_id} updated successfully"}), 200
        else:
            return jsonify({"error": f"User with ID {user_id} not found"}), 404
    else:
        return jsonify({"error": "Unauthorized"}), 403


# Secure State: API v2 Endpoints

@app.route('/api/v2/admin_data', methods=['GET'])
@jwt_required()
def get_admin_data_v2():
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)

    # Check if the user is an admin before providing admin data
    if user_data and user_data.get("role") == "admin":
        return jsonify({'Welcome to Admin Panel':'Here is your User List'},{"data": users_db}), 200
    else:
        return jsonify({"error": "Unauthorized"}), 403

# Secure State: Deleting User in API v1
@app.route('/api/v2/user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_v2(user_id):
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)

    # Only admins and the profile owner can delete users in the secure state
    if (user_data and user_data.get("role") == "admin") or (user_data and user_data.get("id") == user_id):
        user_index = next((index for index, u in enumerate(users_db) if u["id"] == user_id), None)
        if user_index is not None:
            del users_db[user_index]
            return jsonify({"message": f"User with ID {user_id} deleted successfully"}), 200
        else:
            return jsonify({"error": f"User with ID {user_id} not found"}), 404
    else:
        return jsonify({"error": "Unauthorized"}), 403

# Secure State: Updating User Data in API v1
@app.route('/api/v2/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user_v2(user_id):
    current_user = get_jwt_identity()
    user_data = next((user for user in users_db if user['username'] == current_user), None)

    # Only admins and the profile owner can update users in the secure state
    if (user_data and user_data.get("role") == "admin") or (user_data and user_data.get("id") == user_id):
        user_index = next((index for index, u in enumerate(users_db) if u["id"] == user_id), None)
        if user_index is not None:
            data = request.get_json()
            users_db[user_index].update(data)
            return jsonify({"message": f"User with ID {user_id} updated successfully"}), 200
        else:
            return jsonify({"error": f"User with ID {user_id} not found"}), 404
    else:
        return jsonify({"error": "Unauthorized"}), 403


# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = secure_authenticate_user(username, password)

    # Validate credentials
    if user:
        access_token = create_access_token(identity=username)
        resp = make_response(redirect(url_for('get_user_data_v1')))
        resp.headers['X-Access-Token'] = access_token
        #return jsonify({"access_token": access_token}), 200       
        #return redirect(url_for('get_user_data_v1'))
        return resp
    else:
        return jsonify({"error": "Invalid credentials"}), 401


# User authentication
def secure_authenticate_user(username, password):
    user = next((u for u in users_db if u['username'] == username and u['password'] == password), None)
    return user


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
