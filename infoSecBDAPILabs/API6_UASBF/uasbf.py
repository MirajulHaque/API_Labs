import secrets
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)
limiter = Limiter(app=app, key_func=get_remote_address)

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

# Returning Status UP Signal
@app.route('/', methods=['GET'])
def status_up():
    return jsonify({'Status': 'UP'})

v1_stock = 10
v2_stock = 12

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
        
        return jsonify({"message":"Welcome to Admin Dashboard"},{"Current Stock for v1": v1_stock, "Current Stock for v2": v2_stock}), 200
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

# Vulnerable endpoint for purchasing a product
@app.route('/api/v1/purchase', methods=['POST'])
@jwt_required()
def purchase_product_v1():
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity')
    if not product_id or not quantity:
        return jsonify({"error":"product_id or quantity is not defined"})
    if not product_id.isdigit() or not quantity.isdigit():
        return jsonify({"error":"product_id or quantity must be Integer Number"})

    global v1_stock
    quantity = int(quantity)
    v1_stock = v1_stock - quantity
    if v1_stock >= 0:
        return jsonify({"message": f"{quantity} Product(s) purchased successfully"}), 200
    else:
        v1_stock = 0
        return jsonify({"message": "Out of Stock"}), 200
    #return jsonify({"message": "Product purchased successfully"}), 200

# Secure endpoint for purchasing a product with rate limiting
# Dictionary to keep track of total quantity purchased by each user
user_purchase_counts = {}

@app.route('/api/v2/purchase', methods=['POST'])
@jwt_required()
def purchase_product_v2():
    current_user = get_jwt_identity()
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity')

    if not product_id or not quantity:
        return jsonify({"error":"product_id or quantity is not defined"})
    if not product_id.isdigit() or not quantity.isdigit():
        return jsonify({"error":"product_id or quantity must be Integer Number"})

    quantity = int(quantity)

    # Check if the user has already purchased products
    if current_user in user_purchase_counts:
        # Get the total quantity purchased by the user
        total_quantity_purchased = user_purchase_counts[current_user]
    else:
        total_quantity_purchased = 0

    # Calculate the new total quantity after the current purchase
    new_total_quantity = total_quantity_purchased + quantity

    # Check if the new total quantity exceeds the limit of 5
    if new_total_quantity > 5:
        return jsonify({"error": "You can only buy up to 5 products in this OFFER!"}), 400

    # Update the total quantity purchased by the user
    user_purchase_counts[current_user] = new_total_quantity

    # Proceed with the purchase logic
    global v2_stock
    v2_stock = v2_stock - quantity

    if v2_stock >= 0:
        return jsonify({"message": f"{quantity} Product(s) purchased successfully"}), 200
    else:
        v2_stock = 0
        return jsonify({"message": "Out of Stock"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
