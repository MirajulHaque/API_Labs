import os
import secrets
from flask import Flask, request, jsonify, redirect, url_for, make_response, send_from_directory
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)
jwt = JWTManager(app)

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

# Create directories for uploads if they don't exist
UPLOAD_FOLDER_V1 = 'uploads_v1'
UPLOAD_FOLDER_V2 = 'uploads_v2'

if not os.path.exists(UPLOAD_FOLDER_V1):
    os.makedirs(UPLOAD_FOLDER_V1)

if not os.path.exists(UPLOAD_FOLDER_V2):
    os.makedirs(UPLOAD_FOLDER_V2)

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = next((user for user in users_db if user['username'] == username and user['password'] == password), None)
    if user:
        access_token = create_access_token(identity=username)
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
    return jsonify(user_info), 200

# Vulnerable file upload endpoint
@app.route('/api/v1/upload', methods=['POST'])
@jwt_required()
def upload_v1():
    file = request.files['file']
    filename = secure_filename(file.filename)  # Correct variable name
    file.save(os.path.join(UPLOAD_FOLDER_V1, filename))
    return jsonify({"message": "File uploaded successfully"}), 200


# Secure file upload endpoint
@app.route('/api/v2/upload', methods=['POST'])
@jwt_required()
def upload_v2():
    file = request.files['file']
    
    # Check file type
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({"error": "Unsupported file type"}), 400

    # Check file size
    max_file_size = 10 * 1024 * 1024  # 10 MB
    if len(file.read()) > max_file_size:
        return jsonify({"error": "File size exceeds maximum limit (10MB)"}), 400
    file.seek(0)  # Reset file cursor position

    filename = secure_filename(file.filename)
    # Restrict file upload to a specific directory
    upload_path = os.path.join(UPLOAD_FOLDER_V2, 'secure') 
    if not os.path.exists(upload_path):
        os.makedirs(upload_path)
    file.save(os.path.join(upload_path, filename))

    return jsonify({"message": "File uploaded securely"}), 200


# Endpoint to access uploaded files from v1
@app.route('/api/v1/files/<filename>', methods=['GET'])
@jwt_required()
def get_file_v1(filename):
    return send_from_directory(UPLOAD_FOLDER_V1, filename)

# Endpoint to access uploaded files from v2
@app.route('/api/v2/files/<filename>', methods=['GET'])
@jwt_required()
def get_file_v2(filename):
    return send_from_directory(UPLOAD_FOLDER_V2, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
