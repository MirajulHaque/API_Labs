# Broken User Authentication 
# Lab 2_3: Session Management

from flask import Flask, request, jsonify, session
import base64, random, secrets


app = Flask(__name__)

key = "infoSecBD"
secure_key = secrets.token_hex(32)


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
 
vul_session = {}

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
        token_text= username + key + random_characters
        encoded_token = str(base64.b64encode(token_text.encode()))
        session_token = encoded_token[2:-1]
        vul_session.update({session_token:username})
        response = {'message': 'Login successful', 'Set-Cookie': session_token}
        return jsonify(response)
    else:
        # Incorrect password 
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/v1/perform_sensitive_action', methods=['POST'])
def perform_sensitive_action():    
    cookie_session = str(request.cookies.get('session'))
    if cookie_session not in vul_session:
        return jsonify({'error': 'Unauthorized access, Please log in'}), 401
    else:        
        username = vul_session.get(cookie_session)
        result = sensitive_business_action(username)
        return jsonify({'message': result})


# Secure State api/v2

secure_session = {}

# Random Character Generator
characters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*"
random_characters = ''.join(random.choice(characters) for _ in range(13))

@app.route('/api/v2/login', methods=['POST'])
def secure_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = next((item for item in users_db if item["username"] == username), None)
    

    if user and user['password'] == password:
        # Successful login
        token_text= username + secure_key + random_characters
        encoded_token = str(base64.b64encode(token_text.encode()))
        session_token = encoded_token[2:-1]
        secure_session.update({session_token:username})
        response = {'message': 'Login successful', 'Set-Cookie': session_token}
        return jsonify(response)
    else:
        # Incorrect password 
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/v2/perform_sensitive_action', methods=['POST'])
def securely_perform_sensitive_action():
    cookie_session = str(request.cookies.get('session'))
    if cookie_session not in secure_session:
        return jsonify({'error': 'Unauthorized access, Please log in'}), 401
    else:        
        username = secure_session.get(cookie_session)
        result = sensitive_business_action(username)
        return jsonify({'message': result})

    

if __name__ == '__main__':
    app.run(debug=True)
