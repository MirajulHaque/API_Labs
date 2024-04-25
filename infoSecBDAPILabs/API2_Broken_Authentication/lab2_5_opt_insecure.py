# Broken User Authentication 
# Lab 2_5: OTP (2FA)

from flask import Flask, jsonify, request, session
import pyotp, secrets, base64

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'infosecbd'

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

# Function to retrieve user by username
def get_user_by_username(username):
    return next((item for item in users_db if item["username"] == username), None)

# Sensitive business Action
def sensitive_business_action(username):
    user = next((item for item in users_db if item["username"] == username), None)
    
    if user and user['role'] == 'admin':
        return "Admin-specific action performed"
    else:
        return "User-specific action performed"


# Vulnerable login route with OTP verification
@app.route('/api/v1/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')    

    user = next((item for item in users_db if item["username"] == username and item["password"] == password), None)

    if user:
        # Successful password authentication

        # Generate and store OTP
        otp_secret = base64.b32encode(secrets.token_bytes(10)).decode('utf-8')
        user['otp_secret'] = otp_secret

        # Create TOTP object
        totp = pyotp.TOTP(otp_secret, digits=4)       
        generated_otp = totp.now()
        
        # Store the generated OTP in session (encrypted)
        session['generated_otp'] = totp.now()
        session['username'] = username

        return jsonify({'message': 'Login successful. OTP has been sent to your email. Login on /email '})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

# Route for performing sensitive action with OTP
@app.route('/api/v1/perform_sensitive_action', methods=['POST'])
def perform_sensitive_action():
    # Retrieve user and OTP secret from session
    username = session.get('username')
    user = get_user_by_username(username)
    otp_secret = user.get('otp_secret')

    if not otp_secret:
        return jsonify({'error': 'User not authenticated'}), 401

    # Create TOTP object
    totp = pyotp.TOTP(otp_secret)

    # Retrieve the generated OTP from session
    generated_otp = session.get('generated_otp')
    print(f"Generated in sensitive {generated_otp}")

    # Check if the provided OTP matches the generated OTP
    data = request.get_json()
    provided_otp = data.get('otp')
    print(f"Provided{provided_otp}")

    if generated_otp == provided_otp:
        # Perform sensitive action
        result = sensitive_business_action(username)
        return jsonify({'message': result})
    else:
        return jsonify({'error': 'Invalid OTP'}), 401

# Email Log in
@app.route('/email', methods=['GET'])
def email():
    return(jsonify({'Login': 'Login with your email and password to see the emails'}), 200)

@app.route('/email', methods=['POST'])
def emails():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = session.get('username')    
    generated_otp = session.get('generated_otp')

    user = next((item for item in users_db if item["username"] == username and item["email"] == email and item["password"] == password), None)

    if user:
        return jsonify({"Sender":"miraj@infosecbd.org"},{'Your OTP':generated_otp})
    else:
        return jsonify({'error': 'Invalid email or password'}), 401
       


if __name__ == '__main__':
    app.run(debug=True)
