from flask import Flask, request, jsonify

app = Flask(__name__)

# Python list to store received data
attacker_data = []

# Endpoint to receive data from the vulnerable API and store it
@app.route('/store_data', methods=['POST'])
def store_data():
    data = request.json
    attacker_data.append(data)
    return jsonify({"message": "Data stored in attacker's API"}), 200

# Just For Checking is really data is stored in attacker's side
@app.route('/api/check_data', methods=['GET'])
def check_data():
    return jsonify({'message':'Data from Attacker\'s API'},attacker_data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5003)
