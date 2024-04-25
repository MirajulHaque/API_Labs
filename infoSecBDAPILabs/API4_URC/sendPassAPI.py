from flask import Flask, request, jsonify
import random

app = Flask(__name__)

@app.route('/sms/send_reset_pass_code', methods=['POST'])
def send_reset_pass_code():
    data = request.get_json()
    phone_number = data.get('phone_number')

    # Check if the phone number is valid
    if not phone_number:
        return jsonify({"success": False, "error": "Phone number is required"}), 400

    # Generate a random reset password code
    reset_code = ''.join(random.choices('0123456789', k=6))

    # Send the reset password code via SMS 
    # Here, we simulate sending the SMS by logging the reset code
    print(f"Reset password code for {phone_number}: {reset_code}")

    return jsonify({"success": True, "message": "Reset password code sent successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5050)
