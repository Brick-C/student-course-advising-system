from flask import jsonify, Response


# General error responses
def missing_fields(fields):
    return jsonify({"message": f"{', '.join(fields)} are required."}), 400


def invalid_value(field):
    return jsonify({"message": f"Invalid value for {field}."}), 400


def student_not_exist():
    return jsonify({"message": "Student does not exist."}), 404


def not_eligible(message):
    return jsonify(message), 401


def account_not_activated():
    return jsonify({"message": "Account is not activated."}), 401


def account_already_activated():
    return jsonify({"message": "Account is already activated."}), 401


def invalid_password():
    return jsonify({"message": "Invalid student_id or password."}), 401


def same_password():
    return jsonify({"message": "choose a different password."}), 401


def password_too_short():
    return (
        jsonify({"message": "Password must be greater than or equal to 8 characters."}),
        401,
    )


def invalid_otp():
    return jsonify({"message": "Invalid OTP."}), 401


def error_creating_account(student_id):
    return jsonify({"message": f"Error creating account: {student_id}"}), 500


def error_updating_password(student_id):
    return jsonify({"message": f"Error updating password: {student_id}"}), 500


def error_generating_otp(student_id):
    return jsonify({"message": f"Error generating OTP: {student_id}"}), 500


def error_sending_otp(student_id):
    return jsonify({"message": f"Error sending OTP: {student_id}"}), 500


# Success responses
def login_success(access_token):
     response_data = {
        "message":"Login successful", 
        "access_token" :" access_token"}
     return jsonify(response_data), 200


def logout_success():
    return jsonify({"message": "Logout successful."}), 200


def account_activated():
    return jsonify({"message": "Account activated successfully."}), 200


def password_updated_successfully():
    return jsonify({"message": "Password updated successfully."}), 200


def otp_sent():
    return jsonify({"message": "OTP sent successfully."}), 200


def authentication_failed():
    return (
        jsonify(
            {"message": "Authentication credentials were not provided or are invalid."}
        ),
        401,
    )


def internal_server_error():
    return jsonify({"message": "Internal Server Error"}), 500


def account_locked(lockout_until):
    return jsonify({
        "message": f"Account is locked. Try again after {lockout_until}."
    }), 403
