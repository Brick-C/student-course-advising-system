from flask import Blueprint, current_app, request
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import traceback
from app.core.responses import internal_server_error
from app.api.controllers.update import (
    change_password_controller,
    forget_password_controller,
)
from app.core.jwt import jwt_blacklist
from app.api.controllers.auth import (
    login_controller,
    logout_controller,
    activate_controller,
    welcocme_controller,
)
from app.api.controllers.otp import send_otp_controller


api_bp = Blueprint("api", __name__)


limiter = Limiter(key_func=get_remote_address)


@api_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """
    POST /api/login
    - Logs in a student using student_id and password.
    - Request: {"student_id": "...", "password": "..."}
    - Example:
        curl -X POST http://localhost:8000/api/login -H "Content-Type: application/json" -d '{"student_id": "123", "password": "mypassword"}'
    """
    try:
        data = request.get_json()
        if not data:
            # Handle cases where JSON is missing or malformed
            return bad_request("Missing or invalid JSON in request body")#type:ignore
        student_id = data.get("student_id")
        raw_password = data.get("password")
        return login_controller(student_id, raw_password)
    # --- MODIFIED EXCEPTION HANDLING ---
    except Exception as e:
        # Log the actual error to your Flask console
        current_app.logger.error(f"An error occurred in /api/login: {e}")
        current_app.logger.error(traceback.format_exc()) # This provides the full error stack
        return internal_server_error()



@api_bp.route("/logout", methods=["GET"])
@jwt_required()
def logout():
    """
    GET /api/logout
    - Logs out the current student (invalidates JWT).
    - Requires JWT in Authorization header.
    - Example:
        curl -X GET http://localhost:8000/api/logout -H "Authorization: Bearer <access_token>"
    """
    try:
        jti = get_jwt()["jti"]
        return logout_controller(jti, jwt_blacklist)
    except:
        return internal_server_error()


@api_bp.route("/activate", methods=["POST"])
@limiter.limit("3 per minute")
def activate():
    """
    POST /api/activate
    - Activates a student account using student_id, password, and OTP.
    - Request: {"student_id": "...", "password": "...", "otp": "..."}
    - Example:
        curl -X POST http://localhost:8000/api/activate -H "Content-Type: application/json" -d '{"student_id": "123", "password": "newpass", "otp": "123456"}'
    """
    try:
        data = request.get_json()
        student_id = data.get("student_id")
        raw_otp = data.get("otp")
        raw_password = data.get("password")
        return activate_controller(student_id, raw_otp, raw_password)
    except:
        return internal_server_error()


@api_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per minute")
def forgot_password():
    """
    POST /api/forgot-password
    - Resets password using student_id, new password, and OTP.
    - Request: {"student_id": "...", "password": "...", "otp": "..."}
    - Example:
        curl -X POST http://localhost:8000/api/forgot-password -H "Content-Type: application/json" -d '{"student_id": "123", "password": "newpass", "otp": "123456"}'
    """
    try:
        data = request.get_json()
        student_id = data.get("student_id")
        raw_otp = data.get("otp")
        raw_password = data.get("password")
        return forget_password_controller(student_id, raw_otp, raw_password)
    except:
        return internal_server_error()


@api_bp.route("/send-otp", methods=["PATCH"])
@limiter.limit("3 per minute")
def send_otp():
    """
    PATCH /api/send-otp?reason_id=1|2
    - Sends an OTP to the student's email for password change (1) or account activation (2).
    - Query Parameter: reason_id
    - Request: {"student_id": "..."}
    - Example:
        curl -X PATCH "http://localhost:8000/api/send-otp?reason_id=2" -H "Content-Type: application/json" -d '{"student_id": "123"}'
    """
    try:
        reason_id = request.args.get("reason_id")
        data = request.get_json()
        student_id = data.get("student_id")
        return send_otp_controller(student_id, reason_id)
    except:
        return internal_server_error()


@api_bp.route("/welcocme", methods=["GET"])
@jwt_required()
def welcocme():
    """
    GET /api/welcocme
    - Returns the profile of the logged-in student (requires JWT).
    - Example:
        curl -X GET http://localhost:8000/api/welcocme -H "Authorization: Bearer <access_token>"
    """
    try:
        student_id = get_jwt_identity()
        return welcocme_controller(student_id)
    except:
        return internal_server_error()


@api_bp.route("/change-password", methods=["PATCH"])
@jwt_required()
@limiter.limit("5 per minute")
def change_password():
    """
    PATCH /api/change-password
    - Changes the password for the logged-in student.
    - Requires JWT in Authorization header.
    - Request: {"old_password": "...", "new_password": "..."}
    - Example:
        curl -X PATCH http://localhost:8000/api/change-password -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" -d '{"old_password": "oldpass", "new_password": "newpass123"}'
    """
    try:
        student_id = get_jwt_identity()
        data = request.get_json()
        old_password = data.get("old_password")
        new_password = data.get("new_password")
        return change_password_controller(student_id, old_password, new_password)
    except:
        return internal_server_error()
