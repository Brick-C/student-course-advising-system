from flask_jwt_extended import create_access_token, get_jwt_identity
from flask import jsonify, current_app, request, make_response

from app.core.responses import (
    authentication_failed,
    invalid_otp,
    student_not_exist,
    not_eligible,
    account_not_activated,
    invalid_password,
    login_success,
    missing_fields,
    logout_success,
    password_too_short,
    account_already_activated,
    error_creating_account,
    account_activated,
    account_locked,
)
from app.core.keys.passwords import compare_password, hash_password
from app.core.utils.std_manager import (
    check_std_lockout,
    check_student_account,
    valid_str_req_value,
    check_student_login_ability,
)
from app.models.students import StudentLogin
from app.core.keys.otp_manager import verify_otp
from app.core.db import save_db
from app.core.serializers.student import serialize_student


def login_controller(student_id, raw_password):
    if valid_str_req_value([student_id, raw_password]) is False:
        return missing_fields([student_id, raw_password])

    student, student_login = check_student_account(student_id)
    if student is None:
        return student_not_exist()

    if student_login is None:
        return account_not_activated()

    if check_std_lockout(student_login) is False:
        return account_locked(student_login.lockout_until)

    is_able, message = check_student_login_ability(student)
    if not is_able:
        return not_eligible(message)

    if compare_password(raw_password, student_login.password) is False:
        return invalid_password()

    if student_login:
        student_login.failed_attempts = 0
        student_login.lockout_until = None
        save_db(student_login)

    access_token = create_access_token(identity=student_id)
    current_app.logger.info(
        f"[AUDIT] Successful login for student_id={student_id} from {request.remote_addr}"
    )
    response = login_success()
    response.set_cookie(
        "access_token_cookie",
        access_token,
        httponly=True,
        secure=False,  # Set True in production
        samesite="Lax",
    )
    return response


def logout_controller(jti, jwt_blacklist):
    jwt_blacklist.add(jti)
    student_id = None
    try:
        student_id = get_jwt_identity()
    except Exception:
        pass
    current_app.logger.info(
        f"[AUDIT] Logout for student_id={student_id} from {request.remote_addr}"
    )
    return logout_success()


def activate_controller(student_id, raw_otp, raw_password):
    if valid_str_req_value([student_id, raw_otp, raw_password]) is False:
        return missing_fields([student_id, raw_otp, raw_password])

    if len(raw_password) < 8:
        return password_too_short()

    student, student_login = check_student_account(student_id)
    if student is None:
        return student_not_exist()

    is_able, message = check_student_login_ability(student)
    if not is_able:
        return not_eligible(message)

    if student_login is not None:
        return account_already_activated()

    if verify_otp(student_id, raw_otp) is False:
        return invalid_otp()

    hashed_password = hash_password(raw_password)
    student_login = StudentLogin(student_id=student_id, password=hashed_password)  # type: ignore
    if save_db(student_login) is False:
        return error_creating_account(student_id)

    current_app.logger.info(
        f"[AUDIT] Account activated for student_id={student_id} from {request.remote_addr}"
    )
    return account_activated()


def welcome_controller(student_id):
    if valid_str_req_value([student_id]) is False:
        return authentication_failed()

    student, student_login = check_student_account(student_id)
    if student is None:
        return student_not_exist()

    is_able, message = check_student_login_ability(student)
    if not is_able:
        return not_eligible(message)

    if student_login is None:
        return account_not_activated()

    current_app.logger.info(
        f"[AUDIT] Profile viewed for student_id={student_id} from {request.remote_addr}"
    )
    return jsonify(serialize_student(student)), 200
