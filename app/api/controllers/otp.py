from flask import current_app, request

from app.core.emailer import Emailer
from app.core.keys.otp_manager import OtpManager
from app.core.responses import (
    account_already_activated,
    account_not_activated,
    error_generating_otp,
    error_sending_otp,
    invalid_value,
    missing_fields,
    not_eligible,
    otp_sent,
    student_not_exist,
)
from app.core.utils.std_manager import (
    check_student_account,
    check_student_login_ability,
    valid_str_req_value,
)
from app.models.students import StudentOTP


reason_ids = {1: "change_password", 2: "activate_account"}


def send_otp_controller(student_id, reason_id):
    if valid_str_req_value([student_id, reason_id]) is False:
        return missing_fields([student_id, reason_id])

    try:
        reason_id = int(reason_id)
    except ValueError:
        return invalid_value("reason_id")

    if reason_id not in reason_ids.keys():
        return invalid_value("reason_id")

    student, student_login = check_student_account(student_id)
    if student is None:
        return student_not_exist()

    is_able, message = check_student_login_ability(student)
    if not is_able:
        return not_eligible(message)

    if reason_id == 2:
        if student_login is not None:
            return account_already_activated()

    elif reason_id == 1:
        if student_login is None:
            return account_not_activated()

    try:
        student_otp = StudentOTP.query.filter_by(student_id=student_id).first()
        if student_otp is None:
            student_otp = StudentOTP(student_id=student_id)  # type: ignore

        db_otp = OtpManager(student_otp).get_otp()
    except Exception as e:
        current_app.logger.error(f"ERROR generating OTP for {student_id}: {e}")
        return error_generating_otp(student_id)

    emailer = Emailer(student.email, reason_ids[reason_id])

    try:
        # FIXME: UNCOMMENT print(db_otp) when EMAIL IS FIXED
        print(db_otp)
        # emailer.send(db_otp)
        current_app.logger.info(
            f"[AUDIT] OTP sent for student_id={student_id} (reason={reason_ids[reason_id]}) from {request.remote_addr}"
        )
    except Exception as e:
        current_app.logger.error(f"ERROR sending OTP for {student_id}: {e}")
        return error_sending_otp(student_id)

    return otp_sent()
