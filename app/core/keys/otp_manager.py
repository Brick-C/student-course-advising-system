import random
import string
from datetime import datetime, timedelta

from app.models.students import StudentOTP
from app.core.db import save_db


def generate_otp(length: int = 6):
    return "".join(random.choices(string.digits, k=length))


def verify_otp(student_id: str, raw_otp: str):
    student_otp = StudentOTP.query.filter_by(student_id=student_id).first()
    if student_otp is None:
        return False

    return OtpManager(student_otp).compare_otp(raw_otp)


class OtpManager:
    MAX_TRIES = 5

    def __init__(self, std_otp: StudentOTP):
        self.__std_otp: StudentOTP = std_otp
        self.__refresh_otp()

    def __reset_otp(self):
        now = datetime.utcnow()
        self.__std_otp.otp = generate_otp()
        self.__std_otp.created_at = now
        self.__std_otp.expires_at = now + timedelta(minutes=10)
        self.__std_otp.try_count = 0
        save_db(self.__std_otp)

    def __refresh_otp(self):
        if (
            self.__std_otp.otp is None
            or self.__std_otp.created_at is None
            or self.__std_otp.expires_at is None
            or self.__std_otp.try_count is None
        ):
            self.__reset_otp()
        if self.is_expired():
            self.__reset_otp()

    def get_otp(self):
        self.__refresh_otp()
        return self.__std_otp.otp

    def compare_otp(self, raw_otp):
        if (
            self.__std_otp.otp is None
            or self.__std_otp.created_at is None
            or self.__std_otp.expires_at is None
        ):
            return False

        if self.get_otp() == raw_otp:
            self.__std_otp.otp = None
            self.__std_otp.created_at = None
            self.__std_otp.expires_at = None
            self.__std_otp.try_count = 0
            return save_db(self.__std_otp)
        else:
            self.__increment_try_count()
            return False

    def __increment_try_count(self):
        self.__std_otp.try_count = (self.__std_otp.try_count or 0) + 1
        save_db(self.__std_otp)

    def is_expired(self):
        return (
            self.__std_otp.expires_at is None
            or datetime.utcnow() > self.__std_otp.expires_at
            or (self.__std_otp.try_count or 0) >= self.MAX_TRIES
        )
