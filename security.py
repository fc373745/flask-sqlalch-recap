import bcrypt
from werkzeug.security import check_password_hash

from resources.user import UserModel


def authenticate(username, password):
    user = UserModel.find_by_username(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
        return user


def identity(payload):
    user_id = payload['identity']
    return UserModel.find_by_id(user_id)
