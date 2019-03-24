import sqlite3

import bcrypt
from flask_restful import Resource, reqparse
from werkzeug.security import generate_password_hash

from models.user import UserModel


class UserRegister(Resource):
    def post(self):
        connection = sqlite3.connect('data.db')
        cursor = connection.cursor()
        req = reqparse.RequestParser()
        req.add_argument(
            'username', type=str, required=True, help="username is required")
        req.add_argument(
            'password', type=str, required=True, help="password is required")
        data = req.parse_args()
        hashed_password = bcrypt.hashpw(
            data['password'].encode('utf-8'), bcrypt.gensalt())
        if UserModel.find_by_username(data['username']):
            return {"message": "user already exists"}, 400

        user = UserModel(data['username'], hashed_password)
        user.save_to_db()

        return {"message": "User created successfully"}, 201
