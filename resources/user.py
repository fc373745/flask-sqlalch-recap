from werkzeug.security import safe_str_cmp

import bcrypt
from blacklist import BLACKLIST
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt,
                                jwt_refresh_token_required, jwt_required)
from flask_restful import Resource, reqparse
from models.user import UserModel


class UserRegister(Resource):
    def post(self):
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


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        user.delete_from_db()
        return {'message': 'User deleted from db'}, 200


class UserLogout(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']  # a unique identifier for a jwt token
        BLACKLIST.add(jti)
        return {
            'message': 'successful logout'
        }


class UserLogin(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username',
                        type=str,
                        required=-True,
                        help="This field cannot be blank."
                        )
    parser.add_argument('password',
                        type=str,
                        required=True,
                        help="This field cannot be blank."
                        )

    @classmethod
    def post(cls):
        data = cls.parser.parse_args()

        user = UserModel.find_by_username(data['username'])

        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {'message': 'Invalid credentials'}, 401


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200
