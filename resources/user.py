from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
)
from passlib.hash import bcrypt
import datetime

from db import db
from models import UserModel
from schemas import UserSchema
# from blocklist import BLOCKLIST


blp = Blueprint("Users", "users", description="Operations on users")


@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(
                409, message="That username already exists. Please try using a different one.")

        user = UserModel(
            username=user_data["username"],
            password=bcrypt.hash(user_data["password"]),
        )
        db.session.add(user)
        db.session.commit()

        return {"message": "User successfully created."}, 201


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and bcrypt.verify(user_data["password"], user.password):
            expires = datetime.timedelta(days=1)
            access_token = create_access_token(
                identity=user.id, fresh=True, expires_delta=expires)
            refresh_token = create_refresh_token(user.id)
            return {"message": "User successfully logged in.", "access_token": access_token, "refresh_token": refresh_token}, 200

        abort(401, message="Invalid credentials.")


@blp.route("/user/<int:user_id>")
class User(MethodView):

    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200
