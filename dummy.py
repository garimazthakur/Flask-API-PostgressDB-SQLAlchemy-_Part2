import email
import os
# from turtle import pu
import urllib.request
from click import password_option
from itsdangerous import json
from numpy import double
import psycopg2
import jwt
from functools import wraps
# from flask_login import LoginManager, login_user, login_required, logout_user 
from flask import Flask, current_app, jsonify, redirect, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from numpy import double
import uuid   #to generarte random id
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
# from app.utils import verify_password
app= Flask(__name__) 
SECRET_KEY= '659cbe1668c342c4fa07200945c69c45'   
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:123456@localhost:5432/userDB"

db = SQLAlchemy(app)
class Users(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255)) 
    dob = db.Column(db.String())
    password = db.Column(db.String(100))
    is_active = db.Column(db.Boolean())
    
    def __init__(self, public_id, first_name, last_name, email, dob, password,is_active):
        self.public_id = public_id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.dob = dob
        self.password = password
        self.is_active=is_active

    def check_password(self, password):
        return check_password_hash(self.password, password)   

    def serialize(self):     #In order to use jsonify() you have to make serializable the class you need to jsonify.
        return {"public_id": self.public_id,
                "first_name": self.first_name,
                "last_name": self.last_name,
                "dob": self.dob,
                "password": self.password,
                "is_active": self.is_active}

def token_required(f): #Special function for creating a custom decorator with the code required to create and validate tokens.
    @wraps(f)
    def decorator(*args, **kwargs):
        # token = None
        # if 'authorization' in request.headers:
            # token = request.headers['authorization']
        token = request.headers.get('authorization')  
        if not token:
            return jsonify({"message": "A valid token is missing"})
        try:
            data = jwt.decode(token, SECRET_KEY,  algorithms="HS256")
            # current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "token is invalid"})

        # return f(current_user, *args, **kwargs)
        return f(*args, **kwargs)
    return decorator


@app.route('/signup', methods = ['POST'])
def signup():
    body = request.get_json()
    print(body)
    print(body["dob"])
    hashed_password = generate_password_hash(body['password'], method = 'sha256')
    new_user = Users(public_id=str(uuid.uuid4()), first_name=body['first_name'], last_name=body['last_name'], email = body['email'], dob= body['dob'], password=hashed_password, is_active = False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({
        'message': 'Registeration Successfull'
        })

@app.route('/login', methods= ['POST'])
# @token_required
def login_user(): 
    info = json.loads(request.data) 
    email = info["email"] 
    password = info["password"]
    # print(f"{email}, and {password}")
    user = Users.query.filter_by(email=email).first()   
    # print(user)
    if user: 
        if user.check_password(password):   
            # print(user.public_id)s
            token = jwt.encode({'id':str(user.public_id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 3600)}, SECRET_KEY, algorithm = 'HS256')
            # print(token)
            return jsonify({"token":token}) 
    return jsonify({"message": "Login Required"})

@app.route('/getdata', methods = ['GET'])
@token_required
def get_all_data():
    # alldata = Users.query.filter_by(current_user_id=current_user["public_id"]).all
    alldata = Users.query.all
    output = []
    # alldata1 = Users.query.filter_by(id = 2).first()
    for data in alldata:
        datum = {}
        datum["public_id"] =data.public_id
        datum["first_name"]=data.first_name
        datum["last_name"]=data.last_name
        datum["dob"]=data.dob
        datum["password"] = data.password
        output.append(datum)
    return jsonify(output)

def getID(token):
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms = 'HS256')
    # print(">>>>>>>>>>> {}".format(type(decoded_token)))
    return decoded_token

@app.route('/profile', methods = ['GET', 'PUT', 'DELETE'])
@token_required
def get_one_user():
    id = getID(request.headers.get('authorization'))
    print(id)
    # return jsonify({"user": id})
    # user =  user = Users.query.filter_by(public_id=public_id, current_user_id=current_user["public_id"]).first()
    user = Users.query.filter_by(public_id=id['id']).first()
    if request.method=="GET":
        if not user:
            return jsonify({"message":"User not found"})
        else:
            datum = {}
            datum["public_id"] =user.public_id
            datum["first_name"]=user.first_name
            datum["last_name"]=user.last_name
            datum["dob"]=user.dob
            return jsonify({"user": datum})
    # if request.method == "DELETE":
    #     if not user:
    #         return jsonify({"message":"User not found"})
    #     db.session.delete(user)
    #     db.session.commit()
    #     return jsonify({'message' : 'The user has been deleted!'})

    # if request.method == "PUT":
    #     if not user:
    #         return jsonify({"message":"User not found"})
    #     else:
    #         body = request.json
    #         first_name = body["first_name"]
    #         last_name = body["last_name"]
    #         email = body["email"]
    #         dob = body["dob"]
    #         hashed_password = generate_password_hash(body['password'], method = 'sha256')
    #         password = hashed_password 
    #         user.first_name = first_name
    #         user.last_name =last_name
    #         user.email=email
    #         user.dob=dob
    #         user.password=password
    #     user = Users(id, first_name, last_name, email, dob, password)
    #     db.session.add(user)
    #     db.session.commit()
    #     return jsonify({'message' : 'The user has been updated!'})

    
# @app.route('/login', methods= ['POST'])    #For simple login without token 
# def login():
#     info = json.loads(request.data)
#     password = info['password']
#     email = info['email']
#     user = Users.query.filter_by(email=email).first()
#     if user:
#         if user.check_password(password):
#             user = user.serialize()
#             return jsonify(user)
#         else:
#             return jsonify({"status": 401, 
#                         "reason": "Wrong Password"})
#     else:
#         return jsonify({"status": 401, 
#                         "reason": "Email or Password Error"})
if __name__ == "__main__":
    app.run(port=5005, debug=True)