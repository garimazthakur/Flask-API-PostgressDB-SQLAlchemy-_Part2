import email
from lib2to3.pgen2 import token
import os
import bcrypt
import urllib.request
from click import password_option
from itsdangerous import json
from numpy import double
import psycopg2
import jwt
import json
from functools import wraps
from flask import Flask, jsonify, redirect, request, make_response
from werkzeug.utils import secure_filename
from numpy import double
import uuid   
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from app import db, SECRET_KEY,Users, app

def token_required(f): # Special function for creating a custom decorator with the code required to create and validate tokens.
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('authorization')  
        if not token:
            return jsonify({"message": "A valid token is missing"})
        try:
            data = jwt.decode(token, SECRET_KEY,  algorithms="HS256")
        except:
            return jsonify({"message": "token is invalid"})
        return f(*args, **kwargs)
    return decorator

@app.route('/signup', methods = ['POST'])
def signup():
    body = request.get_json()
    print(body)
    print(body["dob"])
    hashed_password = generate_password_hash(body['password'], method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), first_name=body['first_name'], last_name=body['last_name'], email=body['email'], dob=body['dob'], password=hashed_password, is_active = False)
    db.session.add(new_user)
    db.session.commit()            


@app.route('/login', methods= ['POST'])
def login_user(): 
    info = json.loads(request.data) 
    email = info["email"] 
    password = info["password"]
    # print(f"{email}, and {password}")
    user = Users.query.filter_by(email=email).first()   
    # print(user)
    if user: 
        if user.check_password(password):   
            # print(user.public_id)
            token = jwt.encode({'id':str(user.public_id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 3600)}, SECRET_KEY, algorithm = 'HS256')
            # print(token)
            return jsonify({"token":token}) 
    return jsonify({"message": "Login Required"})

def getID(token):
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms = 'HS256')
    # print(">>>>>>>>>>> {}".format(type(decoded_token)))
    return decoded_token

@app.route('/password', methods = ['POST'])
@token_required
def reset_password():
    id = getID(request.headers.get('authorization'))
    user = Users.query.filter_by(public_id=id['id']).first()
    print(user)
    # print(user.password.encode("utf-8"))
    print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
    body = request.json
    old_password = body["old_password"]
    new_password = body["new_password"]
    confirm_password = body["confirm_password"]
    print(old_password)
    print(user.password)
    check_password =check_password_hash(user.password, body['old_password'])
    print(check_password)
    if check_password:
        if new_password == confirm_password:
            print("new password match")
            # user.password = new_password
            user.password = generate_password_hash(new_password, method = 'sha256')
            print(user.password)
            print(user.password)
        else:
            print("does not match")    
    db.session.commit()
   
#forgot password   -- 1. generate otp; 2. verify_otp; 3. forgot password
@app.route('/generate_otp', methods = ['POST'])
def generate_otp():
    # id = getID(request.headers.get('authorization'))
    # user =  Users.query.filter_by(public_id=id['id']).first()
    body = request.json
    email = body["email"]
    user = Users.query.filter_by(email=email).first()
    otp = "12345"
    if user:
        user.otp=otp
        db.session.commit()
        return jsonify({"message" : "The otp sent to your mail"})
    else:
        return jsonify({"message" : "Email is not valid. Please enter the correct email address"})
    
@app.route("/verify_otp", methods = ["POST"])
@token_required
def verify_otp():
    body = request.json
    email = body["email"]
    otp = body["otp"]
    # user = Users.query.filter_by(email = email).first()
    id = getID(request.headers.get('authorization'))
    user =  Users.query.filter_by(public_id=id['id']).first()
    print(user.otp)
    if user:
        if user.otp == otp and user.email == email:
            return jsonify({"mesage": "The otp is verified"})
        elif user.email!=email:
            return jsonify({"message": "Email is not verified."})
        elif user.otp !=otp and user.email ==email:
            return jsonify({"message": "Wrong OTP. Please enter agian!"})
        db.session.commit()   
    else:
        return({"message": " The user does not exist"})

@app.route('/forgot_password', methods = ['POST'])
@token_required
def forgot_password():
    body = request.json
    email = body["email"]
    otp = body["otp"]
    new_password = body["new_password"]
    confirm_password = body["confirm_password"]
    id = getID(request.headers.get('authorization'))
    user =  Users.query.filter_by(public_id=id['id']).first()
    if user:
        if user.email == email and user.otp == otp:
            if new_password == confirm_password:
                print("new password match")
                user.password = generate_password_hash(new_password, method = 'sha256')
                print(user.password)
            else:
                print("does not match")
                return({"message": "password not match"})    
            db.session.commit()
            return jsonify({"password": "Update"})
        elif user.email == email and user.otp !=otp:
            return jsonify({"message" : "OPT is not valid. Please enter the correct OTP"})
    else:
        return({"message": " The user does not exist"})

@app.route('/profile', methods = ['GET', 'PUT', 'DELETE', 'PATCH'])
@token_required
def get_one_user():
    id = getID(request.headers.get('authorization'))
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

    if request.method == "DELETE":
        if not user:
            return jsonify({"message":"User not found"})
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message' : 'The user has been deleted!'})

    if request.method == "PUT":
        if not user:
            return jsonify({"message":"User not found"})
        else:
            body = request.json
            print(body)
            first_name = body["first_name"]
            last_name = body["last_name"]
            email = body["email"]
            dob = body["dob"]
            # otp = body["otp"]
            user.first_name = first_name
            user.last_name =last_name
            user.email=email
            user.dob=dob
            # user.save()
        # db.session.add(updated_user)
        db.session.commit()
        return jsonify({'message' : 'The user has been updated!'})
   
    if request.method == "PATCH":
        # print("enter")
        if not user:
            return jsonify({"message":"User not found"})
        else:
            data = request.json
            print(data)
            if data.get('first_name'):
                user.first_name=data['first_name']
                print(data['first_name'])

            if data.get('last_name'):
                user.last_name=data['last_name']
                print(data['last_name'])

            if data.get('dob'):
                user.dob=data['dob']
                print(data['dob'])

            if data.get('email'):
                user.email=data['email']
                print(data['email'])
            
        db.session.commit()
        return jsonify({'message' : 'The field has been updated!'})
    

 #For simple login without token
        
# @app.route('/login', methods= ['POST'])    
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
    app.run(port=8000, debug=True)

