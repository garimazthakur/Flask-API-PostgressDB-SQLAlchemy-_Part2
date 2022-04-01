from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import Flask
app= Flask(__name__) 

SECRET_KEY= '659cbe1668c342c4fa07200945c69c45'   
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:123456@localhost:5432/userDB"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Users(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255))
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255)) 
    dob = db.Column(db.String())
    password = db.Column(db.String(100))
    otp = db.Column(db.String(100))
    is_active = db.Column(db.Boolean())
    
    def __init__(self, public_id, first_name, last_name, email, dob, password, otp,is_active):
        self.public_id = public_id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.dob = dob
        self.password = password
        self.otp = otp
        self.is_active = True

    def check_password(self, password):
        return check_password_hash(self.password, password)   
    
    def serialize(self):     #In order to use jsonify() you have to make serializable the class you need to jsonify.
        return {"public_id": self.public_id,
                "first_name": self.firstt_name,
                "last_name": self.last_name,
                "dob": self.dob,
                "password": self.password,
                # "otp": self.otp,
                "is_active": self.is_active
                }
