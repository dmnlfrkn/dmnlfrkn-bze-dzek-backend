from flask_sqlalchemy import SQLAlchemy
from datetime import datetime



db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(80),unique=True,nullable=False)
    password_hash = db.Column(db.String(128),nullable=False)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    input_text = db.Column(db.Text, nullable=False)
    target_text = db.Column(db.Text, nullable=False)
    source_lang = db.Column(db.String(50), nullable=False)
    target_lang = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)





