from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.String(300), primary_key=True)
    email = db.Column(db.String(200), unique=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(1000))
    total_accounts = db.Column(db.Integer, default=0)
    createdAt = db.Column(db.DateTime)
    verified = db.Column(db.Boolean, default=False)
    accounts = db.relationship('Accounts', backref='user', cascade="all, delete-orphan", lazy='dynamic')

class Accounts(db.Model):
    id = db.Column(db.String(300), primary_key=True)
    user_id = db.Column(db.String(300), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    account_name = db.Column(db.String(1000), nullable=False)
    username = db.Column(db.String(1000), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    createdAt = db.Column(db.DateTime)

class Admin(UserMixin):
    def __init__(self, username, password):
        self.id = "admin"
        self.username = username
        self.password = password