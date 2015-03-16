from app import db
from app import app
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

import sys
if sys.version_info >= (3, 0):
    enable_search = False
else:
    enable_search = True
    import flask.ext.whooshalchemy as whooshalchemy


class User(db.Model):

	__tablename__ = 'users'
	__searchable__ = ['username']
	
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), index=True, unique=True)
	email = db.Column(db.String(120), index=True, unique=True)
	password = db.Column(db.String(10))
	registered_on = db.Column(db.DateTime, nullable=False)
	confirmed=db.Column(db.Boolean, nullable=False, default=False)
	confirmed_on=db.Column(db.DateTime, nullable=True)
	admin = db.Column(db.Boolean, nullable=False, default=False)
	products = db.relationship('Products', backref='users', lazy='dynamic')

	def is_authenticated(self):
		return True
	
	def is_active(self):
		return True
	
	def is_anonymous(self):
		return False
		
	def get_id(self):
		return unicode(self.id)

	
	def __repr__(self):
		return
	
	def set_password(self, password):
		self.password = generate_password_hash(password)

	
	def __init__(self , username ,password , email, confirmed, admin=False, confirmed_on=None):
		self.username = username
		self.set_password(password)
		self.email = email
		self.admin = admin
		self.registered_on = datetime.datetime.now()
		self.confirmed = confirmed
		self.confirmed_on = confirmed_on
	

class Products(db.Model):
	__tablename__ = 'products'
	__searchable__ = ['p_name']
	
	
	id = db.Column(db.Integer, primary_key=True)
	p_name = db.Column(db.String(50), index=True)
	p_descr = db.Column(db.String(1000))
	p_price = db.Column(db.Float)
	p_picture = db.Column(db.String(1000))
	p_size = db.Column(db.Integer)
	p_stock = db.Column(db.Integer)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
		
	def __repr__(self):
		return '<Product %r>' % (self.p_name)
		
if enable_search:
    whooshalchemy.whoosh_index(app, User)
    whooshalchemy.whoosh_index(app, Products)
