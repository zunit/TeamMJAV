from flask.ext.wtf import Form, RecaptchaField
from wtforms import BooleanField, StringField, TextField, PasswordField, validators, DecimalField, IntegerField, SelectField,TextAreaField, SubmitField
from wtforms.validators import DataRequired,InputRequired, Email, NumberRange
from wtforms.fields.html5 import EmailField  
from wtforms.widgets import TextArea
from flask.ext.login import current_user
from app.models import User
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class ForgetForm(Form):
	email = EmailField('Email Address', [validators.Required(), validators.Email()])
	
	def validate(self):
		if not Form.validate(self):
			return False
		if User.query.filter_by(email = self.email.data).first() is None:
			self.email.errors.append("That email does not exist.")
			return False
		else:
			return True

class ResetPasswordForm(Form):
	
	old_password = PasswordField('Old Password', [validators.Required()])
	new_password = PasswordField('New Password', [validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password', [validators.Required(), validators.EqualTo('new_password', message='Passwords must match')])
	def validate(self):
		if not Form.validate(self):
			return False
		user = User.query.filter_by(username = current_user.username).first()
		password_match = check_password_hash(user.password, self.old_password.data)
		if password_match:
			return True
		else:
			self.old_password.errors.append("Invalid password")
		return False

class ResetEmailForm(Form):
	
	
	password = PasswordField('Password', [validators.Required()])
	new_email = EmailField('New Email Address', [validators.Required(), validators.Email()])
	
	def validate(self):
		if not Form.validate(self):
			return False
		user = User.query.filter_by(username = current_user.username).first()
		password_match = check_password_hash(user.password, self.password.data)
		if password_match:
			return True
		else:
			self.password.errors.append("Invalid password")
		return False


class LoginForm(Form):
    username_or_email = TextField('Username', [validators.Length(min=1, max=25)])
    password = PasswordField('Password', [validators.Required()])
    remember_me = BooleanField('remember_me', default=False)
    def validate(self):
    	if not Form.validate(self):
      		return False

		
    	user = User.query.filter_by(username = self.username_or_email.data.lower()).first()
    	if user is None:
    		user = User.query.filter_by(email = self.username_or_email.data).first()
    	
    	if user is not None:
    		password_match = check_password_hash(user.password, self.password.data)
    	
    	if user and password_match:
    		return True
    	else:
			self.username_or_email.errors.append("Invalid username/e-mail or password")
			return False

class SearchForm(Form):
	search = StringField('search', validators=[DataRequired()])

class RegistrationForm(Form):
    username = TextField('Username', [validators.Required(), validators.Length(min=1, max=25)])
    email = EmailField('Email Address', [validators.Required(), validators.Email()])
    password = PasswordField('New Password', [validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password', [validators.Required(),
        validators.EqualTo('password', message='Passwords must match')
    ])
#     recaptcha = RecaptchaField()

    def validate(self):
    	if not Form.validate(self):
      		return False
      		
#check if username/email is taken or not
    	if User.query.filter_by(username = self.username.data).first() is not None:
    		self.username.errors.append("That username is already taken")
    		return False
    	elif User.query.filter_by(email = self.email.data).first() is not None:
      		self.email.errors.append("That email is already taken")
      		return False
      	else:
      		return True
      		
class AddProdForm(Form):
	MAX_P_NUM = 500
	
	p_name = TextField('Product Name', [validators.Required(), validators.Length(min=3, max = 25, message='Number of characters between 3 ~ 25')])
	p_price = DecimalField('Price', [validators.Required()], places=2, rounding=None)
	p_descr = StringField('Description', [validators.Length(max=990, message='Description can be no longer than 990 chars')], widget=TextArea())
	p_picture = StringField('Image url')
	#p_num_size = IntegerField('Number of Sizes')
	p_size = SelectField(u'Size', choices=[(1, '30mL'),(2, '40mL'),(3, '50mL')],coerce=int)
	p_stock = IntegerField('Stock', [validators.Required(), validators.NumberRange(min=0, max=MAX_P_NUM, message='Range between 0 ~ 500')])
	
	def validate(self):
		if not Form.validate(self):
			return False

class ContactForm(Form):
  name = TextField("Name",  [validators.Required()])
  email = EmailField('Email Address', [validators.Required(), validators.Email()])
  subject = TextField("Subject",  [validators.Required()])
  message = TextAreaField("Message",  [validators.Required()])

	
	
	
	
      		

      		

