from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm, oid, lm, mail
from .forms import LoginForm
from forms import SearchForm, RegistrationForm, ForgetForm, AddProdForm, ResetPasswordForm, ResetEmailForm, ContactForm
from .models import User, Products
from config import MAX_SEARCH_RESULTS
from flask.ext import admin
from flask.ext.admin.contrib import sqla
from flask.ext.admin import helpers, expose
from token import generate_confirmation_token, confirm_token
import datetime
from flask.ext.mail import Message, Mail
from email import send_email
from decorators import check_confirmed
import os, random, string, stripe
from werkzeug.security import generate_password_hash, check_password_hash



@lm.user_loader
def load_user(id):
	return User.query.get(int(id))


@app.before_request
def before_request():
    g.user = current_user
    g.login_form = LoginForm()
    g.search_form = SearchForm()
    g.form = RegistrationForm()
    g.forget_form = ForgetForm()
    g.reset_pwd_form = ResetPasswordForm()
    g.reset_email_form = ResetEmailForm()
    g.add_prod_form = AddProdForm()
    # if g.user.is_authenticated():
#         g.user.last_seen = datetime.utcnow()
#         db.session.add(g.user)
#         db.session.commit()
#         g.search_form = SearchForm()


@app.route('/')
@app.route('/index')
def index():
	
	title = 'Home'
			
	if g.user.is_authenticated():
		title = 'WELCOME ' + g.user.username + '!'
		if not g.user.confirmed:
			return redirect(url_for('unconfirmed'))

	return render_template("index.html", title=title)
                           
@app.route('/aboutus')
def aboutus():
	title = 'Home'
	if g.user.is_authenticated():
		title = 'WELCOME ' + g.user.username + '!'
	return render_template("aboutus.html", title=title)                           
  
@app.route("/login", methods=['GET', 'POST'])
def login():
	title = 'Home'
	
	if g.user is not None and g.user.is_authenticated():
 		return redirect(url_for('index'))
 		
 	elif request.method == 'POST' and g.login_form.validate_on_submit() != False:
 		session['remember_me'] = g.login_form.remember_me.data
 		session['logged_in'] = True
 		user = User.query.filter_by(username = g.login_form.username_or_email.data.lower()).first()
 		if user is None:
 			user = User.query.filter_by(email = g.login_form.username_or_email.data).first()
 		#user = User.query.filter_by(username=g.login_form.username_or_email.data).first()
 		#print user.username
 		login_user(user)
 		
 		return redirect(url_for('unconfirmed'))
 		
 	elif request.method == 'GET':
  		return render_template('index.html', title=title, form=g.login_form)
  	flash('Oops, I think you made a mistake, please try again!')	
  	return render_template('index.html', title=title, form=g.login_form, login_errors=g.login_form.errors)
    
@app.route('/confirm/<token>')
def confirm_email(token):
	print 'herehere'
	try:
		email = confirm_token(token)
	except:
		flash('The confirmation link is invalid or has expired.', 'warning')
	user = User.query.filter_by(email=email).first_or_404()
	print user.username
	if user.confirmed:
		flash('Account already confirmed. Please login.', 'success')
	else:
		user.confirmed = True
		user.confirmed_on = datetime.datetime.now()
		db.session.commit()
		flash('You have confirmed your account. Thanks!', 'success')
	return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
	
    logout_user()
    session['logged_in'] = False
    print 'Logged out'
    return redirect(url_for('index'))


@app.route('/search', methods=['POST'])
# @login_required
def search():
	filter = request.form['filter']
	if not g.search_form.validate_on_submit():
		return redirect(url_for('index'))
	return redirect(url_for('search_results', query=g.search_form.search.data, filter=filter))

@app.route('/search_results/<filter>/<query>')
# @login_required
def search_results(query, filter):
	_query = '*' + query + '*'
	if filter == 'User':
		p_results = []
		u_results = User.query.whoosh_search(_query, MAX_SEARCH_RESULTS).all()
	elif filter == 'Product':
		u_results = []
		p_results = Products.query.whoosh_search(_query, MAX_SEARCH_RESULTS).all()
	#u_results = User.query.whoosh_search(_query, MAX_SEARCH_RESULTS).all()
	return render_template('search_results.html', query=query, presults=p_results, uresults=u_results)

@app.route('/user/<username>')
@login_required
def user(username):
	title = 'WELCOME ' + g.user.username + '!'
	u = User.query.filter_by(username=g.user.username).first()
 	products = Products.query.filter_by(user_id=u.id).all()
	return render_template('users_profile.html', title=title, u=u, products=products)


@app.route('/register', methods=['GET', 'POST'])
def register():

	if request.method == 'POST' and g.form.validate_on_submit() != False:
		user = User(username=g.form.username.data, email=g.form.email.data, password=g.form.password.data, confirmed=False)
		print 'done'
		db.session.add(user)
		db.session.commit()
		token = generate_confirmation_token(user.email)
		confirm_url = url_for('confirm_email', token=token, _external=True)
		html = render_template('user/activate.html', confirm_url=confirm_url)
		subject = "Please confirm your email"
		send_email(user.email, subject, html)
		flash('You have signed up successfully! Check your mail box for a confirmation email.', 'success')
		return redirect(url_for('index'))
	elif request.method == 'POST' and g.form.validate_on_submit() == False:
		flash(u'Looks like you type something wrong, please try again!', 'warning')
		return render_template('index.html', reg_errors=g.form.errors)
	print 'startup fail'
	return render_template('index.html')

@app.route('/unconfirmed')
@login_required
def unconfirmed():
	title = 'WELCOME ' + g.user.username + '!'
	if current_user.confirmed:
		return redirect('index')
	flash('Please confirm your account!', 'warning')
	return render_template('user/unconfirmed.html', title=title)

@app.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'info')
    return redirect(url_for('unconfirmed'))

@app.route('/forget', methods=['GET', 'POST'])
def forget():
	title='Home'	
	if request.method =='POST' and g.forget_form.validate_on_submit() != False:
		user = User.query.filter_by(email=g.forget_form.email.data).first()
		
		#generate a random password
		chars = string.ascii_letters + string.digits
		rnd = random.SystemRandom()
		tmp = ''.join(rnd.choice(chars) for i in range(8))
		
		#update and commit database
		user.password = generate_password_hash(tmp)
		db.session.commit()
		

		html = render_template('user/temp_pwd.html', temp_pwd=tmp)
		subject = "E-Liquid: Here is your temporary passsword."
		send_email(user.email, subject, html)
		return redirect(url_for('index'))
		
	elif request.method == 'POST' and g.forget_form.validate_on_submit() == False:
		return render_template('user/forget.html', error=g.forget_form.errors)
	return render_template('user/forget.html', form=g.forget_form)

@app.route('/reset_pwd', methods=['GET', 'POST'])
@login_required
def reset_pwd():
	title = 'WELCOME ' + g.user.username + '!'
	if request.method == 'POST' and g.reset_pwd_form.validate_on_submit() != False:
		user = User.query.filter_by(username=g.user.username).first()
		
		user.password = generate_password_hash(g.reset_pwd_form.new_password.data)
		db.session.commit()
	
		flash("Your password is updated!", 'success')
		print "password is updated"
		
		return redirect(url_for('index'))
	elif request.method == 'POST' and g.reset_pwd_form.validate_on_submit() == False:
		return render_template('user/reset_pwd.html', error=g.reset_pwd_form.errors)
	return render_template("user/reset_pwd.html", form=g.reset_pwd_form)

@app.route('/reset_email', methods=['GET', 'POST'])
@login_required
def reset_email():
	title = 'WELCOME ' + g.user.username + '!'
	if request.method == 'POST' and g.reset_email_form.validate_on_submit() != False:
		user = User.query.filter_by(username=g.user.username).first()
		user.email = g.reset_email_form.new_email.data
		db.session.commit()
		flash("Your email address is updated and a new confirmation email has been sent.", 'info')
		
		
		resend_confirmation()
		return redirect(url_for('index'))
	elif request.method == 'POST' and g.reset_email_form.validate_on_submit() == False:
		return render_template('user/reset_email.html', error=g.reset_email_form.errors)
	return render_template("user/reset_email.html", form=g.reset_email_form)


@app.route('/checkout')
def checkout():
	return render_template("checkout.php")

@app.route('/products/<p_name>')
def products(p_name):
	p = Products.query.filter_by(p_name=p_name).first()
	return render_template("products/single_product.html", p=p) 

	   
@app.route('/add_products', methods=['GET', 'POST'])
@login_required
def add_products():
	title = 'WELCOME ' + g.user.username + '!'
	if request.method == 'POST' and g.add_prod_form.validate_on_submit() != False:
		u = User.query.filter_by(username=g.user.username).first()
		p = Products(p_name=g.add_prod_form.p_name.data, p_price=g.add_prod_form.p_price.data, p_descr=g.add_prod_form.p_descr.data, p_picture=g.add_prod_form.p_picture.data, p_size=g.add_prod_form.p_size.data, p_stock=g.add_prod_form.p_stock.data, users=u)
		print 'u finish adding product'
		u = User.query.filter_by(username=g.user.username).first()
		db.session.add(p)
		db.session.commit()
		html = render_template('products/new_products.html', p=p)
		subject = "You have added a new product"
		send_email(current_user.email, subject, html)
		flash('You have added a product successfully! Check your mail box for a confirmation email.', 'success')
		return redirect(url_for('index'))
	elif request.method == 'POST' and g.form.validate_on_submit() == False:
		flash(u'Looks like you type something wrong, please try again!', 'warning')
		return render_template('products/add_products.html', reg_errors=g.form.errors)

	
	return render_template("products/add_products.html", title=title)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
  form = ContactForm()
 
  if request.method == 'POST':
    if form.validate() == False:
      flash('All fields are required.')
      return render_template('contact.html', form=form)
    else:
    	msg = Message(form.subject.data, sender='welcome.eliquid@gmail.com', recipients=['welcome.eliquid@gmail.com'])
    	msg.body = """
    	From: %s &lt;%s&gt;
    	%s
    	""" % (form.name.data, form.email.data, form.message.data)
    	mail.send(msg)
    	return render_template('contact.html', success=True)
 
  elif request.method == 'GET':
    return render_template('contact.html', form=form)

@app.route('/charge', methods=['POST'])
def charge():
    # Amount in cents
    amount = 500

    customer = stripe.Customer.create(
        email=request.form['stripeEmail'],
        card=request.form['stripeToken']
    )

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=amount,
        currency='usd',
        description='Flask Charge',
        receipt_email=request.form['stripeEmail'],
    
    )
    
    print customer
    print charge

    return render_template('charge.html', amount=amount)