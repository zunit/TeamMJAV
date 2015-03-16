import os
import stripe
basedir = os.path.abspath(os.path.dirname(__file__))
#first name: eliquid / last name: admin

WTF_CSRF_ENABLED = True
email = 'welcome.eliquid@gmail.com'
username = 'welcome.eliquid@gmail.com'
password = 'vivmich12'

SECRET_KEY = 'you-will-never-guess'
SECURITY_PASSWORD_SALT = 'my_precious_two'

# email server settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True
MAIL_USERNAME = username
MAIL_PASSWORD = password

# administrator list
#ADMINS = [email]

# mail accounts
MAIL_DEFAULT_SENDER = email

stripe_keys = {
    'secret_key': 'sk_test_BQokikJOvBiI2HlWgH4olfQ2',
    'publishable_key': 'pk_test_6pRNASCoBOKtIshFeQd4XMUh'
}

stripe.api_key = stripe_keys['secret_key']
    
    


SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

WHOOSH_BASE = os.path.join(basedir, 'search.db')

#pagination
MAX_SEARCH_RESULTS = 50
