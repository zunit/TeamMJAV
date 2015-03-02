from flask.ext.mail import Message

from app import app, mail


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender='welcome.eliquid@gmail.com'
        
    )
    mail.send(msg)
#sender=app.config['MAIL_DEFAULT_SENDER']