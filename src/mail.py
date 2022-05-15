from flask_mail import Message
from flask import url_for
from . import mail
from jinja2 import Template
import os
from threading import Thread


class HTMLTemplate():
    def __init__(self, template_path="templates"):
        self.template_path = template_path
    
    def render(self, template_file, context):
        with open(os.path.join(self.template_path, template_file), "r") as f:
            template = Template(f.read())
        return template.render(context)


def send_mail(app, msg):
    with app.app_context():
        mail.send(msg)


def send_confirm_mail(app, ts, email, name):
    token = ts.dumps(email, salt='email-confirm')

    msg = Message('Confirm Email', sender=app.config.get('MAIL_USERNAME'), recipients=[email])
    msg.subject = "Confirm Email"

    template = HTMLTemplate(app.template_folder)
    context = {
        "home_url": url_for('login', _external=True),
        "confirm_url": url_for("confirm_email", token=token, _external=True),
        "name": name
    }

    msg.html = template.render('confirmation_mail.html', context)
    
    thr = Thread(target=send_mail, args=(app, msg))
    thr.start()
    

def send_reset_mail(app, ts, email):
    token = ts.dumps(email, salt='reset-password')

    msg = Message('Reset Password', sender=app.config.get('MAIL_USERNAME'), recipients=[email])
    msg.subject = "Reset Password"

    template = HTMLTemplate(app.template_folder)
    context = {
        "home_url": url_for('login', _external=True),
        "reset_url": url_for("reset_password", token=token, _external=True),
    }

    msg.html = template.render('reset_mail.html', context)
    
    thr = Thread(target=send_mail, args=(app, msg))
    thr.start()