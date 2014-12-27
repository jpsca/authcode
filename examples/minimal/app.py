# -*- coding: utf-8 -*-
from __future__ import print_function
from flask import Flask, render_template
import authcode
from flask.ext.sqlalchemy import SQLAlchemy


app = Flask(__name__)

SECRET_KEY = '1234567890qwertyuiopasdfghjklzxcvbnm=+!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
app.config['SECRET_KEY'] = SECRET_KEY
db = SQLAlchemy(app)


def send_auth_email(user, subject, msg):
    print('To:', user)
    print('Subject:', subject)
    print (msg)


auth = authcode.Auth(SECRET_KEY, db=db)
authcode.setup_for_flask(auth, app, send_email=send_auth_email)
authcode.setup_for_flask(auth, app)
User = auth.User


@app.route('/')
@auth.protected()
def index():
    return render_template('index.html')


if __name__ == '__main__':
    db.create_all()
    db.session.add(User(login=u'authcode', password=u'authcode'))
    db.session.commit()

    app.run(debug=True)
