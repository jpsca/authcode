# -*- coding: utf-8 -*-
from flask import url_for
from authcode import Auth, setup_for_flask

import settings
from app import app, db


class UserMixin(object):
    twitter_id = db.Column(db.String(255), nullable=True)
    twitter_username = db.Column(db.String(255), nullable=True)
    twitter_token = db.Column(db.String(255), nullable=True)
    twitter_secret = db.Column(db.String(255), nullable=True)

    facebook_id = db.Column(db.String(255), nullable=True)
    facebook_token = db.Column(db.String(255), nullable=True)


auth = Auth(settings.SECRET_KEY, db=db, UserMixin=UserMixin, roles=False,
    **settings.AUTH_SETTINGS)

User = auth.User

setup_for_flask(auth, app, views=False)


def get_unique_login(target):
    num = 1
    login = target
    while True:
        if not db.query(User).filter(User.login==login).count():
            return login
        num = num + 1
        login = '{0}{1}'.format(target, num)

