# coding=utf-8
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
setup_for_flask(auth, app)
User = auth.User


def get_unique_login(target):
    num = 1
    login = target
    while True:
        if not User.by_login(login):
            return login
        num = num + 1
        login = '{target}{num}'.format(target=target, num=num)
