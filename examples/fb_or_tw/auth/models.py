# -*- coding: utf-8 -*-
from flask import url_for
from authcode import Auth, setup_for_flask

import settings
from app import app, db


class UserMixin(object):
    twitter_token = db.Column(db.String(255), nullable=True)
    twitter_secret = db.Column(db.String(255), nullable=True)


auth = Auth(settings.SECRET_KEY, db=db, UserMixin=UserMixin, roles=False,
    **settings.AUTH_SETTINGS)

User = auth.User

setup_for_flask(auth, app, views=False)
