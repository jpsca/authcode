# -*- coding: utf-8 -*-
import os
from flask import url_for


# Create an app and get your own credentials here:
# https://dev.twitter.com/apps
TWITTER_KEY = os.getenv('TWITTER_KEY',
    '<paste your twitter app key here>')
TWITTER_SECRET = os.getenv('TWITTER_SECRET',
    '<paste your twitter app secret here>')

# Create an app and get your own credentials here:
# https://developers.facebook.com/apps
FACEBOOK_APP_ID = os.getenv('FACEBOOK_APP_ID',
    '<paste your facebook app_id here>')
FACEBOOK_APP_SECRET = os.getenv('FACEBOOK_APP_SECRET',
    '<paste your facebook app secret here>')


SQLALCHEMY_URI = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite')

SECRET_KEY = 'development key 121234567890'

AUTH_SETTINGS = {
    'pepper': '74e89fd60f735b36181272530e12114587ce3',
    'sign_in_redirect': lambda r: url_for('profile'),
    'sign_out_redirect': lambda r: url_for('index'),
    'password_minlen': 5,
    
    'url_sign_in': lambda r: url_for('login'),
    'url_sign_out': lambda r: url_for('logout'),
    'url_reset_password': None,
    'url_change_password': None,
}

try:
    from _secret import *
except ImportError:
    pass
