# coding=utf-8
import os
from flask import url_for


DEBUG = True

# Create an app and get your own credentials here:
# https://dev.twitter.com/apps
TWITTER_KEY = os.getenv('TWITTER_KEY', 'twitter app key')
TWITTER_SECRET = os.getenv('TWITTER_SECRET', 'twitter app secret')

# Create an app and get your own credentials here:
# https://developers.facebook.com/apps
FACEBOOK_APP_ID = os.getenv('FACEBOOK_APP_ID', 'facebook app id')
FACEBOOK_APP_SECRET = os.getenv('FACEBOOK_APP_SECRET', 'facebook app secret')


SQLALCHEMY_URI = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite')

SECRET_KEY = os.getenv('SECRET_KEY', 'development key')

AUTH_SETTINGS = {
    'pepper': os.getenv('AUTH_PEPPER', 'pepper is good for you'),
    'sign_in_redirect': lambda r: url_for('profile'),
    'sign_out_redirect': lambda r: url_for('index'),
    'password_minlen': 5,

    'url_sign_in': lambda r: url_for('sign_in'),
    'views': [],
}
