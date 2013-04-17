# -*- coding: utf-8 -*-
from flask import url_for


SQLALCHEMY_URI = 'sqlite:///test.db'

SECRET_KEY = 'sdsmmp8y3hlkm 4f\xb2\xf7+2oripwfie9fiu29831gelemfop2i3yrp23\x8d'

TWITTER_KEY = '< paste your twitter app key here >'
TWITTER_SECRET = '< paste your twitter app secret here >'

FACEBOOK_APP_ID = '< paste your facebook app_id here >'
FACEBOOK_APP_SECRET = '< paste your feacebook app secret here >'

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
    from local import *
except ImportError:
    pass
