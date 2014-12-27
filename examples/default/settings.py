# coding=utf-8
import os
from flask import url_for


DEBUG = True

SQLALCHEMY_URI = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite')

SECRET_KEY = os.getenv('SECRET_KEY', 'development key')

AUTH_SETTINGS = {
    'pepper': os.getenv('AUTH_PEPPER', 'pepper is good for you'),
    'sign_in_redirect': lambda r: url_for('profile'),
    'sign_out_redirect': lambda r: url_for('index'),
    'password_minlen': 6,
}

MAILER_SENDER = os.getenv('MAILER_SENDER', 'info@example.com'),

MAILER_SETTINGS = {
    'host': os.getenv('MAILER_HOST', 'example.com'),
    'username': os.getenv('MAILER_USERNAME', 'username'),
    'password': os.getenv('MAILER_PASSWORD', 'password'),
    'port': os.getenv('MAILER_PORT', 587),
    'use_tls': True,
}
