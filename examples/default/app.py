# coding=utf-8
from flask import Flask
from mailshake import ToConsoleMailer, SMTPMailer
from orm import SQLAlchemy

import settings


app = Flask(__name__)
app.config.from_object(settings)

db = SQLAlchemy(settings.SQLALCHEMY_URI, app)

if settings.DEBUG:
    mailer = ToConsoleMailer()
else:
    mailer = SMTPMailer(**settings.MAILER_SETTINGS)

