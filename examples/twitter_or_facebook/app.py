# coding=utf-8
from flask import Flask
from sqlalchemy_wrapper import SQLAlchemy

import settings


app = Flask(__name__)
app.config.from_object(settings)

db = SQLAlchemy(settings.SQLALCHEMY_URI, app)
