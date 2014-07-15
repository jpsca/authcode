# coding=utf-8
from hashlib import md5
import os


SECRET_KEY = md5(os.urandom(32)).hexdigest()
