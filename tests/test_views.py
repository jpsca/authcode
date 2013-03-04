# -*- coding: utf-8 -*-
import pytest
import authorizer
from flask import Flask
from orm import SQLAlchemy

from helpers import *


def get_flask_app(**kwargs):
    db = SQLAlchemy()
    auth = authorizer.Auth(SECRET_KEY, db=db, **kwargs)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    app = Flask('test')
    app.secret_key = os.urandom(32)
    app.testing = True

    authorizer.setup_for_flask(auth, app)
    auth.session = {}
    return auth, app, user


def test_login():
    auth, app, user = get_flask_app()
    client = app.test_client()

    r = client.get(auth.url_sign_in)
    assert 'Sign in' in r.data

    r = client.post(auth.url_sign_in)
    assert 'Wrong' in r.data
    assert auth.session_key not in auth.session

    r = client.post(auth.url_sign_in, data=dict(login=user.login, password='foobar'))
    assert r.status == '303 SEE OTHER'
    assert auth.session_key in auth.session

    auth.session[auth.redirect_key] = 'http://google.com'
    r = client.get(auth.url_sign_in)
    assert r.status == '303 SEE OTHER'

    r = client.get(auth.url_sign_out)
    assert r.status == '303 SEE OTHER'
    assert auth.session_key not in auth.session    


def test_reset_password():
    auth, app, user = get_flask_app()
    client = app.test_client()

    log = []
    def send_email(user, subject, msg):
        log.append(msg)
    auth.send_email = send_email
    token = user.get_token()

    r = client.get(auth.url_reset_password)
    assert 'Reset password' in r.data

    r = client.post(auth.url_reset_password, data=dict(login=u'nn'))
    assert 'We couldn\'t find an account for that username' in r.data

    r = client.post(auth.url_reset_password, data=dict(login=user.login))
    assert 'Please check your inbox' in r.data
    print r.data
    assert auth.url_reset_password + token + '/' in log[0]

    r = client.get(auth.url_reset_password + 'xxx/')
    assert 'Something is wrong' in r.data

    r = client.get(auth.url_reset_password + token + '/')
    assert auth.session_key in auth.session
    assert 'Change password' in r.data
    assert 'current password' not in r.data

    r = client.get(auth.url_reset_password)
    assert r.status == '303 SEE OTHER' 


def test_change_password():
    auth, app, user = get_flask_app()
    client = app.test_client()

    r = client.get(auth.url_change_password)
    assert r.status == '303 SEE OTHER'
    
    auth.login(user)
    csrf_token = auth.get_csfr_token()

    r = client.get(auth.url_change_password)
    assert 'Change password' in r.data
    assert 'current password' in r.data

    r = client.post(auth.url_change_password, data=dict(
        np1='lalala', np2='lalala', _csrf_token=csrf_token))
    assert 'Wrong current password' in r.data

    r = client.post(auth.url_change_password, data=dict(
        password='lalala', np1='lalala', np2='lalala', _csrf_token=csrf_token))
    assert 'Wrong current password' in r.data

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='a', np2='a', _csrf_token=csrf_token))
    assert 'too short' in r.data

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalalala', np2='a', _csrf_token=csrf_token))
    assert 'doesn\'t match' in r.data

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalala', np2='lalala'))
    assert r.status == '403 FORBIDDEN'

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalala', np2='lalala', _csrf_token=csrf_token))
    assert 'Password updated' in r.data
    assert user.has_password('lalala')


