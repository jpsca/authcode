# -*- coding: utf-8 -*-
from __future__ import print_function

import authcode
from flask import Flask, request
from orm import SQLAlchemy

from helpers import *


def test_pop_next_url():
    auth = authcode.Auth(SECRET_KEY)
    session = {auth.redirect_key: '/abc'}
    assert authcode.views.pop_next_url(auth, request, session) == '/abc'

    auth.sign_in_redirect = '/test'
    assert authcode.views.pop_next_url(auth, request, {}) == auth.sign_in_redirect

    auth.sign_in_redirect = None
    assert authcode.views.pop_next_url(auth, request, {}) == '/'


def get_flask_app(roles=False, **kwargs):
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, roles=roles, **kwargs)
    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    app = Flask('test')
    app.secret_key = os.urandom(32)
    app.testing = True

    authcode.setup_for_flask(auth, app)
    auth.session = {}
    return auth, app, user


def test_login_view():
    auth, app, user = get_flask_app()
    client = app.test_client()

    r = client.get(auth.url_sign_in)
    assert 'Sign in' in r.data

    r = client.post(auth.url_sign_in)
    assert 'Wrong' not in r.data

    data = {
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert 'Wrong' in r.data
    assert auth.session_key not in auth.session


def test_login_wrong_credentials():
    auth, app, user = get_flask_app()
    client = app.test_client()

    data = {
        'login': 'xxx',
        'password': 'zzz',
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert 'Wrong' in r.data
    assert auth.session_key not in auth.session


def test_login_right_credentials():
    auth, app, user = get_flask_app()
    client = app.test_client()

    data = {
        'login': user.login,
        'password': 'foobar',
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert r.status == '303 SEE OTHER'
    assert auth.session_key in auth.session


def test_login_redirect_if_already_logged_in():
    auth, app, user = get_flask_app()
    client = app.test_client()
    auth.login(user)

    auth.session[auth.redirect_key] = 'http://google.com'
    r = client.get(auth.url_sign_in)
    assert r.status == '303 SEE OTHER'


def test_redirect_after_logout():
    auth, app, user = get_flask_app()
    client = app.test_client()
    auth.login(user)

    url = '{0}?_csrf_token={1}'.format(auth.url_sign_out, auth.get_csrf_token())
    r = client.get(url)
    assert r.status == '303 SEE OTHER'
    assert auth.session_key not in auth.session


def test_reset_password():
    auth, app, user = get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()

    r = client.get(auth.url_reset_password)
    print(r.data)
    assert 'Reset password' in r.data


def test_reset_password_wrong_account():
    auth, app, user = get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()

    data = dict(login=u'nn', _csrf_token=auth.get_csrf_token())
    r = client.post(auth.url_reset_password, data=data)
    print(r.data)
    assert 'We couldn\'t find an account for that username' in r.data


def test_reset_password_email_sent():
    auth, app, user = get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    token = user.get_token()
    data = dict(login=user.login, _csrf_token=auth.get_csrf_token())
    r = client.post(auth.url_reset_password, data=data)
    assert 'Please check your inbox' in r.data
    print(log)
    assert auth.url_reset_password + token + '/' in log[0]


def test_reset_password_wrong_token():
    auth, app, user = get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()
    r = client.get(auth.url_reset_password + 'xxx/')
    print(r.data)
    assert 'Something is wrong' in r.data


def test_reset_password_good_token():
    auth, app, user = get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    token = user.get_token()
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
    csrf_token = auth.get_csrf_token()

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

