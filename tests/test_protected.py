# coding=utf-8
from __future__ import print_function
import os

import authcode
from authcode._compat import to_native
from flask import Flask, Blueprint
import pytest
from sqlalchemy_wrapper import SQLAlchemy

from helpers import SECRET_KEY


def get_flask_app(roles=False, views=None, **kwargs):
    db = SQLAlchemy('sqlite:///:memory:')
    views = views or []
    auth = authcode.Auth(SECRET_KEY, db=db, roles=roles, views=views, **kwargs)
    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    app = Flask('test')
    app.secret_key = os.urandom(32)
    app.testing = True
    authcode.setup_for_flask(auth, app)

    @app.route('/login/')
    def login():
        user = User.by_id(1)
        auth.login(user)
        return 'login'

    @app.route('/logout/')
    def logout():
        auth.logout()
        return 'logout'

    return auth, app, user


def test_protected():
    auth, app, user = get_flask_app()
    client = app.test_client()

    @app.route('/admin/')
    @auth.protected()
    def admin():
        return ''

    resp = client.get('/admin/')
    assert resp.status == '303 SEE OTHER'

    client.get('/login/')
    resp = client.get('/admin/')
    assert resp.status == '200 OK'


def test_signin_url():
    auth, app, user = get_flask_app()
    auth.url_sign_in = '/sign-in/'
    client = app.test_client()

    @app.route('/admin1/')
    @auth.protected()
    def admin1():
        return ''

    @app.route('/admin2/')
    @auth.protected(url_sign_in='/users/sign-in/')
    def admin2():
        return ''

    resp = client.get('/admin1/')
    assert resp.headers.get('location') == 'http://localhost/sign-in/'

    resp = client.get('/admin2/')
    assert resp.headers.get('location') == 'http://localhost/users/sign-in/'

    auth.url_sign_in = lambda request: '/login/'
    resp = client.get('/admin1/')
    assert resp.headers.get('location') == 'http://localhost/login/'


def test_protected_role():
    auth, app, user = get_flask_app(roles=True)
    client = app.test_client()

    @app.route('/admin1/')
    @auth.protected(role='admin')
    def admin1():
        return 'admin1'

    @app.route('/admin2/')
    @auth.protected(roles=['editor', 'admin'])
    def admin2():
        return 'admin2'

    client.get('/login/')

    resp = client.get('/admin1/')
    assert resp.status == '403 FORBIDDEN'
    resp = client.get('/admin2/')
    assert resp.status == '403 FORBIDDEN'

    user.add_role('admin')
    auth.db.commit()
    client.get('/login/')

    resp = client.get('/admin1/?r=123/')
    assert resp.status == '200 OK'
    assert resp.data == b'admin1'

    resp = client.get('/admin2/?r=456/')
    print(user.roles.all())
    assert resp.status == '200 OK'
    assert resp.data == b'admin2'


def test_protected_csrf():
    auth, app, user = get_flask_app(roles=True)
    client = app.test_client()

    @app.route('/gettoken/')
    @auth.protected()
    def gettoken():
        return auth.get_csrf_token()

    @app.route('/delete/', methods=['GET', 'POST'])
    @auth.protected(csrf=True)
    def delete():
        return ''

    @app.route('/update/', methods=['GET', 'POST'])
    @auth.protected()
    def update():
        return ''

    @app.route('/whatever/', methods=['GET', 'POST'])
    @auth.protected(csrf=False)
    def whatever():
        return ''

    client.get('/login/')

    resp = client.get('/delete/')
    assert resp.status == '403 FORBIDDEN'

    resp = client.post('/update/')
    assert resp.status == '403 FORBIDDEN'

    resp = client.post('/whatever/')
    assert resp.status == '200 OK'

    resp = client.get('/gettoken/')
    token = to_native(resp.data)

    resp = client.get('/delete/?{0}={1}'.format(auth.csrf_key, token))
    assert resp.status == '200 OK'

    resp = client.post('/update/', data={auth.csrf_key: token})
    assert resp.status == '200 OK'

    resp = client.post('/update/', headers={'X-CSRFToken': token})
    assert resp.status == '200 OK'


def test_protected_tests():
    auth, app, user = get_flask_app(roles=True)
    client = app.test_client()

    log = []

    def test1(*args, **kwargs):
        log.append('test1')
        return True

    def test2(*args, **kwargs):
        log.append('test2')
        return True

    def fail(*args, **kwargs):
        log.append('fail')
        return False

    @app.route('/admin1/')
    @auth.protected(test1, test2)
    def admin1():
        return ''

    @app.route('/admin2/')
    @auth.protected(test1, fail, test2)
    def admin2():
        return ''

    client.get('/login/')
    resp = client.get('/admin1/')
    assert log == ['test1', 'test2']
    assert resp.status == '200 OK'

    resp = client.get('/admin2/')
    assert log == ['test1', 'test2', 'test1', 'fail']
    assert resp.status == '403 FORBIDDEN'


def test_protected_user_tests():
    auth, app, user = get_flask_app(roles=True)
    client = app.test_client()

    def echo(value, *args, **kwargs):
        return value

    user.echo = echo

    @app.route('/yay/')
    @auth.protected(echo=True)
    def yay():
        return 'yay'

    @app.route('/fail/')
    @auth.protected(echo=False)
    def fail():
        return 'fail'

    @app.route('/foobar/')
    @auth.protected(unknown=False)
    def foobar():
        return 'foobar'

    resp = client.get('/yay/')
    assert resp.status == '303 SEE OTHER'

    client.get('/login/')

    resp = client.get('/yay/')
    assert resp.status == '200 OK'

    resp = client.get('/fail/')
    assert resp.status == '403 FORBIDDEN'

    with pytest.raises(AttributeError):
        resp = client.get('/foobar/')


def test_replace_flask_route():
    auth, app, user = get_flask_app()
    auth.url_sign_in = '/login/'
    client = app.test_client()

    @app.route('/gettoken/')
    def gettoken():
        return auth.get_csrf_token()

    auth.replace_flask_route(app, csrf=True)

    @app.route('/page1/')
    def page1():
        return 'yay'

    @app.route('/page2/')
    def page2():
        return 'yay'

    resp = client.get('/gettoken/')
    token = to_native(resp.data)

    resp = client.get('/page1/')
    assert resp.status == '303 SEE OTHER'
    assert resp.headers.get('location') == 'http://localhost/login/'
    resp = client.get('/page2/')
    assert resp.status == '303 SEE OTHER'
    assert resp.headers.get('location') == 'http://localhost/login/'

    client.get('/login/')

    # Fail because it doesn't have a CSRF token
    resp = client.get('/page1/')
    assert resp.status == '403 FORBIDDEN'
    resp = client.get('/page2/')
    assert resp.status == '403 FORBIDDEN'

    resp = client.get('/page1/?{0}={1}'.format(auth.csrf_key, token))
    assert resp.status == '200 OK'
    resp = client.get('/page2/?{0}={1}'.format(auth.csrf_key, token))
    assert resp.status == '200 OK'
