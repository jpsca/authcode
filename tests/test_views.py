# coding=utf-8
from __future__ import print_function
import os

from authcode._compat import to_unicode
from authcode.views import pop_next_url
from flask import Flask, request
from sqlalchemy_wrapper import SQLAlchemy
import authcode

from helpers import SECRET_KEY


class Session(dict):
    saved = 0

    def save(self):
        self.saved += 1


def _get_flask_app(roles=False, **kwargs):
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(
        SECRET_KEY, db=db, roles=roles, password_minlen=3, **kwargs)
    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)

    user2 = User(login=u'foo', password='bar')
    db.add(user2)
    db.commit()

    app = Flask('test')
    app.secret_key = os.urandom(32)
    app.testing = True

    @app.route('/protected/')
    @auth.protected()
    def protected():
        return u'Welcome'

    authcode.setup_for_flask(auth, app)
    auth.session = {}
    return auth, app, user


def test_pop_next_url():
    auth = authcode.Auth(SECRET_KEY)
    session = {auth.redirect_key: '/abc/'}
    next_url = pop_next_url(auth, request, session)
    assert next_url == '/abc/'

    auth.sign_in_redirect = '/test/'
    next_url = pop_next_url(auth, request, {})
    assert next_url == auth.sign_in_redirect

    auth.sign_in_redirect = lambda request: '/dynamic/'
    next_url = pop_next_url(auth, request, {})
    assert next_url == '/dynamic/'

    auth.sign_in_redirect = None
    next_url = pop_next_url(auth, request, {})
    assert next_url == '/'


def test_login_view():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    r = client.get(auth.url_sign_in)
    assert u'Sign in' in to_unicode(r.data)

    r = client.post(auth.url_sign_in)
    assert u'<!-- ERROR -->' not in to_unicode(r.data)

    data = {
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert u'<!-- ERROR -->' in to_unicode(r.data)
    assert auth.session_key not in auth.session


def test_login_wrong_credentials():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    data = {
        'login': 'xxx',
        'password': 'zzz',
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert u'<!-- ERROR -->' in to_unicode(r.data)
    assert auth.session_key not in auth.session


def test_login_very_wrong_credentials():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    data = {
        'login': None,
        'password': int,
        '_csrf_token': auth.get_csrf_token(),
    }
    r = client.post(auth.url_sign_in, data=data)
    assert u'<!-- ERROR -->' in to_unicode(r.data)
    assert auth.session_key not in auth.session


def test_login_right_credentials():
    auth, app, user = _get_flask_app()
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
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)

    auth.session[auth.redirect_key] = 'http://google.com'
    r = client.get(auth.url_sign_in)
    assert r.status == '303 SEE OTHER'


def test_logout_before_login_again():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    data = {
        'login': user.login,
        'password': 'foobar',
        '_csrf_token': auth.get_csrf_token(),
    }
    client.post(auth.url_sign_in, data=data)
    assert auth.session_key in auth.session
    uhmac1 = auth.session[auth.session_key]

    data = {
        'login': 'foo',
        'password': 'bar',
        '_csrf_token': auth.get_csrf_token(),
    }
    client.post(auth.url_sign_in, data=data)
    assert auth.session_key in auth.session
    uhmac2 = auth.session[auth.session_key]
    assert uhmac1 != uhmac2


def test_unprotected_logout():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)

    r = client.get(auth.url_sign_out)
    assert auth.session_key in auth.session  # still signed in
    assert r.status == '303 SEE OTHER'

    r = client.post(auth.url_sign_out)
    assert auth.session_key in auth.session  # still signed in
    assert r.status == '303 SEE OTHER'


def test_redirect_after_logout():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    auth.login(user)
    url = '{0}?_csrf_token={1}'.format(auth.url_sign_out, auth.get_csrf_token())
    r = client.get(url)
    assert r.status == '303 SEE OTHER'
    assert auth.session_key not in auth.session

    auth.login(user)
    auth.sign_out_redirect = '/test/'
    url = '{0}?_csrf_token={1}'.format(auth.url_sign_out, auth.get_csrf_token())
    r = client.get(url)
    assert r.status == '303 SEE OTHER'
    assert r.location.endswith('/test/')
    assert auth.session_key not in auth.session

    auth.login(user)
    auth.sign_out_redirect = lambda request: '/dynamic/'
    url = '{0}?_csrf_token={1}'.format(auth.url_sign_out, auth.get_csrf_token())
    r = client.get(url)
    assert r.status == '303 SEE OTHER'
    assert r.location.endswith('/dynamic/')
    assert auth.session_key not in auth.session


def test_reset_password():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()

    r = client.get(auth.url_reset_password)
    data = to_unicode(r.data)
    print(data)
    assert u'Reset password' in data


def test_reset_password_wrong_account():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()

    data = dict(login=u'nn', _csrf_token=auth.get_csrf_token())
    r = client.post(auth.url_reset_password, data=data)
    data = to_unicode(r.data)
    print(data)
    assert u'<!-- ERROR WRONG USER -->' in data


def test_reset_password_email_sent():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    token = user.get_token()
    data = dict(login=user.login, _csrf_token=auth.get_csrf_token())
    r = client.post(auth.url_reset_password, data=data)
    data = to_unicode(r.data)
    assert u'<!-- EMAIL SENT -->' in data
    print(log)
    assert u'{0}{1}'.format(auth.url_reset_password, token[:5]) in log[0]


def test_reset_password_default_emailer():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    data = dict(login=user.login, _csrf_token=auth.get_csrf_token())
    resp = client.post(auth.url_reset_password, data=data)
    data = to_unicode(resp.data)
    assert u'<!-- EMAIL SENT -->' in data


def test_reset_password_wrong_token():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    user.get_token()
    r = client.get(auth.url_reset_password + 'xxx/')
    data = to_unicode(r.data)
    print(data)
    assert u'<!-- ERROR WRONG TOKEN -->' in data


def test_reset_password_good_token():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    log = []

    def send_email(user, subject, msg):
        log.append(msg)

    auth.send_email = send_email
    token = user.get_token()
    r = client.get(auth.url_reset_password + token + '/')
    data = to_unicode(r.data)
    assert auth.session_key in auth.session
    assert u'Change password' in data
    assert u'current password' not in data

    r = client.get(auth.url_reset_password)
    assert r.status == '303 SEE OTHER'


def test_change_password_redir():
    auth, app, user = _get_flask_app()
    client = app.test_client()

    r = client.get(auth.url_change_password)
    assert r.status == '303 SEE OTHER'

    auth.login(user)

    r = client.get(auth.url_change_password)
    data = to_unicode(r.data)
    assert u'Change password' in data
    assert u'current password' in data


def test_change_password_no_current_password():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    r = client.post(auth.url_change_password, data=dict(
        np1='lalala', np2='lalala', _csrf_token=csrf_token))
    data = to_unicode(r.data)
    assert u'<!-- ERROR FAIL -->' in data


def test_change_password_wrong_current_password():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    r = client.post(auth.url_change_password, data=dict(
        password='lalala', np1='lalala', np2='lalala', _csrf_token=csrf_token))
    data = to_unicode(r.data)
    assert u'<!-- ERROR FAIL -->' in data


def test_change_password_too_short():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='a', np2='a', _csrf_token=csrf_token))
    data = to_unicode(r.data)
    assert u'<!-- ERROR TOO SHORT -->' in data


def test_change_password_too_long():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    HUGE_PASSWORD = 'x' * 5000
    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1=HUGE_PASSWORD, np2=HUGE_PASSWORD, _csrf_token=csrf_token))
    data = to_unicode(r.data)
    assert u'<!-- ERROR TOO LONG -->' in data


def test_change_password_mismatch():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalalala', np2='a', _csrf_token=csrf_token))
    data = to_unicode(r.data)
    print(data)
    assert u'<!-- ERROR MISMATCH -->' in data


def test_change_password_no_csrf():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalala', np2='lalala'))
    assert r.status == '403 FORBIDDEN'


def test_change_password_ok():
    auth, app, user = _get_flask_app()
    client = app.test_client()
    auth.login(user)
    csrf_token = auth.get_csrf_token()

    r = client.post(auth.url_change_password, data=dict(
        password='foobar', np1='lalala', np2='lalala', _csrf_token=csrf_token))
    data = to_unicode(r.data)
    assert u'<!-- PASSWORD UPDATED -->' in data
    assert user.has_password('lalala')


def test_custom_templates():
    db = SQLAlchemy('sqlite:///:memory:')
    options = {
        'template_sign_in': 'sign-in.html',
        'template_sign_out': 'sign-out.html',
        'template_reset': 'reset-password.html',
        'template_reset_email': 'reset-password-email.html',
        'template_change_password': 'change-password.html',
    }
    inbox = []

    def send_email(user, subject, msg):
        inbox.append(msg)

    auth = authcode.Auth(SECRET_KEY, db=db, **options)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    custom_templates = os.path.join(
        os.path.dirname(__file__),
        'custom_templates'
    )
    app = Flask('test', template_folder=custom_templates)
    app.secret_key = os.urandom(32)
    app.testing = True
    authcode.setup_for_flask(auth, app, send_email=send_email)
    auth.session = {}
    client = app.test_client()

    resp = client.get(auth.url_sign_in)
    assert resp.data == b'OK SIGN IN'

    resp = client.get(auth.url_reset_password)
    assert resp.data == b'OK RESET PASSWORD'

    data = dict(login=user.login, _csrf_token=auth.get_csrf_token())
    resp = client.post(auth.url_reset_password, data=data)
    assert inbox[0] == 'OK RESET PASSWORD EMAIL'

    auth.login(user)

    resp = client.get(auth.url_change_password)
    assert resp.data == b'OK CHANGE PASSWORD'

    url = '{0}?_csrf_token={1}'.format(auth.url_sign_out, auth.get_csrf_token())
    resp = client.get(url)
    assert resp.data == b'OK SIGN OUT'


def test_pop_next_url_save():
    auth = authcode.Auth(SECRET_KEY)
    session = Session({auth.redirect_key: '/abc/'})
    next_url = pop_next_url(auth, request, session)
    assert next_url == '/abc/'
    assert session.saved == 1


def test_login_logout_save():
    auth, app, user = _get_flask_app()
    auth.session = Session()
    client = app.test_client()

    auth.session.saved = 0

    resp = client.get('/protected/')
    print(resp.data)
    assert auth.session_key not in auth.session
    assert auth.redirect_key in auth.session
    assert auth.session.saved == 1

    data = {
        'login': user.login,
        'password': 'foobar',
        '_csrf_token': auth.get_csrf_token(),
    }
    client.post(auth.url_sign_in, data=data)
    assert auth.session_key in auth.session
    assert auth.session.saved == 4

    data = {
        '_csrf_token': auth.get_csrf_token(),
    }
    client.post(auth.url_sign_out, data=data)
    assert auth.session_key not in auth.session
    assert auth.session.saved == 5
