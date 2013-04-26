# -*- coding: utf-8 -*-
import logging
from time import time
from uuid import uuid4
from functools import wraps

from passlib import hash as ph
from passlib.context import CryptContext
from passlib.exc import MissingBackendError

from . import utils, views, wsgi
from .exceptions import *
from .models import extend_user_model, extend_role_model


VALID_HASHERS = ['bcrypt', 'pbkdf2_sha512', 'sha512_crypt']

DEPRECATED_HASHERS = [
    'django_pbkdf2_sha256', 'django_pbkdf2_sha1', 'django_bcrypt',
    'django_salted_sha1', 'django_salted_md5', 'django_des_crypt',
    'hex_sha512', 'hex_sha256', 'hex_sha1', 'hex_md5', 'hex_md4']

MIN_SECRET_LENGTH = 15


class Auth(object):

    defaults = {
        'session_key': '_uhmac',
        'csrf_key': '_csrf_token',
        'csrf_header': 'X-CSRFToken',
        'redirect_key': 'next',

        'sign_in_redirect': '/',
        'sign_out_redirect': '/',

        'url_sign_in': '/sign-in/',
        'url_sign_out': '/sign-out/',
        'url_reset_password': '/reset-password/',
        'url_change_password': '/change-password/',

        'template_sign_in': 'auth/sign_in.html',
        'template_sign_out': None,
        'template_reset': 'auth/reset_password.html',
        'template_reset_email': 'auth/reset_password_email.html',
        'template_change_password': 'auth/change_password.html',

        'password_minlen': 5,
        'token_life': 3 * 60, #minutes
        'update_hash': True,

        'wsgi': wsgi.werkzeug,
    }

    def __init__(self, secret_key, pepper=u'', hash=None, rounds=None, 
            db=None, UserMixin=None, RoleMixin=None, roles=False, 
            logger=None, session=None, request=None,
            render=None, send_email=None, **kwargs):

        self.secret_key = str(secret_key)
        assert len(self.secret_key) >= MIN_SECRET_LENGTH, \
            "`secret_key` must be at least {0} chars long".format(MIN_SECRET_LENGTH)
        self.pepper = pepper
        self.db = db
        
        self.session = session or {}
        self.request = request
        self.render = render or utils.default_render
        self.send_email = send_email or utils.default_send_email

        self.backends = [
            self.auth_password,
            self.auth_token,
        ]
        self._set_hasher(hash, rounds)
        if db:
            self.User = extend_user_model(self, UserMixin)
            if roles or RoleMixin:
                self.Role = extend_role_model(self, self.User, RoleMixin)
        self.logger = logger or logging.getLogger(__name__)

        for key, val in self.defaults.items():
            setattr(self, key, kwargs.get(key, self.defaults[key]))

    def _set_hasher(self, hash, rounds):
        hash = self._get_best_hash(hash)
        if hash not in VALID_HASHERS:
            raise WrongHashAlgorithm

        hasher = getattr(ph, hash)
        rounds = min(max(rounds or hasher.min_rounds, hasher.min_rounds),
            hasher.max_rounds)
        op = {
            'schemes': VALID_HASHERS + DEPRECATED_HASHERS,
            'deprecated': DEPRECATED_HASHERS,
            'default': hash,
            hash + '__default_rounds': rounds
        }
        self.hasher = CryptContext(**op)
        # For testing
        self.hash = hash.replace('_', '-')
        self.rounds = rounds

    def _get_best_hash(self, hash):
        hash = hash or 'bcrypt'
        hash = hash.replace('-', '_')
        if hash == 'bcrypt':
            try:
                utils.test_hasher(ph.bcrypt)    
            except MissingBackendError:
                return 'pbkdf2_sha512'
        return hash

    def prepare_password(self, secret):
        return self.pepper + unicode(secret)

    def hash_password(self, secret):
        secret = self.prepare_password(secret)
        hashed = self.hasher.encrypt(secret)
        return hashed

    def password_is_valid(self, secret, hashed):
        secret = self.prepare_password(secret)
        try:
            return self.hasher.verify(secret, hashed)
        except ValueError, e:
            return False

    def verify_and_update(self, secret, hashed):
        secret = self.prepare_password(secret)
        return self.hasher.verify_and_update(secret, hashed)

    def authenticate(self, credentials):
        for backend in self.backends:
            user = backend(credentials)
            if user:
                return user
        return None

    def auth_password(self, credentials):
        login = credentials.get('login')
        secret = credentials.get('password')
        if login is None or secret is None:
            return None

        user = self.User.by_login(login)
        if not user:
            self.logger.info('User `{0}` not found'.format(login))
            return None

        valid, new_hash = self.verify_and_update(secret, user.password)
        if not valid:
            self.logger.info('Invalid password for user `{0}`'.format(login))
            return None

        if self.update_hash and new_hash:
            user._password = new_hash
            self.db.session.commit()
            self.logger.info('Hash updated for user `{0}`'.format(login))
        return user

    def auth_token(self, credentials):
        token = credentials.get('token')
        if token is None:
            return None
        try:
            timestamp, uid = utils.split_token(str(token))
        except ValueError:
            self.logger.warning('Invalid auth token format')
            return None

        user = self.User.by_id(uid)
        if not user:
            self.logger.warning('Tampered auth token? uid `{0} not found'
                .format(uid[:20]))
            return None

        valid = user.get_token(timestamp) == token
        not_expired = timestamp + self.token_life >= int(time())
        if valid and not_expired:
            return user
        self.logger.warning('Invalid auth token')
        return None

    def get_user(self, session=None):
        if session is None:
            session = self.session
        user = None
        uhmac = session.get(self.session_key)
        if uhmac:
            try:
                uid = utils.split_uhmac(uhmac)
                user = self.User.by_id(uid)
                if not user or uhmac != user.get_uhmac():
                    raise ValueError
            except ValueError, e:
                self.logger.warning('Tampered uhmac?')
                user = None
                self.logout(session)
        return user

    def login(self, user, session=None):
        """Sets the current user UID in the session.

        Instead of just storing the user's id, it generates a hash from the
        password *salt*. That way, an admin or the user herself can invalidate
        the login in other computers just by changing (or re-saving)
        her password.

        """
        self.logger.info('User `{0}` logged in'.format(user.login))
        if session is None:
            session = self.session
        session[self.session_key] = user.get_uhmac()

    def logout(self, session=None):
        if session is None:
            session = self.session
        for key in session.keys():
            session.pop(key, None)

    def get_csrf_token(self, session=None):
        if session is None:
            session = self.session
        csrf_token = session.get(self.csrf_key)
        if not csrf_token:
            self.logger.debug('New CSFR token')
            csrf_token = self.make_csrf_token()
            session[self.csrf_key] = csrf_token
        return csrf_token

    def make_csrf_token(self):
        return str(uuid4()).replace('-', '')

    def protected(self, *tests, **options):
        """Factory of decorators for limit the access to views.
        
        tests
        :   One or more functions that takes the args and kwargs of the
            function and returns either `True` or `False`.
            All test must return True to show the view.

        Options:

        url_sign_in
        :   If any required condition fail, redirect to this place.
            Override the default URL. This can also be a callable.
        
        csrf
        :   If `True` (the default), the decorator will check the value
            of the CSFR token for POST or PUT requests, or for all requests if
            `force_csrf` is also True.
            If `False`, the value of the CSFR token will not be checked.

        role
        :   Test for the user having a role with this name.
        roles
        :   Test for the user having **any** role in this list of names.

        """
        csrf = bool(options.get('csrf', True))
        force_csrf = bool(options.get('force_csrf', False))
        roles = options.get('roles') or []
        role = options.get('role')
        if role:
            roles.append(role)

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                request = options.get('request') or self.request or \
                    args and args[0]
                url_sign_in = self._get_url_sign_in(request, options)

                user = self.get_user()
                if not user:
                    return self._login_required(request, url_sign_in)

                if hasattr(user, 'has_role') and roles:
                    if not user.has_role(*roles):
                        self.logger.info('User `{0}`: has_role fail'
                            .format(user.login))
                        return self._login_required(request, url_sign_in)

                for test in tests:
                    test_pass = test(*args, **kwargs)
                    if not test_pass:
                        self.logger.info('User `{0}`: test fail'
                            .format(user.login))
                        return self._login_required(request, url_sign_in)

                if (csrf and
                        (self.wsgi.is_put_or_post(request) or force_csrf) and
                        not self.csrf_token_is_valid(request)):
                    self.logger.info('User `{0}`: invalid CSFR token'
                        .format(user.login))
                    return self.wsgi.raise_forbidden("CSFR token isn't valid")

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def csrf_token_is_valid(self, request, session=None):
        token = self._get_csrf_token_from_request(request)
        return token and self._csrf_token_is_valid(token, session)

    def _csrf_token_is_valid(self, token, session=None):
        return self.get_csrf_token(session=session) == token

    def _login_required(self, request, url_sign_in):
        self.session[self.redirect_key] = self.wsgi.get_full_path(request)
        return self.wsgi.redirect(url_sign_in)

    def _get_url_sign_in(self, request, options):
        url_sign_in = options.get('url_sign_in') or self.url_sign_in
        if callable(url_sign_in):
            url_sign_in = url_sign_in(request)
        return url_sign_in or '/'

    def _get_csrf_token_from_request(self, request):
        return self.wsgi.get_from_params(request, self.csrf_key) or \
            self.wsgi.get_from_headers(request, self.csrf_header)

    def auth_sign_in(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_in(self, request, self.session,
            *args, **kwargs)

    def auth_sign_out(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_out(self, request, **kwargs)

    def auth_reset_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.reset_password(self, request, **kwargs)

    def auth_change_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.change_password(self, request, **kwargs)

