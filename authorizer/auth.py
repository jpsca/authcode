# -*- coding: utf-8 -*-
import logging
from time import time
from uuid import uuid4
from functools import wraps

from passlib import hash as ph
from passlib.context import CryptContext
from passlib.exc import MissingBackendError

from . import views, utils, compat
from .exceptions import *
from .models import get_user_model, get_user_role_model


VALID_HASHERS = ['bcrypt', 'pbkdf2_sha512', 'sha512_crypt']

DEPRECATED_HASHERS = ['django_salted_sha1', 'django_salted_md5',
    'django_des_crypt', 'hex_sha512', 'hex_sha256', 'hex_sha1', 'hex_md5']

MIN_SECRET_LENGTH = 20


class Auth(object):

    session_key = '_uhmac'
    csrf_key = '_csrf_token'
    csrf_header = 'X-CSRFToken'
    redirect_key = 'next'

    sign_in_redirect = '/'
    sign_out_redirect = '/'

    url_sign_in = '/sign-in/'
    url_sign_out = '/sign-out/'
    url_reset_password = '/reset-password/'
    url_change_password = '/change-password/'

    template_sign_in = 'auth/sign_in.html'
    template_sign_out = None
    template_reset = 'auth/reset_password.html'
    template_reset_email = 'auth/reset_password_email.html'
    template_change_password = 'auth/change_password.html'

    password_minlen = 5

    def __init__(self, secret_key, pepper=u'', db=None, roles=False, 
            hash=None, rounds=None, update_hash=True, token_life=3*60,
            session=None, request=None, render=None, send_email=None,
            logger=None):
        self.secret_key = str(secret_key)
        assert len(self.secret_key) >= MIN_SECRET_LENGTH, \
            "`secret_key` must be at least %s chars long" % MIN_SECRET_LENGTH
        self.pepper = pepper
        self.db = db
        
        self.session = session or {}
        self.request = request
        self.render = render or utils.default_render
        self.send_email = send_email or utils.default_send_email

        self.update_hash = update_hash
        self.token_life = float(token_life) * 60
        assert self.token_life >= 0, \
            "`token_life` must be a positive number of minutes"
        self.backends = [
            self.auth_password,
            self.auth_token,
        ]
        self._set_hasher(hash, rounds)
        if db:
            self.User = get_user_model(self)
            if roles:
                self.UserRole = get_user_role_model(self, self.User)
        self.logger = logger or logging.getLogger(__name__)

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
            self.logger.info('User `%s` not found' % (login,))
            return None

        valid, new_hash = self.verify_and_update(secret, user.password)
        if not valid:
            self.logger.info('Invalid password')
            return None

        if self.update_hash and new_hash:
            user._password = new_hash
            self.db.session.commit()
            self.logger.info('Hash updated for user `%s`' % (login,))
        return user

    def auth_token(self, credentials):
        token = credentials.get('token')
        if token is None:
            return None
        try:
            timestamp, uid = utils.split_token(str(token))
        except ValueError:
            self.logger.info('Invalid auth token format')
            return None

        user = self.User.by_id(uid)
        if not user:
            self.logger.info('Tampered auth token? UID %s not found' % (uid,))
            return None

        valid = user.get_token(timestamp) == token
        not_expired = timestamp <= int(time()) + self.token_life
        if valid and not_expired:
            return user
        self.logger.info('Invalid auth token')
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
                self.logger.info('Tampered uhmac?')
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
        self.logger.debug('User `%s` log in' % (user.login, ))
        if session is None:
            session = self.session
        session[self.session_key] = user.get_uhmac()

    def logout(self, session=None):
        if session is None:
            session = self.session
        session.pop(self.session_key, None)
        if hasattr(session, 'invalidate'):
            session.invalidate()

    def get_csfr_token(self, session=None):
        if session is None:
            session = self.session
        csrf_token = session.get(self.csrf_key)
        if not csrf_token:
            self.logger.debug('New CSFR token')
            csrf_token = self.make_csrf_token()
            session[self.csrf_key] = csrf_token
        return csrf_token

    def make_csrf_token(self):
        return str(uuid4())

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
            of the CSFR token for POST request or for all requests if
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
                url_sign_in = self._get_url_sign_in(options)
                request = options.get('request') or self.request or \
                    args and args[0]

                user = self.get_user()
                if not user:
                    return self._login_required(request, url_sign_in)

                if hasattr(user, 'has_role') and roles:
                    if not user.has_role(*roles):
                        self.logger.info('User `%s`: has_role fail' %
                            (user.login, ))
                        return self._login_required(request, url_sign_in)

                for test in tests:
                    test_pass = test(*args, **kwargs)
                    if not test_pass:
                        self.logger.info('User `%s`: test fail' %
                            (user.login, ))
                        return self._login_required(request, url_sign_in)

                if csrf and (force_csrf or compat.is_post(request)):
                    token = self._get_csrf_token_from_request(request)
                    if not token or not self.csrf_token_is_valid(token):
                        self.logger.info('User `%s`: invalid CSFR token' %
                            (user.login, ))
                        return compat.raise_forbidden("CSFR token isn't valid")

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def csrf_token_is_valid(self, token, session=None):
        return self.get_csfr_token(session=session) == token

    def _login_required(self, request, url_sign_in):
        self.session[self.redirect_key] = compat.get_current_url(request)
        return compat.redirect(url_sign_in)

    def _get_url_sign_in(self, options):
        url_sign_in = options.get('url_sign_in') or self.url_sign_in
        if callable(url_sign_in):
            url_sign_in = url_sign_in()
        return url_sign_in or '/'

    def _get_csrf_token_from_request(self, request):
        return compat.get_from_values(request, self.csrf_key) or \
            compat.get_from_headers(request, self.csrf_header)

    def view_sign_in(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_in(self, request, self.session,
            *args, **kwargs)

    def view_sign_out(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.sign_out(self, request, **kwargs)

    def view_reset_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.reset_password(self, request, **kwargs)

    def view_change_password(self, *args, **kwargs):
        request = self.request or kwargs.get('request') or args and args[0]
        return views.change_password(self, request, **kwargs)

    def setup_for_flask(self, app, views=True, send_email=None):
        utils.setup_for_flask(self, app, views=views, send_email=send_email)

