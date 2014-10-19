# coding=utf-8
from __future__ import print_function

from passlib import hash as ph
from passlib.context import CryptContext

from . import utils, wsgi
from .auth_authentication_mixin import AuthenticationMixin
from .auth_authorization_mixin import AuthorizationMixin
from .auth_views_mixin import ViewsMixin
from .constants import (
    DEFAULT_HASHER, VALID_HASHERS, DEPRECATED_HASHERS, MIN_SECRET_LENGTH,
    WRONG_HASH_MESSAGE
)
from .models import extend_user_model, extend_role_model


class WrongHashAlgorithm(Exception):
    pass


class Auth(AuthenticationMixin, AuthorizationMixin, ViewsMixin):

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

        'views': 'sign_in sign_out reset_password change_password'.split(' '),

        'template_sign_in': None,
        'template_sign_out': None,
        'template_reset': None,
        'template_reset_email': None,
        'template_change_password': None,
        'reset_email_subject': u'Reset your password',

        # Should logins be case insensitive?
        'case_insensitive': True,

        'password_minlen': 5,
        'token_life': 3 * 60,  # minutes
        'update_hash': True,

        'wsgi': wsgi.werkzeug,
    }

    def __init__(self, secret_key, pepper=u'', hash=DEFAULT_HASHER, rounds=None,
                 db=None, UserMixin=None, RoleMixin=None, roles=False,
                 session=None, request=None,
                 render=None, send_email=None, **kwargs):

        self.secret_key = str(secret_key)
        assert len(self.secret_key) >= MIN_SECRET_LENGTH, \
            "`secret_key` must be at least {0} chars long".format(MIN_SECRET_LENGTH)
        self.pepper = pepper
        self.db = db

        self.session = session or {}
        self.request = request
        self.render = render or self.default_render
        self.send_email = send_email or utils.default_send_email

        self.backends = [
            self.auth_password,
            self.auth_token,
        ]
        self.set_hasher(hash, rounds)
        if db:
            self.User = extend_user_model(self, UserMixin)
            if roles or RoleMixin:
                self.Role = extend_role_model(self, self.User, RoleMixin)

        for key, val in self.defaults.items():
            setattr(self, key, kwargs.get(key, self.defaults[key]))

    def set_hasher(self, hash, rounds=None):
        """Updates the has algorithm and, optionally, the number of rounds
        to use.
        :raises: `~WrongHashAlgorithm` if new algorithm isn't one of the three
            recomended options.
        """
        hash = hash.replace('-', '_')
        if hash not in VALID_HASHERS:
            raise WrongHashAlgorithm(WRONG_HASH_MESSAGE)
        hasher = getattr(ph, hash)
        utils.test_hasher(hasher)

        default_rounds = getattr(hasher, 'default_rounds', 1)
        min_rounds = getattr(hasher, 'min_rounds', 1)
        max_rounds = getattr(hasher, 'max_rounds', float("inf"))
        rounds = min(max(rounds or default_rounds, min_rounds), max_rounds)
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
