# coding=utf-8
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
        'views_prefix': u'',

        'template_sign_in': None,
        'template_sign_out': None,
        'template_reset': None,
        'template_reset_email': None,
        'template_change_password': None,
        'reset_email_subject': u'Reset your password',

        # Should logins be case insensitive?
        'case_insensitive': True,

        # Prevent session fixation attacks, but
        # block having multiple logins at the same time.
        # If you set this to False, make sure to delete on logout all user's
        # information stored in the session.
        'clear_session_on_logout': True,

        'password_minlen': 5,
        'token_life': 3 * 60,  # minutes
        'update_hash': True,

        'wsgi': wsgi.werkzeug,
        'user_name': 'user',

        'pepper': u'',  # considering deprecating it
    }

    def __init__(self, secret_key, db=None, hash=DEFAULT_HASHER, rounds=None,
                 UserMixin=None, RoleMixin=None,
                 users_model_name='User', roles_model_name='Role',
                 roles=False, lazy_roles=True,
                 session=None, request=None, **kwargs):

        self.secret_key = str(secret_key)
        assert len(self.secret_key) >= MIN_SECRET_LENGTH, \
            "`secret_key` must be at least {0} chars long".format(MIN_SECRET_LENGTH)
        self.set_hasher(hash, rounds)

        self.db = db
        if db:
            self.users_model_name = users_model_name
            self.lazy_roles = lazy_roles
            roles = roles or RoleMixin
            self.User = extend_user_model(self, UserMixin, roles=roles)
            if roles:
                self.roles_model_name = roles_model_name
                self.Role = extend_role_model(self, self.User, RoleMixin)

        self.backends = [
            self.auth_password,
            self.auth_token,
        ]

        for key, val in self.defaults.items():
            setattr(self, key, kwargs.get(key, self.defaults[key]))

        # backwards compatibility
        self.session = session or {}
        self.request = request

    def set_hasher(self, hash, rounds=None):
        """Updates the has algorithm and, optionally, the number of rounds
        to use.

        Raises:
            `~WrongHashAlgorithm` if new algorithm isn't one of the three
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
