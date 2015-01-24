# coding=utf-8
import logging
from time import time

from . import utils
from ._compat import to_unicode


class AuthenticationMixin(object):

    def prepare_password(self, secret):
        return u'{pepper}{secret}'.format(
            pepper=to_unicode(self.pepper),
            secret=to_unicode(secret)
        )

    def hash_password(self, secret):
        if secret is None:
            return None

        len_secret = len(secret)
        if len_secret < self.password_minlen:
            raise ValueError(
                'Password is too short. Must have at least {} chars long'.format(
                    self.password_minlen))
        if len_secret > self.password_maxlen:
            raise ValueError(
                'Password is too long. Must have at most {} chars long'.format(
                    self.password_maxlen))

        secret = self.prepare_password(secret)
        hashed = self.hasher.encrypt(secret)
        return hashed

    def password_is_valid(self, secret, hashed):
        if secret is None or hashed is None:
            return False

        # To help preventing denial-of-service via large passwords
        # See: https://www.djangoproject.com/weblog/2013/sep/15/security/
        if len(secret) > self.password_maxlen:
            return False

        secret = self.prepare_password(secret)
        try:
            return self.hasher.verify(secret, hashed)
        except ValueError:
            return False

    def authenticate(self, credentials):
        for backend in self.backends:
            user = backend(credentials)
            if user:
                return user
        return None

    def auth_password(self, credentials):
        logger = logging.getLogger(__name__)
        login = credentials.get('login')
        secret = credentials.get('password')
        if login is None or secret is None:
            return None

        user = self.User.by_login(login)
        if not user:
            logger.debug(u'User `{0}` not found'.format(login))
            return None

        if not user.password:
            logger.debug(u'User `{0}` has no password'.format(login))
            return None

        if not self.password_is_valid(secret, user.password):
            logger.debug(u'Invalid password for user `{0}`'.format(login))
            return None

        self._update_password_hash(secret, user)
        return user

    def _update_password_hash(self, secret, user):
        if not self.update_hash:
            return
        new_hash = self.hash_password(secret)
        if new_hash.split('$')[:3] == user.password.split('$')[:3]:
            return
        user.set_raw_password(new_hash)

    def auth_token(self, credentials, token_life=None):
        logger = logging.getLogger(__name__)
        token = credentials.get('token')
        if token is None:
            return None
        try:
            timestamp, uid = utils.split_token(str(token))
        except ValueError:
            logger.info(u'Invalid auth token format')
            return None

        token_life = token_life or self.token_life
        user = self.User.by_id(uid)
        if not user:
            logger.info(u'Tampered auth token? uid `{0} not found'.format(uid[:20]))
            return None

        valid = user.get_token(timestamp) == token
        not_expired = timestamp + token_life >= int(time())
        if valid and not_expired:
            return user
        logger.info(u'Invalid auth token')
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
            except ValueError:
                logger = logging.getLogger(__name__)
                logger.info(u'Tampered uhmac?')
                user = None
                self.logout(session)
        return user

    def login(self, user, remember=True, session=None):
        """Sets the current user UID in the session.

        Instead of just storing the user's id, it generates a hash from the
        password *salt*. That way, an admin or the user herself can invalidate
        the login in other computers just by changing (or re-saving)
        her password.

        """
        logger = logging.getLogger(__name__)
        logger.debug(u'User `{0}` logged in'.format(user.login))
        if session is None:
            session = self.session
        session['permanent'] = remember
        session[self.session_key] = user.get_uhmac()
        if callable(getattr(session, 'save', None)):
            session.save()

    def logout(self, session=None):
        if session is None:
            session = self.session
        if self.session_key in session:
            del session[self.session_key]
        if self.clear_session_on_logout:
            session.clear()
        if callable(getattr(session, 'save', None)):
            session.save()
