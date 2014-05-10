# coding=utf-8
from __future__ import print_function
import hashlib
import hmac
from time import time


def test_hasher(hasher):
    hasher.encrypt('test', rounds=hasher.min_rounds)


def to36(number):
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    base36 = ''
    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36

    return base36 or alphabet[0]


def from36(number):
    return int(number, 36)


def get_uhmac(user, secret):
    key = '|'.join([
        hashlib.sha1(secret).hexdigest(),
        str(user.id),
        (getattr(user, 'password', '') or '')[10:20],
    ])
    key = key.encode('utf8', 'ignore')
    mac = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    mac = mac.hexdigest()[:50]
    # user.id instead of user.login because SQLAlchemy only caches
    # by primary key, so even if you don't cache the user object, a trip to
    # the database is spared.
    uhmac = '{0}${1}'.format(user.id, mac)
    return uhmac


def get_token(user, secret, timestamp=None):
    """Make a timestamped one-time-use token that can be used to
    identifying the user.

    By hashing the `last_sign_in` attribute and the password salt, it produce
    a token that will be invalidated as soon as the user log in again or the
    is changed.

    A hash of the user ID is used, so the HMAC part of the token is always
    unique for each user.

    It also hash a secret key, so without access to the source code,
    fake tokens cannot be generated even if the database is compromised.
    """
    timestamp = int(timestamp or time())
    key = '|'.join([
        hashlib.sha1(secret).hexdigest(),
        str(user.id),
        (getattr(user, 'password', '') or '')[10:20],
        str(getattr(user, 'last_sign_in', 0)),
        str(timestamp),
    ])
    key = key.encode('utf8', 'ignore')
    mac = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    mac = mac.hexdigest()[:50]
    token = '{0}${1}${2}'.format(user.id, to36(timestamp), mac)
    return token


def split_uhmac(uhmac):
    uid, mac = uhmac.split('$', 1)
    return uid


def split_token(token):
    uid, t36, mac = token.split('$', 2)
    return from36(t36), uid


def default_render(template, **context):
    from jinja2 import Environment, PackageLoader
    loader = PackageLoader('authcode', 'templates')
    env = Environment(loader=loader)
    tmpl = env.get_template(template)
    return tmpl.render(context)


def default_send_email(user, subject, msg):
    print(user, subject, msg)


_missing = object()


class cached_property(object):
    """A decorator that converts a function into a lazy property.  The
    function wrapped is called the first time to retrieve the result
    and then that calculated result is used the next time you access
    the value::

        class Foo(object):

            @cached_property
            def foo(self):
                # calculate something important here
                return 42

    The class has to have a `__dict__` in order for this property to
    work.
    """

    # implementation detail: this property is implemented as non-data
    # descriptor.  non-data descriptors are only invoked if there is
    # no entry with the same name in the instance's __dict__.
    # this allows us to completely get rid of the access function call
    # overhead.  If one choses to invoke __get__ by hand the property
    # will still work as expected because the lookup logic is replicated
    # in __get__ for manual invocation.

    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func

    def __get__(self, obj, type=None):
        if obj is None:
            return self
        value = obj.__dict__.get(self.__name__, _missing)
        if value is _missing:
            value = self.func(obj)
            obj.__dict__[self.__name__] = value
        return value
