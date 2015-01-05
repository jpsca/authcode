# coding=utf-8
"""
    ==========
    Authcode
    ==========

    Awesome authentication code

    :copyright: © by `Juan Pablo Scaletti <http://jpscaletti.com>`_.
    :license: MIT, see LICENSE for more details.

"""
from .auth import Auth, WrongHashAlgorithm  # noqa
from .setups.setup_for_cherrypy import setup_for_cherrypy  # noqa
from .setups.setup_for_flask import setup_for_flask  # noqa
from .setups.setup_for_shake import setup_for_shake  # noqa
from .setups.setup_for_webpy import setup_for_webpy  # noqa

__version__ = '1.1.1'
