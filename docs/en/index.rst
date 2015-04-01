:orphan:

=============================================
Authcode
=============================================

.. container:: lead

    Authcode is a clean solution for both **authentication** and **authorization** of Python web applications.

Briefly, authentication verifies a user is who they claim to be, and authorization determines what an authenticated user is allowed to do.

It uses SQLAlchemy models and can be used with `Flask <http://flask.pocoo.org/>`_ or `Bottle <http://bottlepy.org/>`_, although it should be easy to adapt it to other web framework.


Features
---------------------------------------------

* Fully customizable User and Role models
* Includes optional views and templates ready to use for the login and reset password pages.
* You can use multiple auth systems at the same time
* Uses the most secure hashing algorithms by default.
* Auto-update your password hashes if you need to (when the user logs in).
* Easy to integrate with alternatives modes of authentication (eg: Facebook).
* Protection from Cross Site Request Forgery (CSRF) attacks.
* Compatible with Python 2.7, Pypy and Python 3.3 o newer.

.. include:: contents.rst.inc
