AuthCode
============

AuthCode is a clean solution for both authentication and authorization of Python web applications. Briefly, authentication verifies a user is who they claim to be, and authorization determines what an authenticated user is allowed to do.

It uses SQLAlchemy models but does not depends of any specific web
framework.


Features
--------

-  Framework independent
-  Uses the most secure hash algorithms.
-  Default but fully customizable User & Role models.
-  Ready to use authentication views and templates.
-  Auto-update of old password hashes.
-  Password-reset tokens.
-  Cross Site Request Forgery (CSRF) protection.
-  Python 2.7 / Pypy compatible.


Installation
------------

AuthCode expects some basic infraestructure to be in place:

#. A ``session`` object with a dict-like interface.

#. A ``request`` object with the current request. For now, it only support Werkzeug or WebOb request types, but it could easily work with other frameworks like CherryPy.

#. A ``db`` argument used to interface with SQLAlchemy. If you're using `flask-sqlalchemy`_ or `orm`_ you already have one. If not, just pass it a custom object with a declarative base model in ``db.Model`` and an SQLAlchemy session at ``db.session``.

.. _flask-sqlalchemy: http://pythonhosted.org/Flask-SQLAlchemy/
.. _orm: https://github.com/lucuma/orm/
