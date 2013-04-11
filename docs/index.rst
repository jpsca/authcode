Welcome
-------

| AuthCode is a clean and unobtrusive authentication & authorization
solution for Python web applications.
| It uses SQLAlchemy models but does not depends of any specific web
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

Requirements
------------

AuthCode expects some basic infraestructure to be in place:

#. A ``session`` object with a dict-like interface.

2 A ``request`` object with the current request. For now, it only
support Werkzeug or WebOb request types.

3 AuthCode expects a ``db`` argument with a declarative base model in
``db.Model`` and an SQLAlchemy session at ``db.session``. If you're
using ``orm`` or ``flask-sqlalchemy`` your set, if not, just pass it a
custom object.
