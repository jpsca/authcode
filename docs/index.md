
## Welcome

AuthCode is an password authentication library for Python web applications using SQLAlchemy.

## Features

* Framework independent
* Uses the most secure hash algorithms.
* User & Role models.
* Ready to use authentication views and templates.
* Auto-update of old password hashes.
* Password-reset tokens.
* Cross Site Request Forgery (CSRF) protection.
* Python 2.7 / Pypy compatible.

## Requirements

AuthCode does not depends of any specific web framework, but expects some basic infraestructure to be in place:

* A `session` object with a dict-like interface. 
* A `request` object with the current request. For now, it only support Werkzeug or WebOb request types.
* `orm`, `flask-sqlalchemy` or similar library. AuthCode expects a declarative base model in `db.Model` and an SQLAlchemy session at `db.session`.


