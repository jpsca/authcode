
Installation
------------

Authcode expects some basic infraestructure to be in place:

#. A ``session`` object with a dict-like interface.

#. A ``request`` object with the current request. For now, it only support Werkzeug or WebOb request types, but it could easily work with other frameworks like CherryPy.

#. A ``db`` argument used to interface with SQLAlchemy. If you're using `flask-sqlalchemy`_ or `orm`_ you already have one. If not, just pass it a custom object with a declarative base model in ``db.Model`` and an SQLAlchemy session at ``db.session``.

.. _flask-sqlalchemy: http://pythonhosted.org/Flask-SQLAlchemy/
.. _orm: https://github.com/lucuma/orm/
