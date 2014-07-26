# coding=utf-8
import logging

from sqlalchemy import (Table, Column, Integer, Unicode, String, DateTime,
                        Boolean, ForeignKey)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates, relationship, backref

from .utils import get_uhmac, get_token
from ._compat import to_unicode, to_native


def extend_user_model(auth, UserMixin=None):
    db = auth.db
    AuthUserMixin = get_auth_user_mixin(auth)

    if UserMixin is not None:
        class User(UserMixin, AuthUserMixin, db.Model):
            __tablename__ = getattr(UserMixin, '__tablename__', 'users')
    else:
        class User(AuthUserMixin, db.Model):
            __tablename__ = 'users'

    return User


def get_auth_user_mixin(auth):
    db = auth.db

    class AuthUserMixin(object):
        id = Column(Integer, primary_key=True)
        login = Column(Unicode, nullable=False, unique=True)
        password = Column(String(255), nullable=True)
        last_sign_in = Column(DateTime, nullable=True)
        deleted = Column(Boolean, default=False)

        @hybrid_property
        def _password(self):
            """Backwards compatibility fix."""
            return self.password

        @_password.setter
        def _password(self, value):
            """Backwards compatibility fix."""
            self.set_raw_password(value)

        @validates('password')
        def _hash_password(self, key, secret):
            logger = logging.getLogger(__name__)
            logger.debug(u'Hash updated for user `{0}`'.format(self.login))
            return auth.hash_password(secret)

        @classmethod
        def by_id(cls, pk):
            return db.session.query(cls).get(pk)

        @classmethod
        def by_login(cls, login):
            login = to_unicode(login).strip()
            return db.session.query(cls).filter(cls.login == login).first()

        def set_raw_password(self, secret):
            """Sets the password without hashing.
            Don't use it unless you have a good reason to do so.
            """
            table = self.__table__
            upd = (table.update().where(table.c.id == self.id)
                   .values(password=secret))
            db.session.execute(upd)
            db.session.commit()

        def has_password(self, secret):
            return auth.password_is_valid(secret, self.password)

        def get_uhmac(self):
            return get_uhmac(self, auth.secret_key)

        def get_token(self, timestamp=None):
            return get_token(self, auth.secret_key, timestamp)

        def __repr__(self):
            repr = '<User {0}>'.format(self.login)
            return to_native(repr)

    return AuthUserMixin


def extend_role_model(auth, User, RoleMixin=None):
    db = auth.db
    AuthRoleMixin = get_auth_role_mixin(auth, User)

    if RoleMixin is not None:
        class Role(RoleMixin, AuthRoleMixin, db.Model):
            __tablename__ = 'roles'
    else:
        class Role(AuthRoleMixin, db.Model):
            __tablename__ = 'roles'

    Table(
        'users_roles', db.metadata,
        Column('user_id', Integer, ForeignKey(User.id)),
        Column('role_id', Integer, ForeignKey(Role.id))
    )

    extend_user_model_with_role_methods(User, Role)
    return Role


def get_auth_role_mixin(auth, User):
    db = auth.db

    class AuthRoleMixin(object):
        id = Column(Integer, primary_key=True)
        name = Column(Unicode, nullable=False, unique=True)

        @classmethod
        def by_id(cls, pk):
            return db.session.query(cls).get(pk)

        @classmethod
        def by_name(cls, name):
            name = to_unicode(name).strip()
            return db.session.query(cls).filter(cls.name == name).first()

        @classmethod
        def get_or_create(cls, name):
            name = to_unicode(name).strip()
            role = cls.by_name(name)
            if role:
                return role
            role = cls(name=name)
            db.session.add(role)
            return role

        @declared_attr
        def users(cls):
            return relationship(
                User, lazy='dynamic', order_by='User.login',
                secondary='users_roles', enable_typechecks=False,
                backref=backref('roles', lazy='joined')
            )

        def __repr__(self):
            repr = '<Role {0}>'.format(self.name)
            return to_native(repr)

    return AuthRoleMixin


def extend_user_model_with_role_methods(User, Role):
    def _add_role(self, name):
        """Adds a role (by name) to the user."""
        role = Role.get_or_create(name)
        if role not in self.roles:
            self.roles.append(role)
        return self

    User.add_role = _add_role

    def _remove_role(self, name):
        """Remove a role (by name) from the user."""
        role = Role.by_name(name)
        if not role:
            return self
        if role in self.roles:
            self.roles.remove(role)
        return self

    User.remove_role = _remove_role

    def _has_role(self, *names):
        """Check if the user has any of these roles (by name)."""
        roles = [to_unicode(role.name) for role in self.roles]
        for name in names:
            if to_unicode(name) in roles:
                return True
        return False

    User.has_role = _has_role
