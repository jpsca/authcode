# -*- coding: utf-8 -*-
from datetime import datetime

from sqlalchemy import (Table, Column, Integer, Unicode, String, DateTime,
    Boolean, ForeignKey)
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, backref

from .utils import get_uhmac, get_token


def extend_user_model(auth, UserMixin=None):
    db = auth.db

    class AuthUserMixin(object):
        id = Column(Integer, primary_key=True)
        login = Column(Unicode, nullable=False, unique=True)
        _password = Column(String(255), nullable=True)
        created_at = Column(DateTime, nullable=False,
            default=datetime.utcnow)
        modified_at = Column(DateTime, nullable=False,
            default=datetime.utcnow, onupdate=datetime.utcnow)
        last_sign_in = Column(DateTime, nullable=True)
        deleted = Column(Boolean, default=False)

        @hybrid_property
        def password(self):
            return self._password

        @password.setter
        def password(self, secret):
            self._password = auth.hash_password(secret)

        @classmethod
        def by_login(cls, login):
            name = unicode(login).strip()
            return db.session.query(cls).filter(cls.login == login).first()

        @classmethod
        def by_id(cls, pk):
            return db.session.query(cls).get(pk)

        def has_password(self, secret):
            return auth.password_is_valid(secret, self._password)

        def get_uhmac(self):
            return get_uhmac(self, auth.secret_key)

        def get_token(self, timestamp=None):
            return get_token(self, auth.secret_key, timestamp)

        def __repr__(self):
            return '<User {0}>'.format(self.login.encode('utf8'))


    if UserMixin is not None:
        class User(UserMixin, AuthUserMixin, db.Model):
            __tablename__ = 'users'
    else:
        class User(AuthUserMixin, db.Model):
            __tablename__ = 'users'

    return User


def extend_role_model(auth, User, RoleMixin=None):
    db = auth.db

    class AuthRoleMixin(object):
        id = Column(Integer, primary_key=True)
        name = Column(Unicode, nullable=False, unique=True)

        @classmethod
        def by_name(cls, name):
            name = unicode(name).strip()
            return db.session.query(cls).filter(cls.name == name).first()

        @classmethod
        def by_id(cls, pk):
            return db.session.query(cls).get(pk)

        @classmethod
        def get_or_create(cls, name):
            name = unicode(name).strip()
            role = cls.by_name(name)
            if role:
                return role
            role = cls(name=name)
            db.session.add(role)
            return role

        @declared_attr
        def users(cls):
            return relationship(User, lazy='dynamic', order_by='User.login',
                secondary='users_roles', enable_typechecks=False,
                backref=backref('roles', lazy='joined'))

        def __repr__(self):
            return '<Role {0}>'.format(self.name.encode('utf8'))

    if RoleMixin is not None:
        class Role(RoleMixin, AuthRoleMixin, db.Model):
            __tablename__ = 'roles'
    else:
        class Role(AuthRoleMixin, db.Model):
            __tablename__ = 'roles'

    Table('users_roles', db.metadata,
        Column('user_id', Integer, ForeignKey(User.id)),
        Column('role_id', Integer, ForeignKey(Role.id))
    )

    extend_user_model_with_role_methods(User, Role)
    return Role


def extend_user_model_with_role_methods(User, Role):
    def _add_role(self, name):
        """Adds a role (by name) to the user."""
        role = Role.get_or_create(name)
        if role not in self.roles:
            self.roles.append(role)

    User.add_role = _add_role

    def _remove_role(self, name):
        """Remove a role (by name) from the user."""
        role = Role.by_name(name)
        if not role:
            raise ValueError('Role "%s" does not exists' % (name,))
        if role in self.roles:
            self.roles.remove(role)

    User.remove_role = _remove_role

    def _has_role(self, *names):
        """Check if the user has any of these roles (by name)."""
        roles = [role.name for role in self.roles]
        for name in names:
            if name in roles:
                return True
        return False

    User.has_role = _has_role

