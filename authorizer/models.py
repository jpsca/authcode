# -*- coding: utf-8 -*-
from datetime import datetime

from sqlalchemy import (Table, Column, Integer, Unicode, String, DateTime,
    ForeignKey)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, backref

from .utils import get_uhmac, get_token, split_uhmac


def get_user_model(auth):
    db = auth.db

    class User(db.Model):
        id = Column(Integer, primary_key=True)
        login = Column(Unicode(255), nullable=False, unique=True)
        _password = Column(String(255), nullable=True)
        created_at = Column(DateTime, nullable=False,
            default=datetime.utcnow)
        modified_at = Column(DateTime, nullable=False,
            default=datetime.utcnow, onupdate=datetime.utcnow)
        last_sign_in = Column(DateTime, nullable=True)

        @hybrid_property
        def password(self):
            return self._password

        @password.setter
        def password(self, secret):
            self._password = auth.hash_password(secret)

        @classmethod
        def by_id(cls, uid):
            return db.session.query(cls).get(uid)

        @classmethod
        def by_login(cls, login):
            name = unicode(login).strip()
            return db.session.query(cls).filter(cls.login == login).first()

        def has_password(self, secret):
            return auth.password_is_valid(secret, self._password)

        def get_uhmac(self):
            return get_uhmac(self, auth.secret_key)

        def get_token(self, timestamp=None):
            return get_token(self, auth.secret_key, timestamp)

        def __repr__(self):
            return '<%s %s>' % (self.__class__.__name__, 
                self.login.encode('utf8'))

    return User


def get_user_role_model(auth, User):
    db = auth.db
    
    class UserRole(db.Model):
        id = Column(Integer, primary_key=True)
        name = Column(Unicode(255), nullable=False, unique=True)

        @classmethod
        def by_name(cls, name):
            name = unicode(name).strip()
            return db.session.query(cls).filter(cls.name == name).first()

        def __repr__(self):
            return '<%s %s>' % (self.__class__.__name__,
                self.name.encode('utf8'))
    
    User.roles = relationship(UserRole, secondary='users_roles', lazy='joined',
        backref=backref('users', lazy='dynamic', enable_typechecks=False))

    UsersRolesTable = Table('users_roles', db.metadata,
        Column('user_id', Integer, ForeignKey(User.id)),
        Column('role_id', Integer, ForeignKey(UserRole.id))
    )

    def add_role(self, name):
        """Adds a role (by name) to the user."""
        role = UserRole.by_name(name)
        if not role:
            role = UserRole(name=name)
            db.add(role)
        if role not in self.roles:
            self.roles.append(role)

    def remove_role(self, name):
        """Remove a role (by name) from the user."""
        role = UserRole.by_name(name)
        if not role:
            raise ValueError('UserRole "%s" does not exists' % (name,))
        if role in self.roles:
            self.roles.remove(role)

    def has_role(self, *names):
        """Check if the user has any of these roles (by name)."""
        roles = [role.name for role in self.roles]
        for name in names:
            if name in roles:
                return True
        return False

    User.add_role = add_role
    User.remove_role = remove_role
    User.has_role = has_role

    return UserRole

