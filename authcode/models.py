# coding=utf-8
import logging

from sqlalchemy import (
    Table, Column, Integer, Unicode, String, DateTime, Boolean, ForeignKey,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates, relationship, backref

from .utils import get_uhmac, get_token
from ._compat import to_unicode, to_native


class DictSerializable(object):
    """Makes an object serializable to a dictionary.
    """

    def _asdict(self):
        repr(self)  # Force to load the data
        dictrep = self.__dict__.copy()
        dictrep.pop('_sa_instance_state', None)
        return dictrep

    to_dict = _asdict


def extend_user_model(auth, UserMixin=None, roles=False):
    db = auth.db
    AuthUserMixin = get_auth_user_mixin(auth, roles=roles)

    if UserMixin is not None:
        parents = (UserMixin, AuthUserMixin, DictSerializable, db.Model)
        tablename = getattr(UserMixin, '__tablename__', None)
        if not tablename:
            tablename = auth.users_model_name.lower().rstrip('s') + 's'
    else:
        parents = (AuthUserMixin, DictSerializable, db.Model)
        tablename = auth.users_model_name.lower().rstrip('s') + 's'

    return type(auth.users_model_name, parents, {'__tablename__': tablename})


def get_auth_user_mixin(auth, roles=False):
    db = auth.db

    class AuthUserMixin(object):
        id = Column(Integer, primary_key=True)
        login = Column(Unicode(255), nullable=False, unique=True, index=True)
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
        def __hash_password(self, key, secret):
            logger = logging.getLogger(__name__)
            logger.debug(u'Hash updated for user `{0}`'.format(self.login))
            return auth.hash_password(secret)

        @validates('login')
        def __clean_login(self, key, login):
            login = to_unicode(login or u'').strip()
            if auth.case_insensitive:
                login = login.lower()
            return login

        @property
        def email(self):
            return self.login

        @classmethod
        def _auth_base_query(cls):
            return db.session.query(cls)

        @classmethod
        def by_id(cls, pk):
            return cls._auth_base_query().filter(cls.id == pk).first()

        @classmethod
        def by_login(cls, login):
            login = to_unicode(login).strip()
            if auth.case_insensitive:
                login = login.lower()
            return cls._auth_base_query().filter(cls.login == login).first()

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
        parents = (RoleMixin, AuthRoleMixin, DictSerializable, db.Model)
        tablename = getattr(RoleMixin, '__tablename__', None)
        if not tablename:
            tablename = auth.roles_model_name.lower().rstrip('s') + 's'
    else:
        parents = (AuthRoleMixin, DictSerializable, db.Model)
        tablename = auth.roles_model_name.lower().rstrip('s') + 's'

    Role = type(auth.roles_model_name, parents, {'__tablename__': tablename})

    UserRolesTable = Table(
        '{0}_{1}'.format(User.__tablename__, Role.__tablename__),
        db.metadata,
        Column('user_id', Integer, ForeignKey(User.id), primary_key=True),
        Column('role_id', Integer, ForeignKey(Role.id), primary_key=True)
    )

    Role.users = relationship(
        User, lazy='dynamic', order_by=User.login,
        secondary=UserRolesTable, enable_typechecks=False,
        backref=backref('roles', lazy='dynamic')
    )

    extend_user_model_with_role_methods(auth, db, User, Role)
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

        def __repr__(self):
            repr = '<Role {0}>'.format(self.name)
            return to_native(repr)

    return AuthRoleMixin


def extend_user_model_with_role_methods(auth, db, User, Role):

    def _auth_base_query(cls):
        query = db.session.query(cls)
        return query

    User._auth_base_query = classmethod(_auth_base_query)

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
