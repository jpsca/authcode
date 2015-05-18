# coding=utf-8
from __future__ import print_function

import authcode
from sqlalchemy_wrapper import SQLAlchemy

from helpers import SECRET_KEY


def test_user_model():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    assert auth.users_model_name == 'User'
    assert auth.roles_model_name == 'Role'

    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.commit()

    assert user.login == u'meh'
    assert user.email == user.login
    assert hasattr(user, 'password')
    assert hasattr(user, 'last_sign_in')
    assert repr(user) == '<User meh>'


def test_user_model_to_dict():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.commit()

    user_dict = user.to_dict()
    assert user_dict


def test_backwards_compatibility():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.commit()

    assert user._password == user.password
    user._password = 'raw'
    assert user.password == 'raw'


def test_user_model_methods():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.commit()

    assert User.by_id(user.id) == user
    assert User.by_id(33) is None

    assert User.by_login(u'meh') == user
    assert User.by_login(u'foobar') is None

    assert user.has_password('foobar')
    assert not user.has_password('abracadabra')

    assert user.get_token()
    assert user.get_uhmac()


def test_set_raw_password():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.password != 'foobar'
    user.set_raw_password('foobar')
    assert user.password == 'foobar'


def test_role_model():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    Role = auth.Role
    db.create_all()
    role = Role(name=u'admin')
    db.session.add(role)
    db.commit()

    assert role.name == u'admin'
    assert repr(role) == '<Role admin>'


def test_role_model_to_dict():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    Role = auth.Role
    db.create_all()
    role = Role(name=u'admin')
    db.session.add(role)
    db.commit()

    role_dict = role.to_dict()
    assert role_dict


def test_role_model_methods():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    Role = auth.Role
    db.create_all()
    role = Role(name=u'admin')
    db.session.add(role)
    db.commit()

    assert Role.by_id(role.id) == role
    assert Role.by_id(33) is None

    assert Role.by_name(u'admin') == role
    assert Role.by_name(u'foobar') is None

    assert Role.get_or_create(u'admin') == role

    role2 = Role.get_or_create(u'owner')
    db.commit()
    assert role2 != role
    assert db.query(Role).count() == 2

    assert list(role.users) == []
    assert list(role2.users) == []


def test_add_role():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    Role = auth.Role
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    role = Role(name=u'loremipsum')
    db.session.add(role)
    db.session.commit()

    assert hasattr(auth, 'Role')
    assert hasattr(User, 'roles')

    # Add nonexistant role creates it
    user.add_role('admin')
    db.session.commit()
    assert user.has_role('admin')
    assert db.query(Role).count() == 2
    assert list(user.roles) == [Role.by_name('admin')]

    # Adding the same role does nothing
    user.add_role('admin')
    db.session.commit()
    assert user.has_role('admin')
    assert db.query(Role).count() == 2
    assert list(user.roles) == [Role.by_name('admin')]

    # Adding an existent role does not create a new one
    user.add_role('loremipsum')
    db.session.commit()
    assert user.has_role('loremipsum')

    result = sorted([role.name for role in user.roles])
    assert result == ['admin', 'loremipsum']
    assert db.query(Role).count() == 2


def test_remove_role():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    Role = auth.Role
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert hasattr(auth, 'Role')
    assert hasattr(User, 'roles')

    user.add_role('admin')
    db.session.commit()
    assert user.has_role('admin')
    assert db.query(Role).count() == 1

    # Removed from user but not deleted
    user.remove_role('admin')
    db.session.commit()
    assert not user.has_role('admin')
    assert list(user.roles) == []
    assert db.query(Role).count() == 1

    # Removing a role it doesn't have does nothing
    user.remove_role('admin')
    db.session.commit()
    assert not user.has_role('admin')
    assert list(user.roles) == []
    assert db.query(Role).count() == 1

    # Removing a nonexistant role does nothing
    user.remove_role('foobar')
    db.session.commit()
    assert db.query(Role).count() == 1


def test_models_mixins():
    db = SQLAlchemy('sqlite:///:memory:')

    class UserMixin(object):
        email = db.Column(db.Unicode(300))

        def __repr__(self):
            return 'overwrited'

    class RoleMixin(object):
        description = db.Column(db.UnicodeText)

    auth = authcode.Auth(SECRET_KEY, db=db, UserMixin=UserMixin, RoleMixin=RoleMixin)
    User = auth.User
    Role = auth.Role

    db.create_all()
    user = User(login=u'meh', password='foobar', email=u'text@example.com')
    db.session.add(user)
    db.flush()

    assert User.__tablename__ == 'users'
    assert user.login == u'meh'
    assert user.email == u'text@example.com'
    assert hasattr(user, 'password')
    assert hasattr(user, 'last_sign_in')
    assert repr(user) == 'overwrited'

    assert hasattr(Role, 'description')


def test_naked_sqlalchemy():
    from sqlalchemy import create_engine
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import scoped_session, sessionmaker

    engine = create_engine('sqlite://')

    class DB(object):
        Session = scoped_session(sessionmaker(bind=engine))
        Model = declarative_base()

        @property
        def session(self):
            return self.Session()

    db = DB()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User
    db.Model.metadata.create_all(bind=engine)

    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert User.by_id(user.id) == user
    assert User.by_id(33) is None

    assert User.by_login(u'meh') == user
    assert User.by_login(u'foobar') is None

    assert user.has_password('foobar')
    assert not user.has_password('abracadabra')

    assert user.get_token()
    assert user.get_uhmac()
