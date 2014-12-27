# coding=utf-8
import solution as f
from solution import validators as v

from .models import auth, User


class UsernameDoesNotExist(v.Validator):
    code = 'used_login'
    message = u'Username is already being used.'

    def __call__(self, python_value=None, form=None):
        return not User.by_login(python_value)


class RegisterForm(f.Form):
    _model = User

    login = f.Text(validate=[
        v.Required,
        v.LongerThan(4),
        UsernameDoesNotExist,
    ])
    email = f.Text(validate=[v.ValidEmail])
    password = f.Password(validate=[
        v.Required,
        v.LongerThan(auth.password_minlen)
    ])
