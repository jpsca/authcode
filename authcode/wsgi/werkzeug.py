# coding=utf-8
from __future__ import print_function, absolute_import

from .._compat import to_unicode, to_native


SEE_OTHER = 303


def get_site_name(request):
    return request.host


def get_full_path(request):
    path = request.path
    if request.query_string:
        path += '?' + to_native(request.query_string)
    return path


def make_full_url(request, url):
    return request.url_root + url.lstrip('/')


def is_post(request):
    return request.method.upper() == 'POST'


def is_put_or_post(request):
    return request.method.upper() in ('POST', 'PUT')


def redirect(url):
    from werkzeug.utils import redirect
    return redirect(url, code=SEE_OTHER)


def raise_forbidden(msg='You are not allowed to access this.'):
    from werkzeug.exceptions import Forbidden
    raise Forbidden(msg)


def get_from_params(request, key):
    value = request.values.get(key)
    return to_native(value)


def get_from_headers(request, key):
    value = request.headers.get(key)
    return to_native(value)


def get_post_data(request):
    return request.form

