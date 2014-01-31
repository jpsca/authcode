# -*- coding: utf-8 -*-
from __future__ import absolute_import


SEE_OTHER = 303


def get_site_name(request):
    return request.host


def get_full_path(request):
    path = request.path
    if request.query_string:
        path += '?' + request.query_string
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
    return request.values.get(key)


def get_from_headers(request, key):
    return request.headers.get(key)


def get_post_data(request):
    return request.form

