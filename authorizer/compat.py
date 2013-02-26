# -*- coding: utf-8 -*-


def is_post(request):
    return request.method.upper() == 'POST'


def get_current_url(request):
    return request.url


def redirect(sign_in_url):
    from werkzeug.utils import redirect
    return redirect(sign_in_url)


def raise_forbidden(msg=''):
    from werkzeug.exceptions import Forbidden
    raise Forbidden(msg)


def get_from_values(request, key):
    return request.values.get(key)


def get_from_headers(request, key):
    return request.headers.get(key)


def get_post_data(request):
    return request.form


def get_host(request):
    return request.host


def get_full_url(request, url):
    return request.host_url + url.lstrip('/')

