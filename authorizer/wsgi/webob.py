# -*- coding: utf-8 -*-
from __future__ import absolute_import


def get_site_name(request):
    return request.server_name


def get_full_path(request):
    return request.path_qs


def make_full_url(request, url):
    return request.relative_url(url)


def is_post(request):
    return request.method.upper() == 'POST'


def redirect(url):
    from webob.exc import HTTPSeeOther
    raise HTTPSeeOther(url)


def raise_forbidden(msg=''):
    from webob.exc import HTTPForbidden
    raise HTTPForbidden(msg)


def get_from_values(request, key):
    return request.params.get(key)
    

def get_from_headers(request, key):
    return request.headers.get(key)


def get_post_data(request):
    return request.POST

