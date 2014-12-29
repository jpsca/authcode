# coding=utf-8
from __future__ import absolute_import


SEE_OTHER = 303


def get_site_name(request):
    return request.base.replace(request.scheme + '://', '')


def get_full_path(request):
    path = request.path_info
    if request.query_string:
        path += '?' + request.query_string
    return path


def make_full_url(request, url):
    import cherrypy
    return cherrypy.url(url, relative=False)


def is_post(request):
    return request.method.upper() == 'POST'


def not_safe_method(request):
    return request.method.upper() not in ('GET', 'HEAD')


def redirect(url):
    import cherrypy
    raise cherrypy.HTTPRedirect(url, SEE_OTHER)


def raise_forbidden(msg='You are not allowed to access this resource.'):
    import cherrypy
    raise cherrypy.HTTPError("403 Forbidden", msg)


def get_from_params(request, key):
    return request.params.get(key)


def get_from_headers(request, key):
    return request.headers.get(key)


def get_post_data(request):
    return getattr(request, 'body_params', request.body.params)


def make_response(body, mimetype='text/html'):
    import cherrypy
    cherrypy.response.headers['Content-Type'] = mimetype
    return body
