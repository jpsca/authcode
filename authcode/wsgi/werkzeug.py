# coding=utf-8
from __future__ import absolute_import

from .._compat import to_native


HTTP_SEE_OTHER = 303


def get_site_name(request):
    """Return the domain:port part of the URL without scheme.
    Eg: facebook.com, 127.0.0.1:5000, etc.
    """
    return request.host


def get_full_path(request):
    """Return the current relative path including the query string.
    Eg: “/foo/bar/?page=1”
    """
    path = request.path
    if request.query_string:
        path += '?' + to_native(request.query_string)
    return path


def make_full_url(request, url):
    """Get a relative URL and returns the absolute version.
    Eg: “/foo/bar?q=is-open” ==> “http://example.com/foo/bar?q=is-open”
    """
    return request.url_root + url.lstrip('/')


def is_post(request):
    """Return ``True`` if the method of the request is ``POST``.
    """
    return request.method.upper() == 'POST'


def is_idempotent(request):
    """Return ``True`` if the method of the request is ``GET`` or ``HEAD``.
    """
    return request.method.upper() in ('GET', 'HEAD')


def redirect(url):
    """Return an HTTP 303 See Other response for this url, in the
    idiom of the framework.
    """
    from werkzeug.utils import redirect
    return redirect(url, code=HTTP_SEE_OTHER)


def raise_forbidden(msg='You are not allowed to access this.'):
    """Return an HTTP 403 Forbidden response (with the passed message), in the
    idiom of the framework.
    """
    from werkzeug.exceptions import Forbidden
    raise Forbidden(msg)


def get_from_params(request, key):
    """Try to read a value named ``key`` from the GET parameters.
    """
    value = request.values.get(key)
    return to_native(value)


def get_from_headers(request, key):
    """Try to read a value named ``key`` from the headers.
    """
    value = request.headers.get(key)
    return to_native(value)


def get_post_data(request):
    """Return all the POST data from the request.
    """
    return request.form


def make_response(body, mimetype='text/html'):
    """Build a framework specific HTPP response, containing ``body`` and
    marked as the type ``mimetype``.
    """
    from werkzeug.wrappers import Response
    if isinstance(body, Response):
        body.mimetype = mimetype
        return body
    return Response(body, mimetype=mimetype)
