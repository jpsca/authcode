# coding=utf-8
from __future__ import absolute_import

from .._compat import to_native


HTTP_FORBIDDEN = 403


def get_site_name(request):
    """Return the domain:port part of the URL without scheme.
    Eg: facebook.com, 127.0.0.1:8080, etc.
    """
    urlparts = request.urlparts
    return ':'.join([urlparts.hostname, str(urlparts.port)])


def get_full_path(request):
    """Return the current relative path including the query string.
    Eg: “/foo/bar/?page=1”
    """
    path = request.fullpath
    query_string = request.environ.get('QUERY_STRING')
    if query_string:
        path += '?' + to_native(query_string)
    return path


def make_full_url(request, url):
    """Get a relative URL and returns the absolute version.
    Eg: “/foo/bar?q=is-open” ==> “http://example.com/foo/bar?q=is-open”
    """
    urlparts = request.urlparts
    return '{scheme}://{site}/{url}'.format(
        scheme=urlparts.scheme,
        site=get_site_name(request),
        url=url.lstrip('/'),
    )


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
    from bottle import redirect
    redirect(url)


def raise_forbidden(msg='You are not allowed to access this.'):
    """Return an HTTP 403 Forbidden response (with the passed message), in the
    idiom of the framework.
    """
    from bottle import abort
    abort(HTTP_FORBIDDEN, msg)


def get_from_params(request, key):
    """Try to read a value named ``key`` from the GET parameters.
    """
    return request.query.get(key)


def get_from_headers(request, key):
    """Try to read a value named ``key`` from the headers.
    """
    return request.headers.get(key)


def get_post_data(request):
    """Return all the POST data from the request.
    """
    return request.forms


def make_response(body, mimetype='text/html'):
    """Build a framework specific HTPP response, containing ``body`` and
    marked as the type ``mimetype``.
    """
    from bottle import response
    response.content_type = mimetype
    return body or u''
