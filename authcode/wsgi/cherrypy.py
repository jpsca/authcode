# coding=utf-8
from __future__ import absolute_import


SEE_OTHER = 303


def get_site_name(request):
    """Return the domain:port part of the URL without scheme.
    Eg: facebook.com, 0.0.0.0:8080, etc.
    """
    return request.base.replace(request.scheme + '://', '')


def get_full_path(request):
    """Return the current relative path including the query string.
    Eg: “/foo/bar/?page=1”
    """
    import cherrypy
    path = cherrypy.url(base='', relative=False)
    query = '&'.join(
        '{key}={val}'.format(key=key, val=val)
        for key, val in cherrypy.request.params.items()
    )
    if not query:
        return path
    return '{path}?{query}'.format(path=path, query=query)


def make_full_url(request, url):
    """Get a relative URL and returns the absolute version.
    Eg: “/foo/bar?q=is-open” ==> “http://example.com/foo/bar?q=is-open”
    """
    import cherrypy
    return cherrypy.url(url, relative=False)


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
    import cherrypy
    raise cherrypy.HTTPRedirect(url, SEE_OTHER)


def raise_forbidden(msg='You are not allowed to access this resource.'):
    """Return an HTTP 403 Forbidden response (with the passed message), in the
    idiom of the framework.
    """
    import cherrypy
    raise cherrypy.HTTPError("403 Forbidden", msg)


def get_from_params(request, key):
    """Try to read a value named ``key`` from the GET parameters.
    """
    return request.params.get(key)


def get_from_headers(request, key):
    """Try to read a value named ``key`` from the headers.
    """
    return request.headers.get(key)


def get_post_data(request):
    """Return all the POST data from the request.
    """
    return getattr(request, 'body_params', request.body.params)


def make_response(body, mimetype='text/html'):
    """Build a framework specific HTPP response, containing ``body`` and
    marked as the type ``mimetype``.
    """
    import cherrypy
    cherrypy.response.headers['Content-Type'] = mimetype
    return body
