# coding=utf-8
from __future__ import absolute_import


def get_site_name(request):
    """Return the domain:port part of the URL without scheme.
    Eg: “facebook.com”, “0.0.0.0:8080”, etc.
    """
    import web
    return web.ctx.host


def get_full_path(request):
    """Return the current relative path including the query string.
    Eg: “/foo/bar/?page=1”
    """
    import web
    return web.ctx.fullpath


def make_full_url(request, url):
    """Get a relative URL and returns the absolute version.
    Eg: “/foo/bar?q=is-open” ==> “http://example.com/foo/bar?q=is-open”
    """
    import web
    return '{protocol}://{host}{url}'.format(
        protocol=web.ctx.protocol,
        host=web.ctx.host,
        url=url,
    )


def is_post(request):
    """Return ``True`` if the method of the request is ``POST``.
    """
    import web
    return web.ctx.method.upper() == 'POST'


def is_idempotent(request):
    """Return ``True`` if the method of the request is ``GET`` or ``HEAD``.
    """
    import web
    return web.ctx.method.upper() in ('GET', 'HEAD')


def redirect(url):
    """Return an HTTP 303 See Other response for this url, in the
    idiom of the framework.
    """
    import web
    raise web.seeother(url)


def raise_forbidden(msg='You are not allowed to access this resource.'):
    """Return an HTTP 403 Forbidden response (with the passed message), in the
    idiom of the framework.
    """
    import web
    error = web.Forbidden()
    error.message = msg
    raise error


def get_from_params(request, key):
    """Try to read a value named ``key`` from the GET parameters.
    """
    import web
    return web.input().get(key)


def get_from_headers(request, key):
    """Try to read a value named ``key`` from the headers.
    """
    import web
    key = 'HTTP_' + key.upper().replace('-', '_').replace(' ', '_')
    return web.ctx.env.get(key)


def get_post_data(request):
    """Return all the POST data from the request.
    """
    import web
    return web.input()


def make_response(body, mimetype='text/html'):
    """Build a framework specific HTPP response, containing ``body`` and
    marked as the type ``mimetype``.
    """
    import web
    web.header('Content-Type', mimetype)
    return body
