# coding=utf-8
from __future__ import absolute_import


def get_site_name(request):
    import web
    return web.ctx.host


def get_full_path(request):
    import web
    return web.ctx.fullpath


def make_full_url(request, url):
    import web
    return '{protocol}://{host}{fullpath}'.format(
        protocol=web.ctx.protocol,
        host=web.ctx.host,
        fullpath=web.ctx.fullpath,
    )


def is_post(request):
    import web
    return web.ctx.method.upper() == 'POST'


def not_safe_method(request):
    import web
    return web.ctx.method.upper() not in ('GET', 'HEAD')


def redirect(url):
    import web
    raise web.seeother(url)


def raise_forbidden(msg='You are not allowed to access this resource.'):
    import web
    raise web.Forbidden(msg)


def get_from_params(request, key):
    import web
    return web.input().get(key)


def get_from_headers(request, key):
    import web
    return web.ctx.env.get(key, web.ctx.env.get(key.upper()))


def get_post_data(request):
    import web
    return web.input()


def make_response(body, mimetype='text/html'):
    import web
    web.header('Content-Type', mimetype)
    return body
