# coding=utf-8
from __future__ import print_function, absolute_import

import sys

from authcode import wsgi
import pytest

from .helpers import wsgi_tester


request = None


def make_wepapp():
    import web
    from cherrypy import wsgiserver

    class get_site_name(object):
        def GET(self):
            return wsgi.webpy.get_site_name(request)

    class get_full_path(object):
        def GET(self):
            return wsgi.webpy.get_full_path(request)

    class make_full_url(object):
        def GET(self):
            return wsgi.webpy.make_full_url(request, '/tests/get_site_name/')

    class is_post(object):
        def GET(self):
            return 'yes' if wsgi.webpy.is_post(request) else 'no'

        def HEAD(self):
            assert not wsgi.webpy.is_post(request)

        def POST(self):
            return 'yes' if wsgi.webpy.is_post(request) else 'no'

        def PUT(self):
            return 'yes' if wsgi.webpy.is_post(request) else 'no'

        def DELETE(self):
            return 'yes' if wsgi.webpy.is_post(request) else 'no'

    class is_idempotent(object):
        def GET(self):
            return 'yes' if wsgi.webpy.is_idempotent(request) else 'no'

        def HEAD(self):
            assert wsgi.webpy.is_idempotent(request)

        def POST(self):
            return 'yes' if wsgi.webpy.is_idempotent(request) else 'no'

        def PUT(self):
            return 'yes' if wsgi.webpy.is_idempotent(request) else 'no'

        def DELETE(self):
            return 'yes' if wsgi.webpy.is_idempotent(request) else 'no'

    class redirect(object):
        def GET(self):
            return wsgi.webpy.redirect('/tests/redirected_to/')

    class redirected_to(object):
        def GET(self):
            return u'Hello world'

    class raise_forbidden(object):
        def GET(self):
            return wsgi.webpy.raise_forbidden('Custom forbidden message')

    class get_from_params(object):
        def GET(self):
            return wsgi.webpy.get_from_params(request, 'foo')

    class get_from_headers(object):
        def GET(self):
            return wsgi.webpy.get_from_headers(request, 'X-CSRFToken')

    class get_post_data(object):
        def POST(self):
            data = wsgi.webpy.get_post_data(request)
            return '{val1},{val2}'.format(
                val1=data.get('val1'),
                val2=data.get('val2')
            )

    class make_response(object):
        def GET(self):
            body = '{"foo": "bar"}'
            mime = 'application/json'
            return wsgi.webpy.make_response(body, mime)

    urls = (
        '/tests/get_site_name/', 'get_site_name',
        '/tests/get_full_path/', 'get_full_path',
        '/tests/make_full_url/', 'make_full_url',
        '/tests/is_post/', 'is_post',
        '/tests/is_idempotent/', 'is_idempotent',
        '/tests/redirect/', 'redirect',
        '/tests/redirected_to/', 'redirected_to',
        '/tests/raise_forbidden/', 'raise_forbidden',
        '/tests/get_from_params/', 'get_from_params',
        '/tests/get_from_headers/', 'get_from_headers',
        '/tests/get_post_data/', 'get_post_data',
        '/tests/make_response/', 'make_response',
    )

    sys.argv = sys.argv[:1] + ['127.0.0.1:8081']
    app = web.application(urls, locals())
    app.run()


@pytest.mark.slow
def test_wsgi_webpy():
    pytest.importorskip('web')
    url_base = 'http://127.0.0.1:8081'
    wsgi_tester(make_wepapp, url_base)
