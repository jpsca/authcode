# coding=utf-8
from __future__ import print_function, absolute_import

from authcode import wsgi
import pytest

from .helpers import wsgi_tester


def make_wepapp():
    import cherrypy

    class GetSiteName(object):
        exposed = True

        def GET(self):
            return wsgi.cherrypy.get_site_name(cherrypy.request)

    class GetFullPath(object):
        exposed = True

        def GET(self, foo=None):
            return wsgi.cherrypy.get_full_path(cherrypy.request)

    class MakeFullURL(object):
        exposed = True

        def GET(self):
            return wsgi.cherrypy.make_full_url(
                cherrypy.request, '/tests/get_site_name/')

    class IsPost(object):
        exposed = True

        def GET(self):
            return 'yes' if wsgi.cherrypy.is_post(cherrypy.request) else 'no'

        def HEAD(self):
            assert not wsgi.cherrypy.is_post(cherrypy.request)

        def POST(self):
            return 'yes' if wsgi.cherrypy.is_post(cherrypy.request) else 'no'

        def PUT(self):
            return 'yes' if wsgi.cherrypy.is_post(cherrypy.request) else 'no'

        def DELETE(self):
            return 'yes' if wsgi.cherrypy.is_post(cherrypy.request) else 'no'

    class IsIdempotent(object):
        exposed = True

        def GET(self):
            return 'yes' if wsgi.cherrypy.is_idempotent(cherrypy.request) else 'no'

        def HEAD(self):
            assert wsgi.cherrypy.is_idempotent(cherrypy.request)

        def POST(self):
            return 'yes' if wsgi.cherrypy.is_idempotent(cherrypy.request) else 'no'

        def PUT(self):
            return 'yes' if wsgi.cherrypy.is_idempotent(cherrypy.request) else 'no'

        def DELETE(self):
            return 'yes' if wsgi.cherrypy.is_idempotent(cherrypy.request) else 'no'

    class Redirect(object):
        exposed = True

        def GET(self):
            return wsgi.cherrypy.redirect('/tests/redirected_to/')

    class RedirectedTo(object):
        exposed = True

        def GET(self):
            return u'Hello world'

    class RaiseForbidden(object):
        exposed = True

        def GET(self):
            return wsgi.cherrypy.raise_forbidden('Custom forbidden message')

    class GetFromParams(object):
        exposed = True

        def GET(self, foo=None):
            return wsgi.cherrypy.get_from_params(cherrypy.request, 'foo')

    class GetFromHeaders(object):
        exposed = True

        def GET(self):
            return wsgi.cherrypy.get_from_headers(cherrypy.request, 'X-CSRFToken')

    class GetPostData(object):
        exposed = True

        def POST(self, val1, val2):
            data = wsgi.cherrypy.get_post_data(cherrypy.request)
            return '{val1},{val2}'.format(
                val1=data.get('val1'),
                val2=data.get('val2')
            )

    class MakeResponse(object):
        exposed = True

        def GET(self):
            body = b'{"foo": "bar"}'
            mime = 'application/json'
            return wsgi.cherrypy.make_response(body, mime)

    class Tests(object):
        exposed = True
        get_site_name = GetSiteName()
        get_full_path = GetFullPath()
        make_full_url = MakeFullURL()
        is_post = IsPost()
        is_idempotent = IsIdempotent()
        redirect = Redirect()
        redirected_to = RedirectedTo()
        raise_forbidden = RaiseForbidden()
        get_from_params = GetFromParams()
        get_from_headers = GetFromHeaders()
        get_post_data = GetPostData()
        make_response = MakeResponse()

    class API(object):
        exposed = True
        tests = Tests()

    config = {
        '/': {
            'request.dispatch': cherrypy.dispatch.MethodDispatcher()
        },
    }
    cherrypy.server.socket_host = '127.0.0.1'
    cherrypy.quickstart(API(), config=config)


@pytest.mark.slow
def test_wsgi_cherrypy():
    pytest.importorskip('cherrypy')
    url_base = 'http://127.0.0.1:8080'
    wsgi_tester(make_wepapp, url_base)
