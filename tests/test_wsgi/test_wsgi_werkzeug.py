# coding=utf-8
from __future__ import print_function, absolute_import

from authcode import wsgi
import pytest

from .helpers import wsgi_tester


request = None


def make_wepapp():
    from werkzeug.exceptions import HTTPException
    from werkzeug.routing import Map, Rule
    from werkzeug.serving import run_simple
    from werkzeug.wrappers import Request, Response

    class Application(object):
        def __init__(self):
            self.url_map = Map([
                Rule('/tests/get_site_name/', endpoint='get_site_name'),
                Rule('/tests/get_full_path/', endpoint='get_full_path'),
                Rule('/tests/make_full_url/', endpoint='make_full_url'),
                Rule('/tests/is_post/', endpoint='is_post'),
                Rule('/tests/is_idempotent/', endpoint='is_idempotent'),
                Rule('/tests/redirect/', endpoint='redirect'),
                Rule('/tests/redirected_to/', endpoint='redirected_to'),
                Rule('/tests/raise_forbidden/', endpoint='raise_forbidden'),
                Rule('/tests/get_from_params/', endpoint='get_from_params'),
                Rule('/tests/get_from_headers/', endpoint='get_from_headers'),
                Rule('/tests/get_post_data/', endpoint='get_post_data'),
                Rule('/tests/make_response/', endpoint='make_response'),
            ])

        def __call__(self, environ, start_response):
            return self.wsgi_app(environ, start_response)

        def wsgi_app(self, environ, start_response):
            request = Request(environ)
            response = self.dispatch_request(request)
            if not isinstance(response, Response):
                response = Response(response)
            return response(environ, start_response)

        def dispatch_request(self, request):
            try:
                adapter = self.url_map.bind_to_environ(request.environ)
                endpoint, values = adapter.match()
                return getattr(self, 'on_' + endpoint)(request, **values)
            except HTTPException as e:
                return Response(str(e), status=e.code)

        def on_get_site_name(self, request):
            return wsgi.werkzeug.get_site_name(request)

        def on_get_full_path(self, request):
            return wsgi.werkzeug.get_full_path(request)

        def on_make_full_url(self, request):
            return wsgi.werkzeug.make_full_url(request, '/tests/get_site_name/')

        def on_is_post(self, request):
            return 'yes' if wsgi.werkzeug.is_post(request) else 'no'

        def on_is_idempotent(self, request):
            return 'yes' if wsgi.werkzeug.is_idempotent(request) else 'no'

        def on_redirect(self, request):
            return wsgi.werkzeug.redirect('/tests/redirected_to/')

        def on_redirected_to(self, request):
            return u'Hello world'

        def on_raise_forbidden(self, request):
            return wsgi.werkzeug.raise_forbidden('Custom forbidden message')

        def on_get_from_params(self, request):
            return wsgi.werkzeug.get_from_params(request, 'foo')

        def on_get_from_headers(self, request):
            return wsgi.werkzeug.get_from_headers(request, 'X-CSRFToken')

        def on_get_post_data(self, request):
            data = wsgi.werkzeug.get_post_data(request)
            return '{val1},{val2}'.format(
                val1=data.get('val1'),
                val2=data.get('val2')
            )

        def on_make_response(self, request):
            body = '{"foo": "bar"}'
            mime = 'application/json'
            return wsgi.werkzeug.make_response(body, mime)

    app = Application()
    run_simple('0.0.0.0', 8082, app, use_debugger=False, use_reloader=False)


@pytest.mark.slow
def test_wsgi_werkzeug():
    wsgi_tester(make_wepapp, 8082)
