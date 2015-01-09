# coding=utf-8
from __future__ import print_function, absolute_import

from authcode import wsgi
import pytest

from .helpers import wsgi_tester


def make_wepapp():
    from bottle import Bottle, run, request

    app = Bottle()

    @app.route('/tests/get_site_name/')
    def get_site_name():
        return wsgi.bottle.get_site_name(request)

    @app.route('/tests/get_full_path/')
    def get_full_path():
        return wsgi.bottle.get_full_path(request)

    @app.route('/tests/make_full_url/')
    def make_full_url():
        return wsgi.bottle.make_full_url(request, '/tests/get_site_name/')

    @app.route('/tests/is_post/', ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'])
    def is_post():
        return 'yes' if wsgi.bottle.is_post(request) else 'no'

    @app.route('/tests/is_idempotent/', ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'])
    def is_idempotent():
        return 'yes' if wsgi.bottle.is_idempotent(request) else 'no'

    @app.route('/tests/redirect/')
    def redirect():
        return wsgi.bottle.redirect('/tests/redirected_to/')

    @app.route('/tests/redirected_to/')
    def redirected_to():
        return u'Hello world'

    @app.route('/tests/raise_forbidden/')
    def raise_forbidden():
        return wsgi.bottle.raise_forbidden('Custom forbidden message')

    @app.route('/tests/get_from_params/', ['GET', 'POST'])
    def get_from_params():
        return wsgi.bottle.get_from_params(request, 'foo')

    @app.route('/tests/get_from_headers/')
    def get_from_headers():
        return wsgi.bottle.get_from_headers(request, 'X-CSRFToken')

    @app.route('/tests/get_post_data/', ['POST'])
    def get_post_data():
        data = wsgi.bottle.get_post_data(request)
        return '{val1},{val2}'.format(
            val1=data.get('val1'),
            val2=data.get('val2')
        )

    @app.route('/tests/make_response/')
    def make_response():
        body = '{"foo": "bar"}'
        mime = 'application/json'
        return wsgi.bottle.make_response(body, mime)

    run(app, host='0.0.0.0', port=8081, debug=False)


@pytest.mark.slow
def test_wsgi_bottle():
    wsgi_tester(make_wepapp, 8081)
