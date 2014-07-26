# coding=utf-8
import pytest

from authcode._compat import to_unicode


def test_webob():
    from authcode.wsgi import webob as w
    from webob import Request

    path = u'/hello?world=1'
    data = {'foo': u'some text'}
    headers = {'foo': u'bar'}
    req = Request.blank(path, headers=headers, POST=data)

    assert w.get_site_name(req) == 'localhost'
    assert w.get_full_path(req) == path
    assert w.make_full_url(req, u'/hey/') == 'http://localhost/hey/'
    assert w.is_post(req)
    assert w.not_safe_method(req)

    with pytest.raises(Exception):
        w.redirect('http://google.com')

    with pytest.raises(Exception):
        w.raise_forbidden('hello')

    assert w.get_from_params(req, 'foo') == data['foo']
    assert w.get_from_headers(req, 'foo') == headers['foo']
    assert 'foo' in w.get_post_data(req)

    req = Request.blank(path)
    assert not w.is_post(req)
    assert not w.not_safe_method(req)


# def test_cherrypy():
#     from authcode.wsgi import cherrypy as w
#     import cherrypy

#     path = '/hello?world=1'
#     data = {'foo': 'some text'}
#     headers = {'foo': 'bar'}

#     req = ???

#     assert w.get_site_name(req) == 'localhost'
#     assert w.get_full_path(req) == path
#     assert w.make_full_url(req, '/hey/') == 'http://localhost/hey/'
#     assert w.is_post(req)

#     with pytest.raises(Exception):
#         w.redirect('http://google.com')

#     with pytest.raises(Exception):
#         w.raise_forbidden('hello')

#     assert w.get_from_params(req, 'foo') == data['foo']
#     assert w.get_from_headers(req, 'foo') == headers['foo']
#     assert 'foo' in w.get_post_data(req)

#     req = ???
#     assert not w.is_post(req)


def test_werkzeug():
    from authcode.wsgi import werkzeug as w
    from werkzeug.test import EnvironBuilder
    from werkzeug.wrappers import Request

    path = '/hello?world=1'
    data = {'foo': 'some text'}
    headers = {'foo': 'bar'}

    builder = EnvironBuilder(path=path, method='POST', data=data, headers=headers)
    env = builder.get_environ()
    req = Request(env)

    assert w.get_site_name(req) == 'localhost'
    assert w.get_full_path(req) == path
    assert w.make_full_url(req, u'/hey/') == 'http://localhost/hey/'
    assert w.is_post(req)

    r = w.redirect('http://google.com')
    assert u'http://google.com' in to_unicode(r.data)
    assert r.status.upper() == '303 SEE OTHER'

    with pytest.raises(Exception):
        w.raise_forbidden('hello')

    assert w.get_from_params(req, 'foo') == data['foo']
    assert w.get_from_headers(req, 'foo') == headers['foo']
    assert 'foo' in w.get_post_data(req)

    builder = EnvironBuilder(path=path, method='GET')
    env = builder.get_environ()
    req = Request(env)
    assert not w.is_post(req)
