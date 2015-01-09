# coding=utf-8
from time import sleep
import threading

import requests


URL_BASE = 'http://localhost:{port}'


def wsgi_tester(run_func, port):
    t = threading.Thread(target=run_func)
    t.daemon = True
    t.start()
    sleep(1)
    _run_tests(port)


def _run_tests(port):
    url_base = URL_BASE.format(port=port)
    _test_get_site_name(url_base)
    _test_get_full_path(url_base)
    _test_make_full_url(url_base)
    _test_is_post(url_base)
    _test_is_idempotent(url_base)
    _test_redirect(url_base)
    _test_raise_forbidden(url_base)
    _test_get_from_params(url_base)
    _test_get_from_headers(url_base)
    _test_get_post_data(url_base)
    _test_make_response(url_base)


def _test_get_site_name(url_base):
    req = requests.get(url_base + '/tests/get_site_name/', timeout=5)
    assert url_base.replace('http://', '') in req.text


def _test_get_full_path(url_base):
    full_path1 = '/tests/get_full_path/'
    full_path2 = '/tests/get_full_path'
    req = requests.get(url_base + full_path1)
    assert (
        full_path1 in req.text or
        full_path2 in req.text
    )

    full_path1 = '/tests/get_full_path/?foo=bar'
    full_path2 = '/tests/get_full_path?foo=bar'
    req = requests.get(url_base + full_path1)
    assert (
        full_path1 in req.text or
        full_path2 in req.text
    )


def _test_make_full_url(url_base):
    req = requests.get(url_base + '/tests/make_full_url/')
    url = url_base + '/tests/get_site_name/'
    assert url in req.text


def _test_is_post(url_base):
    req = requests.get(url_base + '/tests/is_post/')
    assert req.text == 'no'

    requests.head(url_base + '/tests/is_post/')

    req = requests.post(url_base + '/tests/is_post/')
    assert req.text == 'yes'

    req = requests.put(url_base + '/tests/is_post/')
    assert req.text == 'no'

    req = requests.delete(url_base + '/tests/is_post/')
    assert req.text == 'no'


def _test_is_idempotent(url_base):
    req = requests.get(url_base + '/tests/is_idempotent/')
    assert req.text == 'yes'

    requests.head(url_base + '/tests/is_idempotent/')

    req = requests.post(url_base + '/tests/is_idempotent/')
    assert req.text == 'no'

    req = requests.put(url_base + '/tests/is_idempotent/')
    assert req.text == 'no'

    req = requests.delete(url_base + '/tests/is_idempotent/')
    assert req.text == 'no'


def _test_redirect(url_base):
    req = requests.get(url_base + '/tests/redirect/')
    assert req.text == u'Hello world'


def _test_raise_forbidden(url_base):
    req = requests.get(url_base + '/tests/raise_forbidden/')
    assert req.status_code == 403


def _test_get_from_params(url_base):
    req = requests.get(url_base + '/tests/get_from_params/?foo=bar')
    assert req.text == 'bar'

    data = {'foo': u'meh'}
    req = requests.post(url_base + '/tests/get_from_params/?foo=bar', data=data)
    assert req.text == 'bar'


def _test_get_from_headers(url_base):
    headers = {'X-CSRFToken': 'foobar'}
    req = requests.get(url_base + '/tests/get_from_headers/', headers=headers)
    assert req.text == 'foobar'


def _test_get_post_data(url_base):
    data = {'val1': u'foo', 'val2': u'bar'}
    req = requests.post(url_base + '/tests/get_post_data/', data=data)
    assert req.text == u'foo,bar'


def _test_make_response(url_base):
    req = requests.get(url_base + '/tests/make_response/')
    assert req.text == '{"foo": "bar"}'
    assert req.headers['Content-Type'] == 'application/json'
