# -*- coding: utf-8 -*-


def eval_url(url):
    if callable(url):
        url = url()
    return url


def setup_for_flask(auth, app, views=True, send_email=None, render=None):
    from flask import g, request, session, render_template

    auth.request = request
    auth.session = session
    if send_email:
        auth.send_email = send_email
    if render == True:
        auth.render = render_template
    elif render:
        auth.render = render

    def set_user():
        g.user = auth.get_user()

    app.before_request_funcs.setdefault(None, []).insert(0, set_user)
    app.jinja_env.globals['csrf_token'] = auth.get_csrf_token
    app.jinja_env.globals['auth'] = auth

    if views:
        if auth.url_sign_in:
            url_sign_in = eval_url(auth.url_sign_in)
            app.route(url_sign_in, methods=['GET', 'POST'])(auth.auth_sign_in)

        if auth.url_sign_out:
            url_sign_out = eval_url(auth.url_sign_out)
            app.route(url_sign_out, methods=['GET', 'POST'])(auth.auth_sign_out)

        if auth.url_change_password:
            url_change_password = eval_url(auth.url_change_password)
            app.route(url_change_password,
                      methods=['GET', 'POST'])(auth.auth_change_password)

        if auth.url_reset_password:
            url_reset_password = eval_url(auth.url_reset_password)
            app.route(url_reset_password,
                      methods=['GET', 'POST'])(auth.auth_reset_password)
            app.route(url_reset_password + '<token>/',
                      methods=['GET', 'POST'])(auth.auth_reset_password)


def setup_for_shake(auth, app, views=True, send_email=None, render=None):
    if send_email:
        auth.send_email = send_email
    if render:
        auth.render = render

    def set_auth_info(request, **kwargs):
        auth.session = request.session
        request.user = auth.get_user()

    app.before_request_funcs.insert(0, set_auth_info)
    app.render.env.globals['csrf_token'] = auth.get_csrf_token
    app.render.env.globals['auth'] = auth

    if views:
        if auth.url_sign_in:
            url_sign_in = eval_url(auth.url_sign_in)
            app.route(url_sign_in, methods=['GET', 'POST'])(auth.auth_sign_in)

        if auth.url_sign_out:
            url_sign_out = eval_url(auth.url_sign_out)
            app.route(url_sign_out, methods=['GET', 'POST'])(auth.auth_sign_out)

        if auth.url_change_password:
            url_change_password = eval_url(auth.url_change_password)
            app.route(url_change_password,
                      methods=['GET', 'POST'])(auth.auth_change_password)

        if auth.url_reset_password:
            url_reset_password = eval_url(auth.url_reset_password)
            app.route(url_reset_password,
                      methods=['GET', 'POST'])(auth.auth_reset_password)
            app.route(url_reset_password + '<token>/',
                      methods=['GET', 'POST'])(auth.auth_reset_password)
