# -*- coding: utf-8 -*-


def setup_for_flask(auth, app, views=True, send_email=None, render=False):
    from flask import g, request, session, render_template

    auth.request = request
    auth.session = session
    if send_email:
        auth.send_email = send_email
    if render:
        auth.render = render_template

    @app.before_request
    def set_user():
        g.user = auth.get_user()
    
    app.jinja_env.globals['csrf_token'] = auth.get_csrf_token
    app.jinja_env.globals['auth'] = auth

    if views:
        app.route(auth.url_sign_in,
            methods=['GET','POST'])(auth.auth_sign_in)
        app.route(auth.url_sign_out,
            methods=['GET','POST'])(auth.auth_sign_out)

        if auth.url_change_password:
            app.route(auth.url_change_password,
                methods=['GET','POST'])(auth.auth_change_password)

        if auth.url_reset_password:
            app.route(auth.url_reset_password, 
                methods=['GET','POST'])(auth.auth_reset_password)
            app.route(auth.url_reset_password + '<token>/',
                methods=['GET','POST'])(auth.auth_reset_password)


def setup_for_shake(auth, app, views=True, send_email=None, render=None):
    if send_email:
        auth.send_email = send_email
    if render:
        auth.render = render

    @app.before_request
    def set_auth_info(request, **kwargs):
        auth.session = request.session
        request.user = auth.get_user()

    app.render.env.globals['csrf_token'] = auth.get_csrf_token
    app.render.env.globals['auth'] = auth

    if views:
        app.route(auth.url_sign_in,
            methods=['GET','POST'])(auth.auth_sign_in)
        app.route(auth.url_sign_out,
            methods=['GET','POST'])(auth.auth_sign_out)

        if auth.url_change_password:
            app.route(auth.url_change_password,
                methods=['GET','POST'])(auth.auth_change_password)

        if auth.url_reset_password:
            app.route(auth.url_reset_password, 
                methods=['GET','POST'])(auth.auth_reset_password)
            app.route(auth.url_reset_password + '<token>/',
                methods=['GET','POST'])(auth.auth_reset_password)

