# -*- coding: utf-8 -*-
from datetime import datetime

from flask import g, render_template, request, redirect, url_for

from app import app, db

from .models import auth, User
from .oauth import twitter, facebook


@app.route('/sign-in/')
def login():
    if g.user:
        return redirect(url_for('profile'))
    return render_template('login.html')


@app.route('/sign-out/')
def logout():
    auth.logout()
    return redirect(url_for('index'))


@app.route('/sign-in/twitter/')
def twitter_login():
    next = request.args.get('next') or None
    return twitter.authorize(callback=url_for('twitter_authorized',
        next=next))


@app.route('/sign-in/twitter/authorized/')
@twitter.authorized_handler
def twitter_authorized(resp):
    if resp is None:
        return redirect(url_for('login'))

    user = User.by_login(resp['screen_name'])
    if user is None:
        user = User(login=resp['screen_name'],
            twitter_token=resp['oauth_token'],
            twitter_secret=resp['oauth_token_secret'])
        # Be careful to actually create the user and commit before
        # to log in it
        db.add(user)
        db.commit()

    auth.login(user)
    user.last_sign_in = datetime.utcnow()
    db.commit()

    next = request.args.get('next')
    return redirect(next or url_for('profile'))


@app.route('/sign-in/facebook/')
def facebook_login():
    next = request.args.get('next') or None
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=next))


@app.route('/sign-in/facebook/authorized/')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return redirect(url_for('login'))

    user.last_sign_in = datetime.utcnow()
    db.commit()
    
    auth.login(user)
    next = request.args.get('next')
    return redirect(next or url_for('profile'))

