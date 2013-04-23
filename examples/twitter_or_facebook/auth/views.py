# -*- coding: utf-8 -*-
from flask import g, render_template, redirect, url_for

from app import app, db

from .models import auth, User


@app.route('/sign-in/')
def login():
    return render_template('login.html')


@app.route('/sign-out/')
def logout():
    auth.logout()
    return redirect(url_for('index'))


@app.route('/delete_me/')
@auth.protected(csrf=True)
def delete_me():
    db.session.delete(g.user)
    db.commit()
    auth.logout()
    return redirect(url_for('index'))


