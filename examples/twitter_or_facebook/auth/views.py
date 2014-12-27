# coding=utf-8
from flask import g, render_template, redirect, url_for

from app import app, db

from .models import auth


@app.route('/sign-in/')
def sign_in():
    return render_template('login.html')


@app.route('/sign-out/')
@auth.protected(csrf=True)
def sign_out():
    auth.logout()
    return redirect(url_for('index'))


@app.route('/delete_me/')
@auth.protected(csrf=True)
def delete_me():
    db.session.delete(g.user)
    db.commit()
    auth.logout()
    return redirect(url_for('index'))
