# coding=utf-8
from flask import g, redirect, url_for

from app import app, db

from .models import auth


@app.route('/delete-me/')
@auth.protected(csrf=True, role='user')
def delete_me():
    db.session.delete(g.user)
    db.commit()
    auth.logout()
    return redirect(url_for('index'))
