# coding=utf-8
import os

from flask import g, render_template, redirect, url_for, request

from app import app, db
from auth.models import auth, User
from auth.forms import RegisterForm


@app.route('/', methods=['GET', 'POST'])
def index():
    if g.user:
        return redirect(url_for('profile'))

    form = RegisterForm(request.form)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        user.add_role('user')
        db.commit()  # commit BEFORE doing auth.login!
        auth.login(user)
        return redirect(url_for('profile'))

    return render_template('index.html', **locals())


@app.route('/user/')
@auth.protected()
def profile():
    return render_template('profile.html', **locals())


if __name__ == '__main__':
    # Just for this demo
    db.create_all()
    if not User.by_login(u'example'):
        db.add(User(login=u'example', password='example'))
        db.commit()
    #

    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
