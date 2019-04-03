#import functools

#from flask import (
#	Blueprint, flash, g, redirect, render_template, request, session, url_for
#)
#from werkzeug.security import check_password_hash, generate_password_hash

#from FrontEnd.db import get_db

#bp = Blueprint('auth', __name__, url_prefix='/auth')

#def login_required(view):
#	"""View decorator that redirects anonymous users to the login page."""
#	@functools.wraps(view)
#	def wrapped_view(**kwargs):
#		if g.user is None:
#			return redirect(url_for('auth.login'))

#		return view(**kwargs)

#	return wrapped_view

#@bp.before_app_request
#def load_logged_in_user():
#	"""If a user id is stored in the session, load the user object from
#	the database into ``g.user``."""
#	user_id = session.get('user_id')

#	if user_id is None:
#		g.user = None
#	else:
#		g.user = get_db().execute(
#			'SELECT * FROM user WHERE id = ?', (user_id,)
#		).fetchone()

#@bp.route('/register', methods=('GET', 'POST'))
#def register():
#    if request.method == 'POST':
#        username = request.form['username']
#        email = request.form['email']
#        password = request.form['password']
#        db = get_db()
#        error = None

#        if not username:
#            error = 'Username is required.'
#        elif not email:
#            error = 'Email is required.'
#        elif not password:
#            error = 'Password is required.'
#        elif db.execute(
#            'SELECT id FROM users WHERE username = ?', (username,)
#            ).fetchone() is not None:
#            error = 'User {0} is already registered.'.format(username)

#        if error is None:
#            db.execute('INSERT INTO users (username, email, password) VALUES (?, ?',(username, generate_password_hash(password)))
#            db.commit()
#            return redirect(url_for('login'))

#                    #flash(error)
#    return render_template('register.html')

#@bp.route('/login', methods=('GET', 'POST'))
#def login():
#	"""Log in a registered user by adding the user id to the session."""
#	if request.method == 'POST':
#		username = request.form['username']
#		password = request.form['password']
#		db = get_db()
#		error = None
#		user = db.execute(
#			'SELECT * FROM user WHERE username = ?', (username,)
#		).fetchone()

#		if user is None:
#			error = 'Incorrect username.'
#		elif not check_password_hash(user['password'], password):
#			error = 'Incorrect password.'

#		if error is None:
#			# store the user id in a new session and return to the index
#			session.clear()
#			session['user_id'] = user['id']
#			return redirect(url_for('comingsoon')) #Need to change to a new screen

#		flash(error)

#	return render_template('login.html')

#@app.route('/logout')
#def logout():
#	"""Clear the current session, including the stored user id."""
#	session.clear()
#	return redirect(url_for('comingsoon'))