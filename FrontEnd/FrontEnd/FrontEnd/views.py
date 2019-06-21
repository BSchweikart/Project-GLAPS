"""
Routes and views for the flask application.
"""
import functools
import os
import csv
import requests
import json

from flask import (
	Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from FrontEnd.db import get_db
from datetime import datetime
from flask import render_template, Markup
from FrontEnd import app
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore,\
    UserMixin, RoleMixin, login_required 

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///F:/Project-GLAPS/FrontEnd/FrontEnd/glapsdb.sqlite'

#create a secure db connection to be able to use flask security
db2 = SQLAlchemy(app)

mail = Mail(app)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)
app.config.update(
    DEBUG = True,
    # Flask-Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = 'glapsproject@gmail.com',
    MAIL_PASSWORD = 'PA$$word13',
    DEFAULT_MAIL_SENDER = 'glapsproject@gmail.com'
    )

# setup Mail
mail = Mail(app)

# set the db key
app.config.from_mapping(SECRET_KEY='dev',
        DATABASE='glapsdb.sqlite')

roles_users = db2.Table('roles_users', 
                        db2.Column('user_id', db2.Integer(), db2.ForeignKey('user.id')),
                        db2.Column('role_id', db2.Integer(), db2.ForeignKey('role.id')))

class Role(db2.Model, RoleMixin):
    id = db2.Column(db2.Integer(), primary_key=True)
    name = db2.Column(db2.String(80), unique=True)
    description = db2.Column(db2.String(255))

class User(db2.Model, UserMixin):
    id = db2.Column(db2.Integer, primary_key=True)
    username = db2.Column(db2.String(255), unique=True)
    email = db2.Column(db2.String(255), unique=True)
    password = db2.Column(db2.String(255))
    active = db2.Column(db2.Boolean())
    confirmed_at = db2.Column(db2.DateTime())
    roles = db2.relationship('Role', secondary=roles_users,
                            backref=db2.backref('users', lazy='dynamic'))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db2, User, Role)
security = Security(app, user_datastore)

@app.route('/', methods=('GET', 'POST'))
def home():
        load_logged_in_user()
        """Renders the home page."""
        message = ''

        if request.method =='POST':
            name = str(request.form['contactName'])
            subject = str(request.form['contactSubject'])
            content = str(request.form['contactMessage'])
            client = str(request.form['contactEmail'])
            note = name+'\n'+subject+'\n'+content+'\n'+client
            sender = "glapsproject@gmail.com"
            recipient = "glapsproject@yahoo.com"

            if note is not None and note != '':
                msg = Message("Message From Contact Form", sender=sender, recipients=[recipient])
                msg.body = note
                mail.send(msg)
                message = "Your message has been sent."
                return render_template('home.html', title='Home Page', message = message,
                year=datetime.now().year)

        return render_template('home.html',
            title='Home Page', message = message,
            year=datetime.now().year)


#Region - Log In information
@app.route('/login', methods=('GET', 'POST'))
def login():
	"""Log in a registered user by adding the user id to the session."""
	message = "Please login."

	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		db = get_db()
		user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

		if username != "" and username is not None and password !="" and password is not None:
		    if user is not None and check_password_hash(user['password'], password):
		        session.clear()
		        session['user_id'] = user['id']
		        return redirect(url_for('home'))
		    elif user is not None and check_password_hash(user['password'], password) is False:
		        message = "Incorrect Username and/or Password."
		        return render_template('auth/login.html', title='Login', message=message, year=datetime.now().year)
		#flash(error)

	return render_template('auth/login.html', title='Login', message=message, year=datetime.now().year)

def login_required(view):
	"""View decorator that redirects anonymous users to the login page."""
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
			return redirect(url_for('auth.login'))

		return view(**kwargs)

	return wrapped_view

def load_logged_in_user():
	"""If a user id is stored in the session, load the user object from
	the database into ``g.user``."""
	user_id = session.get('user_id')

	if user_id is None:
		g.user = None
	else:
		g.user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

@app.route('/logout')
def logout():
	"""Clear the current session, including the stored user id."""
	session.clear()
	return redirect(url_for('/'))
#end Region
@app.route('/register', methods=('GET', 'POST'))
def register():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        # we're trying to add username to this command string
        #command_string = """SELECT id FROM users WHERE username = ?",
        #(username,)
        #    ).fetchone() is not None:
        #    error = "User {0} is already registered."""
        command_string = "SELECT id from users WHERE username = ?{0}"
        command_string = command_string.format(username)
        print("---\ncommand_string is ", command_string, "\n---\n")
        if not username:
            error = 'Username is required.'
        elif not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)
        elif db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone() is not None:
            error = 'Email {} is already registered.'.format(email)

        if error is None:
            user_datastore.create_user(username=username, email=email, password=generate_password_hash(password))
            db2.session.commit()
            db.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)',(username, email, generate_password_hash(password)))
            db.commit()
            return redirect(url_for('login'))

    return render_template('auth/register.html', title='Register', error=error, year=datetime.now().year)

@app.route('/account', methods=["GET","POST"])
def account():
    load_logged_in_user()
    if request.method == 'POST':
        username = g.user['username']
        fobar = g.user
        db = get_db()
        error = None
        db.execute("DELETE FROM users WHERE username = ?", (username,))
        db.commit()

        if error is None:
            session.clear()
            return redirect(url_for('home')) #redirect to page showing user account deleted

    return render_template('auth/account.html', title='Account', year=datetime.now().year)

@app.route('/comingsoon')
def comingsoon():
    """
        Renders the count down page. This page is a place holder for right now.
    """
    return render_template('comingsoon.html',
        title='Coming Soon',
        year=datetime.now().year)

app.config["DEBUG"] = True
@app.route('/glaps', methods=["GET","POST"]) #this section is used for when the data bases are linked.
def glaps():
    States_Counties = getState_CountiesList()
    valueError = ""
    countyError = ""
    HomeVal2 = ""
    if request.method == "POST":
        County = None
        HomeVal = None

        County = request.form['County']

        if County == "" or County == None:
            countyError = Markup("<font color = red><bold>Please enter a County<bold></font>")
        try:
            HomeVal = int(request.form["HomeVal"])
        except:
            valueError = Markup("<font color = red><bold>Please enter a Home Value<bold></font>")
        if County != "" and HomeVal is not None and County != None:
            for item in States_Counties:
                if County == item:
                    result = getAPI()
                    result = list(result[0].values())

                    actualNoStad = str("{:,}".format(result[0]))
                    actualWStad = str("{:,}".format(result[1]))
                    medianNoStad = str("{:,}".format(result[2]))
                    medianWStad = str("{:,}".format(result[3]))

                    output = Markup("Current Home Value without a Stadium:   " + '<font color="limegreen">$' + actualNoStad + '</font>' + \
                    "<br><br>Current Home Value with a Stadium:   " + '<font color="limegreen">$' + actualWStad + '</font>' + \
                   "<br><br>Median Value of Homes in " + '<font color="yellow">' + County + '</font>' + " without a Stadium:   " + '<font color="limegreen">$' + medianNoStad + '</font>' + \
                   "<br><br>Median Value of Homes in " + '<font color="yellow">' + County + '</font>' + " with a Stadium:   " + '<font color="limegreen">$' + medianWStad + '</font>' + \
                   "<br><br><br><small>The predicted values have a .0008 Mean Squared Error and were calculated using data from the 2017 U.S. Census</small>")

                    return render_template('glaps.html',
                    title='Home Value Predictor',
                    bytearray=datetime.now().year,
                    message=output)

                countyError = Markup("<font color = red><bold>Please enter a County<bold></font>")

    return render_template('glaps.html',
        title='Home Value Predictor',
        bytearray=datetime.now().year,
        message= 'Enter your location on the map and your current home value below:',
        countyError = countyError, valueError = valueError)
    States_Counties = getState_CountiesList()
    valueError = ""
    countyError = ""
    if request.method == "POST":
        County = None
        HomeVal = None

        County = request.form['County']

        if County == "" or County == None:
            countyError = Markup("<font color = red><bold>Please enter a County<bold></font>")
        try:
            HomeVal = int(request.form["HomeVal"])
        except:
            valueError = Markup("<font color = red><bold>Please enter a Home Value<bold></font>")
        if County != "" and HomeVal is not None and County != None:
            for item in States_Counties:
                if County == item:
                    result = getAPI()
                    result = list(result[0].values())

                    actualNoStad = str("{:,}".format(result[0]))
                    actualWStad = str("{:,}".format(result[1]))
                    medianNoStad = str("{:,}".format(result[2]))
                    medianWStad = str("{:,}".format(result[3]))

                    output = Markup("Current Home Value without a Stadium:   " + '<font color="limegreen">$' + actualNoStad + '</font>' + \
                    "<br><br>Current Home Value with a Stadium:   " + '<font color="limegreen">$' + actualWStad + '</font>' + \
                   "<br><br>Median Value of Homes in " + '<font color="yellow">' + County + '</font>' + " without a Stadium:   " + '<font color="limegreen">$' + medianNoStad + '</font>' + \
                   "<br><br>Median Value of Homes in " + '<font color="yellow">' + County + '</font>' + " with a Stadium:   " + '<font color="limegreen">$' + medianWStad + '</font>' + \
                   "<br><br><br><small>The predicted values have a .0008 mean squared error and were calculated using data from the 2017 U.S. Census</small>")

                    return render_template('glaps.html',
                    title='Home Value Predictor',
                    bytearray=datetime.now().year,
                    message=output)

                countyError = Markup("<font color = red><bold>Please enter a County<bold></font>")

    return render_template('glaps.html',
        title='Home Value Predictor',
        bytearray=datetime.now().year,
        message= 'Enter your location on the map and your current home value below:',
        countyError = countyError, valueError = valueError)


#view for the facets.html page
@app.route('/facets')
def facets():
    return render_template('facets.html')


#View for the facets.html page
@app.route('/visualizations')
def visualizations():
    """Renders the visualizations page."""
    return render_template('visualizations.html')
    """Renders the visualizations page."""
    return render_template('visualizations.html')

#method that gets data from GLAPS API
def getAPI():

    myreqs = {"HomeVal":request.form['HomeVal'], "County":request.form['County']}
    url = requests.get("http://gmastorg.pythonanywhere.com/GLAPS", params=myreqs)
    responseJson = json.loads(url.text)

    return responseJson

def getState_CountiesList():

    States_Counties = []
    path = os.path.abspath("States_Counties.csv")
    with open(path) as file:
        inputFile = csv.reader(file)

        for row in inputFile:
             State_County = row[0]
             States_Counties.append(State_County)

    States_Counties.pop(0)
    return States_Counties

    States_Counties = []
    path = os.path.abspath("States_Counties.csv")
    with open(path) as file:
        inputFile = csv.reader(file)

        for row in inputFile:
             State_County = row[0]
             States_Counties.append(State_County)

    States_Counties.pop(0)
    return States_Counties

#Region Misc Pages
@app.errorhandler(500)
def server_not_found(e):
    # note that we set the 500 status explicitly
    return render_template('errors/500.html'), 500

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('errors/404.html'), 404
#End Region Misc Pages