from flask import Flask, render_template, request, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email  # unused: EqualTo
from yelp import find_coffee
from flask_login import login_user, login_required, logout_user  # unused: current_user
from models import db, login, UserModel

class LoginForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired(), Length(min=6, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label="Login")


class RegisterForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired(), Length(min=6, max=20)])
    email = StringField(label="Email", validators=[DataRequired(), Email(), Length(max=80)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label="Register")


app = Flask(__name__)
app.secret_key = "a secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login.init_app(app)

def addUser(username, email, password):
    # FIXME check if email or username already exists
    # currently instead doing this in form handling.
    user = UserModel()
    user.username = username
    user.email = email
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

@app.before_first_request
def create_table():
    db.create_all()

@app.route("/home")
@login_required
def findCoffee():
    return render_template("home.html", myData=find_coffee())

@app.route("/")
def redirectToLogin():
    return redirect("/login")

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if request.method == "POST":
            username = request.form["username"]
            pw = request.form["password"]
            user = UserModel.query.filter_by(username=username).first()
            if user is None:
                form.username.errors = ["No such user."]
            elif not user.check_password(pw):
                form.username.errors = ["Password not accepted."]
            elif not login_user(user):
                form.username.errors = ["Login failed."]
            else:
                return redirect('/home')
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            username = request.form["username"]
            email = request.form["email"]
            pw = request.form["password"]
            user = UserModel.query.filter_by(username=username).first()
            if user is not None:
                form.username.errors = ['User already exists with this username']
            user = UserModel.query.filter_by(email=email).first()
            if user is not None:
                form.email.errors = ['User already exists with this email']
            if not form.username.errors and not form.email.errors:
                addUser(username=username, email=email, password=pw)
                # TODO check addUser() retval
                return redirect('/login')
    return render_template("register.html", form=form)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
