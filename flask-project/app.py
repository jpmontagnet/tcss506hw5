from flask import Flask, render_template, request, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email  # unused: EqualTo
from yelp import find_coffee
from flask_login import login_user, login_required, logout_user  # unused: current_user
from models import db, login, UserModel

class LoginForm(FlaskForm):
    email = StringField(label="Enter email", validators=[DataRequired(), Email(), Length(min=6, max=20)])
    password = PasswordField(label="Enter password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label="Login")


class RegisterForm(FlaskForm):
    email = StringField(label="Enter email", validators=[DataRequired(), Email(), Length(min=6, max=20)])
    password = PasswordField(label="Enter password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label="Register")


app = Flask(__name__)
app.secret_key = "a secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login.init_app(app)

# Since a self-registration page exists, no need to pre-populate
users_initial = [("lhhung@uw.edu", "qwerty123")]

def addUser(email, password):
    # check if email or username exits
    user = UserModel()
    user.set_password(password)
    user.email = email
    db.session.add(user)
    db.session.commit()

@app.before_first_request
def create_table():
    db.create_all()
    # Since a self-registration page exists, no need to pre-populate
    # for u in users_initial:
    #     found = UserModel.query.filter_by(email="lhhung@uw.edu").first()
    #     if found is None:
    #         addUser(u[0], u[1])
    
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
            email = request.form["email"]
            pw = request.form["password"]
            user = UserModel.query.filter_by(email=email).first()
            if user is not None and user.check_password(pw):
                login_user(user)
                return redirect('/home')
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    error = None
    if request.method == "POST":
        if form.validate_on_submit():
            email = request.form["email"]
            pw = request.form["password"]
            user = UserModel.query.filter_by(email=email).first()
            if user is not None:
                form.email.errors = ['User already exists']
            else:
                # TODO check addUser() retval
                # TODO store pw hashed
                addUser(email=email, password=pw)
                return redirect('/login')
    return render_template("register.html", form=form)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
