from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'prajeshanchalia'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/prajesh/Documents/flaskSystem/database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User (UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    phone = db.Column(db.String(10))
    password = db.Column(db.String(80))
    userType = db.Column(db.String(1))


class Vehicle (UserMixin, db.Model):
    vehicleSerial = db.Column(db.Integer, primary_key=True)
    vehicleName = db.Column(db.String(15))
    vehicleModel = db.Column(db.String(50))
    vehicleYear = db.Column(db.String(4))
    vehicleColour = db.Column(db.String(50))
    vehicleMSRP = db.Column(db.Integer)
    vehicleLOP = db.Column(db.Integer)
    vehicleType = db.Column(db.String(1))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm (FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm (FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    phone = StringField('Phone',validators=[InputRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])


class userInfoForm (FlaskForm):
    oldPassword = PasswordField('Old Password', validators=[InputRequired(), Length(min=8, max=80)])
    newPassword = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    phone = StringField('Phone', validators=[Length(min=10, max=10)])
    email = StringField('Email', validators=[Email(message='Invalid email')])


class employeeForm (FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    phone = StringField('Phone',validators=[InputRequired(), Length(min=10, max=10)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])


class vehicleForm (FlaskForm):

    vehicleName =  StringField('Make', validators=[InputRequired(), Length(min=4, max=15)])
    vehicleModel = StringField('Model', validators=[InputRequired(), Length(min=1, max=15)])
    vehicleYear = StringField('Year', validators=[InputRequired(), Length(min=4, max=4)])
    vehicleColour = StringField('Colour', validators=[InputRequired()])
    vehicleMSRP = IntegerField('MSRP', validators=[InputRequired()])
    vehicleLOP = IntegerField('LOP', validators=[InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/unauth')
def unauth():
    userName = current_user.username
    return render_template('unauthorized.html', name=userName)


@app.route('/login', methods=['GET', 'POST'])
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        user_login = User.query.filter_by(username=loginForm.username.data).first()
        if user_login:
            if check_password_hash(user_login.password, loginForm.password.data):
                if user_login.userType == "a":
                    login_user(user_login, remember=loginForm.remember.data)
                    return redirect(url_for('adminDash'))
                elif user_login.userType == "e":
                    login_user(user_login, remember=loginForm.remember.data)
                    return redirect(url_for('employeeDashboard'))
                else:
                    login_user(user_login, remember=loginForm.remember.data)
                    return redirect(url_for('customerDashboard'))
        return "<h1> Invalid Login </h2>"
    return render_template('login.html', form=loginForm)


@app.route('/userInfoUpdate', methods=['GET', 'POST'])
def userInfoUpdate():
    user_login = User.query.filter_by(username=current_user.username).first()
    if user_login.userType == "e":
        dashboardType = 'employeeDashboard'
        dashboardName = 'Employee Dashboard'
    else:
        dashboardType = 'customerDashboard'
        dashboardName = 'Customer Dashboard'
    uiForm = userInfoForm()
    if uiForm.validate_on_submit():

        if user_login:
            if check_password_hash(user_login.password, uiForm.oldPassword.data):
                user_login.password = generate_password_hash(uiForm.newPassword.data, method='sha256')
                if uiForm.email.data != "":
                    user_login.email = uiForm.email.data
                if uiForm.phone.data != "":
                    user_login.phone = uiForm.phone.data
                db.session.commit()
                if user_login.userType=='e':
                    return redirect(url_for('employeeDashboard'))
                else:
                    return redirect(url_for('customerDashboard'))
            else:
                return redirect(url_for('login'))

        return "<h1> Success </h2>"
    return render_template('infoUpdate.html', form=uiForm, dashType=dashboardType, dashName=dashboardName)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    registerForm = RegisterForm()
    if registerForm.validate_on_submit():
        hashed_password = generate_password_hash(registerForm.password.data, method='sha256')
        new_user = User(username = registerForm.username.data, email = registerForm.email.data, phone = registerForm.phone.data, password = hashed_password, userType='c')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('customerDashboard'))
    return render_template('signup.html', form=registerForm)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/adminDash')
@login_required
def adminDash():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'a':
        return redirect(url_for('unauth'))
    return render_template('adminDash.html', name=current_user.username)


@app.route('/adminEmployeeDashboard', methods=['GET', 'POST'])
@login_required
def adminEmployeeDashboard():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'a':
        return redirect(url_for('unauth'))
    empForm = employeeForm()
    if empForm.validate_on_submit():
        hashed_password = generate_password_hash(empForm.password.data, method='sha256')
        new_user = User(username=empForm.username.data, email=empForm.email.data,phone=empForm.phone.data, password=hashed_password, userType='e')
        db.session.add(new_user)
        db.session.commit()

    result_set = User.query.filter_by(userType='e').all()
    return render_template('employeeAdmin.html', form=empForm, result=result_set, name=current_user.username)


@app.route('/deleteEmployee', methods=['GET','POST'])
@login_required
def deleteEmployee():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'a':
        return redirect(url_for('unauth'))
    user=request.args['username']
    delEmp = User.query.filter_by(username=user).first()
    db.session.delete(delEmp)
    db.session.commit()
    return redirect(url_for('adminEmployeeDashboard'))


@app.route('/adminVehicleDashboard', methods=['GET', 'POST'])
@login_required
def adminVehicleDashboard():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'a':
        return redirect(url_for('unauth'))
    vehiForm = vehicleForm()
    if vehiForm.validate_on_submit():
        new_vehicle = Vehicle(vehicleName=vehiForm.vehicleName.data, vehicleModel=vehiForm.vehicleModel.data, vehicleYear=vehiForm.vehicleYear.data, vehicleColour=vehiForm.vehicleColour.data, vehicleMSRP=vehiForm.vehicleMSRP.data, vehicleLOP=vehiForm.vehicleLOP.data, vehicleType='v')
        db.session.add(new_vehicle)
        db.session.commit()
    result_set = Vehicle.query.filter_by(vehicleType='v').all()
    return render_template('vehicleAdmin.html', form=vehiForm, result=result_set, name=current_user.username)


@app.route('/deleteVehicle', methods=['GET','POST'])
@login_required
def deleteVehicle():
    vehiSerial=request.args['vehicleSerial']
    delVeh = Vehicle.query.filter_by(vehicleSerial=vehiSerial).first()
    db.session.delete(delVeh)
    db.session.commit()
    return redirect(url_for('adminVehicleDashboard'))


@app.route('/employeeDashboard', methods=['GET', 'POST'])
@login_required
def employeeDashboard():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'e':
        return redirect(url_for('unauth'))
    result_set = Vehicle.query.filter_by(vehicleType='v').all()
    return render_template('employeeDashboard.html', result=result_set, name=current_user.username)


@app.route('/customerDashboard', methods=['GET', 'POST'])
@login_required
def customerDashboard():
    user_type = User.query.filter_by(username=current_user.username).first()
    if user_type.userType != 'c':
        return redirect(url_for('unauth'))
    result_set = Vehicle.query.filter_by(vehicleType='v').all()
    return render_template('customerDashboard.html', result=result_set, name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)