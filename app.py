from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo

# Создание приложения Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Модель пользователя для базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтверждение пароля', validators=[DataRequired(), EqualTo('password')])

# Форма для входа
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])

# Функция загрузки пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Главная страница
@app.route("/")
def home():
    return render_template('home.html')

# Страница регистрации
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверка, существует ли уже пользователь с таким именем или email
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Имя пользователя уже существует. Пожалуйста, выберите другое.', 'danger')
            return redirect(url_for('register'))

        if existing_email:
            flash('Адрес электронной почты уже существует. Пожалуйста, используйте другой.', 'danger')
            return redirect(url_for('register'))

        # Хеширование пароля
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Создание нового пользователя
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Ваша учетная запись создана!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# Страница входа
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

# Страница профиля
@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html', name=current_user.username)

# Страница выхода
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Запуск приложения
if __name__ == '__main__':
    with app.app_context():  # Оборачиваем создание таблиц в контекст приложения
        db.create_all()  # Создание таблиц в базе данных
    app.run(debug=True)