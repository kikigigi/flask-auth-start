from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("FLASK_AUTH_START_SECRET_KEY")
print(f'key = {os.environ.get("FLASK_AUTH_START_SECRET_KEY")}')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    print('THERE')
    if request.method == 'POST':
        print('HERE')
        name = request.form['name']
        entered_password = request.form['password']
        hashed_password = generate_password_hash(entered_password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
                        name = name,
                        email = request.form['email'],
                        password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('secrets.html', name=name)
    return render_template("register.html")





@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename='files/cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
