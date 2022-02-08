from crypt import methods
from django import views
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_required, login_user, logout_user, current_user 
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                login_user(user,remember=True)
                flash('Te has loggeado correctamente',category='succes')
                return redirect(url_for('views.home'))

            else:
                flash('Contraseña incorrecta', category='error') 
        else:
            flash('Usuario inexistente',category='error')   


    data = request.form
    return render_template('login.html',user=current_user)

@auth.route('/logout')
@login_required

def logout():
    logout_user()
    return redirect(url_for('auth.login'))



@auth.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('El usuario ya existe', category='error')
            pass
        elif len(email) < 4:
            flash('El email debe tener una longitud mayor a 3 caracteres',
                  category='error')
            pass
        elif len(first_name) < 4:
            flash('El nombre debe tener una longitud mayor a 3 caracteres',
                  category='error')
            pass
        elif len(password1) < 4:
            flash(
                'La contraseña debe tener una longitud mayor a 5 caracteres', category='error')
            pass
        elif password1 != password2:
            flash('Las contraseñas deben ser identicas', category='error')
            pass
        # elif email=="" or password1=="" or password2=="" or firstName=="":
        #     flash('Complete el formulario',category='error')
        #     pass
        else:
            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user,remember=True)
            flash('Cuenta creada, felicitaciones.', category='success')
            return redirect(url_for('views.home'))
        print(email, first_name, password1)

    return render_template('sign_up.html',user=current_user)
