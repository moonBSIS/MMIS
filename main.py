from flask import Flask, render_template, request, flash, redirect, session, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from datetime import datetime
from flask_session import Session
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, HiddenField, SelectField, PasswordField
from wtforms.validators import DataRequired, Length, Optional, EqualTo, ValidationError, Email
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import os
import csv
import io
import numpy as np
import joblib

app = Flask(__name__, static_folder='static')


UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


app.config['SECRET_KEY'] = '4046bde895cc19ca9cbd373a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:1234@localhost/malnutritiondb3'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER) 

db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)


# Load the logistic regression model
model = joblib.load('multioutput_rf.pkl')
barangays = [
            'Aganan', 'Amparo', 'Anilao', 'Balabag', 'Cabugao Norte', 'Cabugao Sur',
            'Jibao-an', 'Mali-ao', 'Pagsanga-an', 'Pal-agon', 'Pandac', 'Purok 1',
            'Purok 2', 'Purok 3', 'Purok 4', 'Tigum', 'Ungka 1', 'Ungka 2'
        ]
    
# RCHU_ACCOUNTS = {
#     "rch_user1": "rch_password1",
#     "rch_user2": "rch_password2"
# }

# # RCHU authentication function
# def authenticate_rchu(username, password):
#     if username in RCHU_ACCOUNTS and RCHU_ACCOUNTS[username] == password:
#         return username 
#     return None

# Association Table for BHW and Barangays (many-to-many relationship)
bhw_barangay = db.Table('bhw_barangay',
    db.Column('bhw_id', db.Integer, db.ForeignKey('admin.id'), primary_key=True),
    db.Column('barangay_id', db.Integer, db.ForeignKey('barangay.id'), primary_key=True)
)

class Barangay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, unique=True)

    def __repr__(self):
        return f'Barangay {self.name}'
    
    
# User Class
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'), nullable=True)

    # Relationship with Barangay
    barangay = db.relationship('Barangay', backref='users')

    # One-to-many relationship with Household
    households = db.relationship(
        "Household",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # Relationship for PredictionData
    predictions = db.relationship(
        "PredictionData",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Child Class
class Child(db.Model):
    __tablename__ = 'child'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'), nullable=False) 
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    parent_id = db.Column(db.Integer, nullable=False)

    # Relationships
    predictions = db.relationship("PredictionData", back_populates="child")
    user = db.relationship("User", backref="children")
    barangay = db.relationship("Barangay", backref="children")  

    def __repr__(self):
        return f'<Child {self.first_name} {self.last_name}>'


class ChildForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Household Class
class Household(db.Model):
    __tablename__ = 'household'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    mother_first_name = db.Column(db.String(100), nullable=False)
    mother_last_name = db.Column(db.String(100), nullable=False)
    father_first_name = db.Column(db.String(100), nullable=False)
    father_last_name = db.Column(db.String(100), nullable=False)
    mother_age = db.Column(db.Integer, nullable=False)
    father_age = db.Column(db.Integer, nullable=False)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'))

    # Relationship with User
    user = db.relationship("User", back_populates="households")

    # Optional relationship with Barangay if needed
    barangay = db.relationship("Barangay", backref="households", foreign_keys=[barangay_id])

    # Relationship with PredictionData
    predictions = db.relationship(
        "PredictionData",
        back_populates="household",
        cascade="all, delete"
    )

    def __repr__(self):
        return f'<Household {self.id}>'
    
class HouseholdForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired(), Length(max=100)])
    mother_first_name = StringField('Mother First Name', validators=[DataRequired(), Length(max=100)])
    mother_last_name = StringField('Mother Last Name', validators=[DataRequired(), Length(max=100)])
    father_first_name = StringField('Father First Name', validators=[DataRequired(), Length(max=100)])
    father_last_name = StringField('Father Last Name', validators=[DataRequired(), Length(max=100)])
    mother_age = IntegerField('Mother Age', validators=[DataRequired()])
    father_age = IntegerField('Father Age', validators=[DataRequired()])
    submit = SubmitField('Save')

# PredictionData Class
class PredictionData(db.Model):
    __tablename__ = 'prediction_data'

    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id', ondelete='CASCADE'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    admin_id = db.Column(db.Integer, nullable=False)
    barangay_id = db.Column(db.Integer, db.ForeignKey('barangay.id'))
    household_id = db.Column(db.Integer, db.ForeignKey('household.id', ondelete='CASCADE'), nullable=True)

    child_first_name = db.Column(db.String(50), nullable=False)
    child_last_name = db.Column(db.String(50), nullable=False)
    prediction_date = db.Column(db.DateTime, default=datetime.utcnow)

    # Prediction outcome fields for malnutrition metrics
    weight_status = db.Column(db.String(50), nullable=False)         
    height_status = db.Column(db.String(50), nullable=False)        
    weight_length_status = db.Column(db.String(50), nullable=False)  

    # Data fields specific to prediction
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(1), nullable=False)
    vitamin_a = db.Column(db.String(3), nullable=False)
    birth_order = db.Column(db.Integer, nullable=False)
    breastfeeding = db.Column(db.String(3), nullable=False)
    comorbidity_status = db.Column(db.String(3), nullable=False)
    type_of_birth = db.Column(db.String(50), nullable=False)
    size_at_birth = db.Column(db.String(50), nullable=False)
    dietary_diversity_score = db.Column(db.String(50), nullable=False)
    mothers_age = db.Column(db.Integer, nullable=False)
    mothers_education_level = db.Column(db.String(50), nullable=False)
    fathers_education_level = db.Column(db.String(50), nullable=False)
    womens_autonomy_tertiles = db.Column(db.String(50), nullable=False)
    toilet_facility = db.Column(db.String(20), nullable=False)
    source_of_drinking_water = db.Column(db.String(50), nullable=False)
    bmi_of_mother = db.Column(db.String(50), nullable=False)
    number_of_children_under_five = db.Column(db.Integer, nullable=False)
    household_size = db.Column(db.Integer, nullable=False)
    mothers_working_status = db.Column(db.String(50), nullable=False)
    prediction_result = db.Column(db.String(255), nullable=False)

    user = db.relationship("User", back_populates="predictions")
    household = db.relationship("Household", back_populates="predictions")
    child = db.relationship("Child", back_populates="predictions")

    def __repr__(self):
        return f'<PredictionData {self.id} - {self.child_first_name} {self.child_last_name} - {self.prediction_date}>'



class PredictionForm(FlaskForm):
    child_first_name = StringField("Child's First Name", validators=[DataRequired()])
    child_last_name = StringField("Child's Last Name", validators=[DataRequired()])
    age = IntegerField('Age in months', validators=[DataRequired()])
    sex = SelectField('Sex', choices=[('M', 'Male'), ('F', 'Female')], validators=[DataRequired()])
    vitamin_a = SelectField('Vitamin A', choices=[('Yes', 'Yes'), ('No', 'No')], validators=[DataRequired()])
    birth_order = IntegerField('Birth Order', validators=[DataRequired()])
    breastfeeding = SelectField('Breastfeeding', choices=[('Yes', 'Yes'), ('No', 'No')], validators=[DataRequired()])
    comorbidity_status = SelectField('Comorbidity Status', choices=[('Yes', 'Yes'), ('No', 'No')], validators=[DataRequired()])
    type_of_birth = SelectField('Type of Birth', choices=[('Singleton', 'Singleton'), ('Multiple', 'Multiple')], validators=[DataRequired()])
    size_at_birth = SelectField('Size at Birth', choices=[('Smaller than average', 'Smaller than average'), ('Average', 'Average'), ('Larger than average', 'Larger than average')], validators=[DataRequired()])
    dietary_diversity_score = SelectField('Dietary Diversity Score', choices=[('Below minimum requirement', 'Below minimum requirement'), ('Minimum Requirement', 'Minimum Requirement'), ('Maximum Requirement', 'Maximum Requirement')], validators=[DataRequired()])
    mothers_age = IntegerField("Mother's Age", validators=[DataRequired()])
    residence = SelectField('Residence', choices=[('Rural', 'Rural'), ('Urban', 'Urban')], validators=[DataRequired()])
    mothers_education_level = SelectField("Mother's Education Level", choices=[('Elementary', 'Elementary'), ('Highschool', 'Highschool'), ('College', 'College')], validators=[DataRequired()])
    fathers_education_level = SelectField("Father's Education Level", choices=[('Elementary', 'Elementary'), ('Highschool', 'Highschool'), ('College', 'College')], validators=[DataRequired()])
    womens_autonomy_tertiles = SelectField("Women's Autonomy Tertiles", choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], validators=[DataRequired()])
    toilet_facility = SelectField("Toilet Facility", choices=[('Improved', 'Improved'), ('Unimproved', 'Unimproved')], validators=[DataRequired()])
    source_of_drinking_water = SelectField("Source of Drinking Water", choices=[('Improved', 'Improved'), ('Unimproved', 'Unimproved')], validators=[DataRequired()])
    bmi_of_mother = SelectField("BMI of Mother", choices=[('Underweight', 'Underweight'), ('Normal', 'Normal'), ('Overweight', 'Overweight'), ('Obese', 'Obese')], validators=[DataRequired()])
    number_of_children_under_five = IntegerField("Number of Children Under Five", validators=[DataRequired()])
    mothers_working_status = SelectField("Mother's Working Status", choices=[('Working', 'Working'), ('Not Working', 'Not Working')], validators=[DataRequired()])
    household_size = IntegerField("Household Size", validators=[DataRequired()])
    submit = SubmitField('Submit')


class NewUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=50)])
    barangay = SelectField('Barangay', validators=[DataRequired()], choices=[
        'Aganan', 'Amparo', 'Anilao', 'Balabag', 'Cabugao Norte', 'Cabugao Sur',
        'Jibao-an', 'Mali-ao', 'Pagsanga-an', 'Pal-agon', 'Pandac', 'Purok 1',
        'Purok 2', 'Purok 3', 'Purok 4', 'Tigum', 'Ungka 1', 'Ungka 2'
    ])
    submit = SubmitField('Add User')
    
# BHW Admin Class    
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    barangays = db.relationship('Barangay', secondary=bhw_barangay, backref=db.backref('admins', lazy='dynamic'))

    def set_password(self, password):
        """Hashes the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies the password."""
        return check_password_hash(self.password_hash, password)

# BHW Admin Form with dynamic barangay choices
class CreateAdminForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    barangay1 = SelectField('Primary Barangay', validators=[DataRequired()], choices=[
        ('Aganan', 'Aganan'), ('Amparo', 'Amparo'), ('Anilao', 'Anilao'), ('Balabag', 'Balabag'),
        ('Cabugao Norte', 'Cabugao Norte'), ('Cabugao Sur', 'Cabugao Sur'), ('Jibao-an', 'Jibao-an'),
        ('Mali-ao', 'Mali-ao'), ('Pagsanga-an', 'Pagsanga-an'), ('Pal-agon', 'Pal-agon'),
        ('Pandac', 'Pandac'), ('Purok 1', 'Purok 1'), ('Purok 2', 'Purok 2'),
        ('Purok 3', 'Purok 3'), ('Purok 4', 'Purok 4'), ('Tigum', 'Tigum'),
        ('Ungka 1', 'Ungka 1'), ('Ungka 2', 'Ungka 2')
    ])
    barangay2 = SelectField('Secondary Barangay', choices=[
        ('', 'None'), ('Aganan', 'Aganan'), ('Amparo', 'Amparo'), ('Anilao', 'Anilao'), ('Balabag', 'Balabag'),
        ('Cabugao Norte', 'Cabugao Norte'), ('Cabugao Sur', 'Cabugao Sur'), ('Jibao-an', 'Jibao-an'),
        ('Mali-ao', 'Mali-ao'), ('Pagsanga-an', 'Pagsanga-an'), ('Pal-agon', 'Pal-agon'),
        ('Pandac', 'Pandac'), ('Purok 1', 'Purok 1'), ('Purok 2', 'Purok 2'),
        ('Purok 3', 'Purok 3'), ('Purok 4', 'Purok 4'), ('Tigum', 'Tigum'),
        ('Ungka 1', 'Ungka 1'), ('Ungka 2', 'Ungka 2')
    ])
    barangay3 = SelectField('Tertiary Barangay', choices=[
        ('', 'None'), ('Aganan', 'Aganan'), ('Amparo', 'Amparo'), ('Anilao', 'Anilao'), ('Balabag', 'Balabag'),
        ('Cabugao Norte', 'Cabugao Norte'), ('Cabugao Sur', 'Cabugao Sur'), ('Jibao-an', 'Jibao-an'),
        ('Mali-ao', 'Mali-ao'), ('Pagsanga-an', 'Pagsanga-an'), ('Pal-agon', 'Pal-agon'),
        ('Pandac', 'Pandac'), ('Purok 1', 'Purok 1'), ('Purok 2', 'Purok 2'),
        ('Purok 3', 'Purok 3'), ('Purok 4', 'Purok 4'), ('Tigum', 'Tigum'),
        ('Ungka 1', 'Ungka 1'), ('Ungka 2', 'Ungka 2')
    ])
    submit = SubmitField('Create BHW')

# Update BHW 
class UpdateBHWForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password (Leave blank to keep current password)', validators=[Optional()])
    barangay1 = SelectField('Primary Barangay', choices=[], validators=[DataRequired()])
    barangay2 = SelectField('Secondary Barangay', choices=[], validators=[Optional()])
    barangay3 = SelectField('Tertiary Barangay', choices=[], validators=[Optional()])
    submit = SubmitField('Update BHW')

class RCHU(db.Model):
    __tablename__ = 'rchu'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def __repr__(self):
        return f'<RCHU {self.username}>'

# Flaskform for Creating RHU
class CreateRCHUForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=25)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Create RCHU')

    def validate_username(self, username):
        existing_rchu = RCHU.query.filter_by(username=username.data).first()
        if existing_rchu:
            raise ValidationError('This username is already taken. Please choose a different one.')

class UpdateRCHUForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('New Password', validators=[Length(min=6, message="Optional")])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Update RCHU')

    def validate_username(self, username):
        existing_user = RCHU.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('This username is already taken.')


# Association Table
bhw_barangay = db.Table('bhw_barangay',
    db.Column('bhw_id', db.Integer, db.ForeignKey('admin.id'), primary_key=True),
    db.Column('barangay_id', db.Integer, db.ForeignKey('barangay.id'), primary_key=True), extend_existing=True
)

class DummyForm(FlaskForm):
    hidden_tag = HiddenField('hidden_tag')

def has_access(self, barangay_name):
    return any(barangay.name == barangay_name for barangay in self.barangays)

# Initialize the database
def create_db_tables():
    with app.app_context():
        db.create_all()
        print("Database tables created.")


# Custom Jinja2 filter to format numbers
def format_number(value):
    if value.is_integer():
        return int(value)
    return round(value, 1)

app.jinja_env.filters['format_number'] = format_number


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Main index page
@app.route('/')
def index():
    return render_template('System4/index.html')

# User Type
@app.route('/user-type-redirect', methods=['POST'])
def userTypeRedirect():
    user_type = request.form.get('user-type')
    
    if user_type == 'guardian':
        return redirect(url_for('userIndex'))
    elif user_type == 'health_worker':
        return redirect(url_for('adminIndex'))
    elif user_type == 'rch':
        return redirect(url_for('rchuLogin'))
    else:
        flash('Invalid user type selected.', 'danger')
        return redirect(url_for('index'))


#-------------------------Admin Area---------------------------------------

def authenticate_admin(username, password):
    admin = Admin.query.filter_by(username=username).first() 
    if admin and check_password_hash(admin.password_hash, password):
        return admin.id
    return None

# Admin login
@app.route('/admin/', methods=['GET', 'POST'])
def adminIndex():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Authenticate the user (Admin/BHW)
        admin_id = authenticate_admin(username, password)
        
        if admin_id:
            session['admin_id'] = admin_id
            session['role'] = 'BHW'
            return redirect(url_for('adminDashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('admin/login.html')

# Route to view all barangays
@app.route('/admin/barangays')
def adminBarangays():
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))
    
    admin_id = session.get('admin_id')
    admin = Admin.query.get(admin_id)
    
    if not admin:
        flash('Admin account not found.', 'danger')
        return redirect(url_for('adminIndex'))
    
    barangays = admin.barangays  # Passing full Barangay objects

    return render_template('admin/barangays.html', barangays=barangays)


@app.route('/admin/user_barangays')
def adminUserBarangays():
    # Check if the user is logged in
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))
   
    admin_id = session.get('admin_id')
    admin = Admin.query.get(admin_id)
    
    if not admin:
        flash('Admin account not found.', 'danger')
        return redirect(url_for('adminIndex'))

    # Get the Barangay objects assigned to the admin
    barangays = admin.barangays

    return render_template('admin/userbarangay.html', barangays=barangays)


# Admin view user profiles filtered by barangay
@app.route('/admin/user_profiles/<barangay>')
def adminUserProfiles(barangay):
    # Check if admin is logged in
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

    # Find the Barangay instance by name
    barangay_instance = Barangay.query.filter_by(name=barangay).first()

    # If the barangay does not exist, flash a message and redirect
    if not barangay_instance:
        flash(f"Barangay '{barangay}' does not exist.", "danger")
        return redirect(url_for('adminDashboard'))

    # Fetch users in the specified barangay using relationship-based filtering
    users = User.query.filter(User.barangay.has(id=barangay_instance.id)).all()
    
    if not users:
        flash(f'No users found in {barangay}.', 'info')

    # Render user_profiles template with users in specified barangay
    return render_template('admin/user_profiles.html', users=users, barangay=barangay)


# Admin View Prediction Data
@app.route('/admin/predictions')
def adminPredictionData():
    if 'admin_id' in session:
        predictions = PredictionData.query.all()
        users = {user.id: user for user in User.query.all()}
        
        prediction_list = []
        for prediction in predictions:
            user = users.get(prediction.parent_id)
            prediction_list.append({
                'id': prediction.id,
                'child_first_name': prediction.child_first_name,
                'child_last_name': prediction.child_last_name,
                'age': prediction.age,
                'sex': prediction.sex,
                'prediction_result': prediction.prediction_result,
                'household_id': prediction.household_id 
            })
        
        return render_template('admin/viewpredictions.html', predictions=prediction_list)
    else:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

# View predictions filtered by barangay
@app.route('/admin/predictions/<string:barangay>', methods=['GET'])
def adminBarangayPredictions(barangay):
    if 'admin_id' in session:
        households = Household.query.filter_by(address=barangay).all()
        predictions = []
        for household in households:
            household_predictions = PredictionData.query.filter_by(household_id=household.id).all()
            for prediction in household_predictions:
                predictions.append({
                    'id': prediction.id,
                    'child_first_name': prediction.child_first_name,
                    'child_last_name': prediction.child_last_name,
                    'age': prediction.age,
                    'sex': prediction.sex,
                    'prediction_result': prediction.prediction_result,
                    'household_address': household.address,
                    'mother_first_name': household.mother_first_name,
                    'mother_last_name': household.mother_last_name
                })
        return render_template('admin/barangay_predictions.html', predictions=predictions, barangay=barangay)
    else:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))


# Admin add new user
@app.route('/admin/add_user', methods=['GET', 'POST'])
def adminAddUser():
    if 'admin_id' in session:
        form = NewUserForm()
        if form.validate_on_submit():
            # Find the Barangay by name as selected in the form
            selected_barangay = Barangay.query.filter_by(name=form.barangay.data).first()
            
            if not selected_barangay:
                flash("Selected barangay does not exist.", "danger")
                return render_template('admin/admin_add_user.html', form=form)

            # Create the new user with a barangay_id 
            new_user = User(
                username=form.username.data,
                barangay_id=selected_barangay.id  
            )
            new_user.set_password(form.password.data)  
            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('New user created successfully!', 'success')
                return redirect(url_for('adminDashboard'))
            except IntegrityError:
                db.session.rollback()
                flash('Username already exists. Please choose a different username.', 'danger')
        return render_template('admin/admin_add_user.html', form=form)
    else:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

# Admin edit user
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def adminEditUser(user_id):
    if 'admin_id' in session:
        user = User.query.get_or_404(user_id)
        form = NewUserForm(obj=user)

        if form.validate_on_submit():
            user.username = form.username.data
            user.barangay = form.barangay.data
            if form.password.data:
                user.set_password(form.password.data)
            try:
                db.session.commit()
                flash('User profile updated successfully!', 'success')
                return redirect(url_for('adminUserProfiles', barangay=user.barangay))
            except IntegrityError:
                db.session.rollback()
                flash('Username already exists. Please choose a different username.', 'danger')

        return render_template('admin/admin_edit_user.html', form=form, user=user)
    else:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

# Admin Delete User
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def adminDeleteUser(user_id):
    # Check for admin access
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))
    
    # Fetch the user by ID
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('adminUserBarangays'))

    try:
        # Delete all related PredictionData records
        predictions = PredictionData.query.filter(PredictionData.parent_id == user_id).all()
        for prediction in predictions:
            db.session.delete(prediction)
        
        # Delete all related children records
        children = Child.query.filter(Child.user_id == user_id).all()
        for child in children:
            db.session.delete(child)
        
        # Delete all related households
        households = Household.query.filter(Household.user_id == user_id).all()
        for household in households:
            db.session.delete(household)
        
        # Finally, delete the user
        db.session.delete(user)
        db.session.commit()  # Commit deletions

        flash('User and all related data deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        flash(f'Error deleting user: {e}', 'danger')

    # Redirect back to the list of users in the specific barangay
    return redirect(url_for('adminUserBarangays'))

@app.route('/admin/add_household', methods=['GET', 'POST'])
def adminAddHousehold():
    user_id = request.args.get('user_id')
    form = HouseholdForm()

    # Fetch household and user data from the database
    household = Household.query.filter_by(user_id=user_id).first()
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('adminUserBarangays'))

    # Set the barangay_id from the user, assuming each user belongs to one barangay
    barangay_id = user.barangay_id
    if not barangay_id:
        flash('Barangay information is missing for this user.', 'warning')
        return redirect(url_for('adminUserBarangays'))

    # Pre-fill form fields if household data exists
    if household:
        form.address.data = household.address
        form.mother_first_name.data = household.mother_first_name
        form.mother_last_name.data = household.mother_last_name
        form.father_first_name.data = household.father_first_name
        form.father_last_name.data = household.father_last_name
        form.mother_age.data = household.mother_age
        form.father_age.data = household.father_age
    else:
        form.address.data = user.barangay.name if user.barangay else ''

    # Handle form submission
    if form.validate_on_submit():
        try:
            if household:
                # Update existing household
                household.address = form.address.data
                household.mother_first_name = form.mother_first_name.data
                household.mother_last_name = form.mother_last_name.data
                household.father_first_name = form.father_first_name.data
                household.father_last_name = form.father_last_name.data
                household.mother_age = form.mother_age.data
                household.father_age = form.father_age.data
                household.barangay_id = barangay_id  # Ensure barangay_id is set
            else:
                # Create new household entry
                household = Household(
                    user_id=user_id,
                    address=form.address.data,
                    mother_first_name=form.mother_first_name.data,
                    mother_last_name=form.mother_last_name.data,
                    father_first_name=form.father_first_name.data,
                    father_last_name=form.father_last_name.data,
                    mother_age=form.mother_age.data,
                    father_age=form.father_age.data,
                    barangay_id=barangay_id  # Assign barangay_id to the new household
                )
                db.session.add(household)
            
            db.session.commit()
            flash('Household information saved successfully.', 'success')
            return redirect(url_for('adminUserBarangays'))
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving household: {e}")
            flash('An error occurred while saving the household information.', 'danger')

    if form.errors:
        flash('Please correct the errors in the form.', 'danger')
        app.logger.error(f"Form errors: {form.errors}")

    # Render template
    return render_template('admin/add_household.html', form=form, user=user)

# bhw_manage_child Route
@app.route('/bhwManageChild', methods=['GET'])
def bhw_manage_child():
    user_id = request.args.get('user_id', type=int)
    admin_id = session.get('admin_id')

    if not admin_id:
        flash("Admin login required.", "danger")
        return redirect(url_for('adminIndex'))

    admin = Admin.query.get(admin_id)
    if not admin:
        flash("Admin account does not exist. Please contact support.", "danger")
        return redirect(url_for('adminDashboard'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("adminUserBarangays"))

    barangay_ids = [barangay.id for barangay in admin.barangays]
    if user.barangay_id not in barangay_ids:
        flash("You do not have permission to manage this user's children.", "danger")
        return redirect(url_for("adminUserBarangays"))

    children_with_households = (
        db.session.query(Child, Household)
        .join(Household, Household.user_id == Child.user_id)
        .filter(Child.user_id == user_id)
        .all()
    )

    latest_predictions = {
        child.id: PredictionData.query
            .filter_by(child_id=child.id)
            .order_by(PredictionData.prediction_date.desc())
            .first()
        for child, _ in children_with_households
    }

    children = [child for child, _ in children_with_households]

    return render_template(
        'admin/manage_child.html',
        children_with_households=children_with_households,
        latest_predictions=latest_predictions,
        user=user,
        children=children
    )


@app.route('/bhwManageChild/add', methods=['GET', 'POST'])
def add_child():
    if 'admin_id' not in session:
        flash("Please log in as an admin to add children.", "danger")
        return redirect(url_for("adminIndex"))
    
    admin_id = session['admin_id']
    admin = Admin.query.get(admin_id)
    
    if not admin:
        flash("Admin account not found. Please contact support.", "danger")
        return redirect(url_for("adminIndex"))

    # Retrieve `user_id` from the request
    user_id = request.args.get('user_id', type=int) or request.form.get('user_id', type=int)
    if not user_id:
        flash("User ID is missing. Please try again.", "danger")
        return redirect(url_for("adminUserBarangays"))

    # Ensure the user belongs to one of the admin's assigned barangays
    barangay_ids = [barangay.id for barangay in admin.barangays]
    user = User.query.filter(User.id == user_id, User.barangay_id.in_(barangay_ids)).first()
    
    if not user:
        flash("The specified user does not exist or is not in your assigned barangays.", "danger")
        return redirect(url_for("adminUserBarangays"))

    # Fetch the father’s last name from the Household model
    household = Household.query.filter_by(user_id=user.id).first()
    father_last_name = household.father_last_name if household else ""

    form = ChildForm()
    
    # Pre-fill the father's last name if it exists
    form.last_name.data = father_last_name

    if form.validate_on_submit():
        try:
            # Create the new child instance, setting parent_id to the user's ID
            new_child = Child(
                user_id=user.id,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                barangay_id=user.barangay_id,
                parent_id=user.id 
            )

            # Add and commit the child to the database
            db.session.add(new_child)
            db.session.commit()
            
            flash("Child added successfully.", "success")
            return redirect(url_for("bhw_manage_child", user_id=user_id))
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding child for user {user_id}: {e}")
            flash("An error occurred while adding the child. Please try again.", "danger")
    
    elif request.method == 'POST':
        app.logger.warning(f"Form validation failed with errors: {form.errors}")
        flash("Please correct the errors in the form.", "warning")

    return render_template("admin/add_child.html", form=form)

@app.route('/edit_child/<int:child_id>', methods=['GET', 'POST'])
def edit_child(child_id):
    # Ensure the user has admin permissions
    if 'admin_id' not in session:
        flash("You need to be logged in as an admin to access this page.", "danger")
        return redirect(url_for('adminIndex'))

    # Fetch the child based on the provided child_id
    child = Child.query.get_or_404(child_id)

    # Initialize the form and populate with child data for a GET request
    form = ChildForm(obj=child)

    if request.method == 'POST' and form.validate_on_submit():
        # Update child data with form data
        child.first_name = form.first_name.data
        child.last_name = form.last_name.data

        # Save changes to the database
        try:
            db.session.commit()
            flash("Child's information has been updated successfully.", "success")
            return redirect(url_for('bhw_manage_child', user_id=child.user_id))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the child's information.", "danger")
            print(f"Error: {e}")

    # Render the edit form with existing child information for a GET request
    return render_template('admin/edit_child.html', form=form, child=child)


@app.route('/admin/edit_prediction/<int:prediction_id>', methods=['GET', 'POST'])
def edit_prediction(prediction_id):
    if 'admin_id' not in session:
        flash("Please log in as an admin to add children.", "danger")
        return redirect(url_for("adminIndex"))
    
    # Retrieve the prediction to edit
    prediction = PredictionData.query.get_or_404(prediction_id)
    
    # Retrieve the associated child and household for the prediction
    child = Child.query.get(prediction.child_id)
    household = Household.query.filter_by(user_id=child.user_id).first()
    
    # Initialize the form with the prediction's data
    form = PredictionForm(obj=prediction)
    
    # Pre-fill mother's age in the form if household data exists
    if household:
        form.mothers_age.data = household.mother_age

    if form.validate_on_submit():
        # Update the prediction data with form data
        form.populate_obj(prediction)
        db.session.commit()
        flash("Prediction updated successfully.", "success")
        return redirect(url_for('bhw_manage_child', user_id=child.user_id))
    
    # Render the edit prediction form with pre-filled data
    return render_template("admin/edit_prediction.html", form=form, prediction=prediction, child=child, household=household)


@app.route('/delete_predictions/<int:child_id>', methods=['POST'])
def delete_predictions_only(child_id):
    """Deletes only the predictions for a specific child."""
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))
    
    try:
        # Query and delete all PredictionData records associated with this child
        predictions = PredictionData.query.filter_by(child_id=child_id).all()
        for prediction in predictions:
            db.session.delete(prediction)
        db.session.commit()
        flash('Predictions for the child were deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting predictions: {e}', 'danger')

    return redirect(url_for('bhw_manage_child', user_id=session.get('user_id'))) 

@app.route('/delete_child/<int:child_id>', methods=['POST'])
def delete_child_and_predictions(child_id):
    """Deletes both the child and their associated prediction records."""
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))
    
    try:
        # Delete all predictions for the child
        predictions = PredictionData.query.filter_by(child_id=child_id).all()
        for prediction in predictions:
            db.session.delete(prediction)
        
        # Delete the child record
        child = Child.query.get(child_id)
        if child:
            db.session.delete(child)
            db.session.commit()
            flash('Child and all associated predictions were deleted successfully.', 'success')
        else:
            flash('Child not found.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting child and predictions: {e}', 'danger')

    return redirect(url_for('bhw_manage_child', user_id=session.get('user_id')))


# Admin logout
@app.route('/admin/logout')
def adminLogout():
    session.pop('admin_id', None)
    session.pop('role', None)
    return redirect('/')


# -------------------------------RCHU Area --------------------------------
# RCHU login
@app.route('/rchu/login', methods=['GET', 'POST'])
def rchuLogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        rchu_account = RCHU.query.filter_by(username=username).first()
        if rchu_account:
            print("Found RCHU account:", rchu_account.username)
        if rchu_account and rchu_account.check_password(password):
            session['rchu_id'] = rchu_account.id
            print(f"RCHU ID set in session: {session['rchu_id']}")  
            flash('Logged in successfully as RCHU admin.', 'success')
            return redirect(url_for('rchuDashboard'))
        else:
            flash('Invalid username or password', 'danger')
            print("Login failed: invalid credentials")  
    return render_template('rchu/login.html')

@app.route('/debug/rchu')
def debug_rchu():
    accounts = RCHU.query.all()
    return f"Accounts: {[account.username for account in accounts]}"


# RCHU Dashboard Route
@app.route('/rchu/dashboard')
def rchuDashboard():
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))

    # Fetch core dashboard data
    total_users = User.query.count()
    total_bhws = Admin.query.count()
    total_children = Child.query.count()

    # Initialize malnutrition metrics, age groups, and gender counts as before
    malnutrition_metrics = {
        'Weight for Age': {'Severely Underweight': 0, 'Underweight': 0, 'Normal': 0, 'Overweight': 0},
        'Height for Age': {'Severely Stunted': 0, 'Stunted': 0, 'Normal': 0, 'Tall': 0},
        'Weight for Length/Height': {'Severely Wasted': 0, 'Wasted': 0, 'Normal': 0, 'Overweight': 0, 'Obese': 0}
    }
    age_groups = {'0-5': 0, '6-12': 0, '13-18': 0, '19-50': 0, '50+': 0}
    gender_counts = {'M': 0, 'F': 0, 'Other': 0}

    predictions = PredictionData.query.all()
    for prediction in predictions:
        malnutrition_metrics['Weight for Age'][prediction.weight_status or "Normal"] += 1
        malnutrition_metrics['Height for Age'][prediction.height_status or "Normal"] += 1
        malnutrition_metrics['Weight for Length/Height'][prediction.weight_length_status or "Normal"] += 1

        if prediction.age <= 5:
            age_groups['0-5'] += 1
        elif 6 <= prediction.age <= 12:
            age_groups['6-12'] += 1
        elif 13 <= prediction.age <= 18:
            age_groups['13-18'] += 1
        elif 19 <= prediction.age <= 50:
            age_groups['19-50'] += 1
        else:
            age_groups['50+'] += 1

        gender = prediction.sex if prediction.sex in gender_counts else 'Other'
        gender_counts[gender] += 1

    # Modified query to include all barangays with zero-count handling
    barangay_predictions = (
        db.session.query(Barangay.name, func.count(PredictionData.id).label('prediction_count'))
        .outerjoin(PredictionData, Barangay.id == PredictionData.barangay_id)
        .group_by(Barangay.name)
        .order_by(Barangay.name)  
        .all()
    )

    # Separate barangay names and prediction counts for easier charting
    barangay_labels = [b[0] for b in barangay_predictions]
    barangay_data = [b[1] for b in barangay_predictions]

    return render_template(
        'rchu/dashboard.html',
        total_users=total_users,
        total_bhws=total_bhws,
        total_children=total_children,
        malnutrition_metrics=malnutrition_metrics,
        age_groups=age_groups,
        gender_counts=gender_counts,
        barangay_labels=barangay_labels,
        barangay_data=barangay_data
    )



# RCHU Manage BHWs Route
@app.route('/rchu/manage-bhws')
def rchuManageBHWs():
    if 'rchu_id' not in session:  
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))
    
    bhws = Admin.query.all() 
    return render_template('rchu/manage_bhws.html', bhws=bhws)

@app.route('/rchu/create', methods=['GET', 'POST'])
def create_rchu_account():
    form = CreateRCHUForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Create a new RCHU object and save it to the database
        new_rchu = RCHU(username=username)
        new_rchu.set_password(password)  # Assuming RCHU has set_password method for hashing
        db.session.add(new_rchu)
        db.session.commit()
        
        flash('RCHU account created successfully!', 'success')
        return redirect(url_for('manage_rchu'))

    return render_template('rchu/create_rchu.html', form=form)


@app.route('/rchu/manage-rchu')
def manage_rchu():
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))

    rchus = RCHU.query.all()  # Fetch all RCHU accounts
    return render_template('rchu/manage_rchu.html', rchus=rchus)

@app.route('/rchu/manage-rchu/update/<int:id>', methods=['GET', 'POST'])
def update_rchu(id):
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))

    rchu = RCHU.query.get_or_404(id)
    form = UpdateRCHUForm(obj=rchu)

    if form.validate_on_submit():
        rchu.username = form.username.data

        # Update password only if a new one is provided
        if form.password.data:
            rchu.set_password(form.password.data)

        db.session.commit()
        flash('RCHU account updated successfully!', 'success')
        return redirect(url_for('manage_rchu'))

    return render_template('rchu/update_rchu.html', form=form, rchu=rchu)


# Delete an RCHU account
@app.route('/rchu/manage-rchu/delete/<int:id>', methods=['POST'])
def delete_rchu(id):
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))

    rchu = RCHU.query.get_or_404(id)
    db.session.delete(rchu)
    db.session.commit()
    flash('RCHU account deleted successfully!', 'success')
    return redirect(url_for('manage_rchu'))

# Add new BHW (Admin)
@app.route('/rchu/manage-bhws/create', methods=['GET', 'POST'])
def rchuCreateBHW():
    if 'rchu_id' not in session:  
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))
    
    form = CreateAdminForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        barangay1 = form.barangay1.data
        barangay2 = form.barangay2.data if form.barangay2.data != '' else None
        barangay3 = form.barangay3.data if form.barangay3.data != '' else None

        password_hash = generate_password_hash(password)
        new_admin = Admin(username=username, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()

        # Assign barangays to the BHW
        if barangay1:
            assign_barangay_to_admin(new_admin, barangay1)
        if barangay2:
            assign_barangay_to_admin(new_admin, barangay2)
        if barangay3:
            assign_barangay_to_admin(new_admin, barangay3)

        flash('BHW Account Created Successfully', 'success')
        return redirect(url_for('rchuManageBHWs'))

    return render_template('rchu/create_bhw.html', form=form)


# Update BHW
@app.route('/rchu/manage-bhws/update/<int:id>', methods=['GET', 'POST'])
def rchuUpdateBHW(id):
    if 'rchu_id' not in session: 
        flash('You are not logged in or do not have the required permissions.')
        return redirect(url_for('rchuLogin'))
    
    bhw = Admin.query.get_or_404(id)
    form = UpdateBHWForm(obj=bhw)
    
    barangays = [(b.name, b.name) for b in Barangay.query.all()]
    form.barangay1.choices = barangays
    form.barangay2.choices = barangays
    form.barangay3.choices = barangays

    if form.validate_on_submit():
        bhw.username = form.username.data
       
        if form.password.data:
            bhw.password_hash = generate_password_hash(form.password.data)
        
        bhw.barangays.clear()
        assign_barangay_to_admin(bhw, form.barangay1.data)
        if form.barangay2.data:
            assign_barangay_to_admin(bhw, form.barangay2.data)
        if form.barangay3.data:
            assign_barangay_to_admin(bhw, form.barangay3.data)

        db.session.commit()

        flash('BHW account updated successfully!')
        return redirect(url_for('rchuManageBHWs'))

    return render_template('rchu/update_bhw.html', form=form, bhw=bhw)


# Delete BHW
@app.route('/rchu/manage-bhws/delete/<int:bhw_id>', methods=['POST'])
def rchuDeleteBHW(bhw_id):
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('rchuIndex'))
    
    bhw = Admin.query.get_or_404(bhw_id)  
    db.session.delete(bhw)
    db.session.commit() 
    flash('BHW deleted successfully!')
    return redirect(url_for('rchuManageBHWs'))

# RCHU View Barangays
@app.route('/rchu/barangays')
def rchuBarangays():
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('rchuIndex'))
    
    barangays = Barangay.query.all() 
    return render_template('rchu/barangays.html', barangays=barangays)


# RCHU View All Predictions Route
@app.route('/rchu/view-predictions/<int:barangay_id>')
def rchuViewAllPredictions(barangay_id):
    # Ensure the user has RCHU permissions (adjust this as needed)
    if 'rchu_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('rchuIndex'))

    # Query all relevant prediction data, filtered by barangay_id
    predictions = db.session.query(
        PredictionData.id,
        PredictionData.child_first_name,
        PredictionData.child_last_name,
        PredictionData.age,
        PredictionData.prediction_result,
        PredictionData.sex,
        PredictionData.prediction_date,  # Include prediction date
        Household.father_first_name,
        Household.father_last_name,
        Barangay.name.label('barangay_name')
    ).join(Household, PredictionData.household_id == Household.id)\
     .join(Barangay, PredictionData.barangay_id == Barangay.id)\
     .filter(PredictionData.barangay_id == barangay_id)\
     .all()

    # Render the template with the filtered predictions data
    return render_template('rchu/view_predictions.html', predictions=predictions, barangay_id=barangay_id)



# Route to view prediction details on the RCHU side
@app.route('/rchu/viewPrediction/<int:prediction_id>')
def rchuViewPrediction(prediction_id):
    # Check if the user has RCHU-level access (adjust session check as needed)
    if not session.get('rchu_id'):
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('rchuIndex'))

    # Fetch the prediction data
    prediction = PredictionData.query.get(prediction_id)

    # Redirect if prediction is not found
    if not prediction:
        flash('Prediction not found', 'danger')
        return redirect(url_for('rchuDashboard'))

    # Safely fetch associated household and child information if available
    household = Household.query.get(prediction.household_id) if prediction.household_id else None
    child = Child.query.get(prediction.child_id) if prediction.child_id else None

    # Calculate child’s age in months and determine the risk level for meal plan generation
    child_age_in_months = prediction.age
    risk_level = prediction.prediction_result
    meal_plan = generate_meal_plan(child_age_in_months, risk_level)

    # Render a dedicated template for viewing a single prediction
    return render_template(
        'rchu/results.html',
        prediction=prediction,
        household=household,
        child=child,
        meal_plan=meal_plan
    )

# RCHU logout
@app.route('/rchu/logout')
def rchuLogout():
    session.pop('rchu_id', None)
    session.pop('role', None)
    return redirect(url_for('index'))

# Assign Barangay to BHW
def assign_barangay_to_admin(admin, barangay_name):
    # Query the Barangay model to find the barangay by name
    barangay = Barangay.query.filter_by(name=barangay_name).first()
    
    if barangay:
        # Append the barangay to the admin's barangays list
        admin.barangays.append(barangay)
        db.session.commit()
    else:
        raise ValueError(f"Barangay '{barangay_name}' not found.")

def initialize_rchu_account():
    """Create a default RCHU account if none exists."""
    # Check if there's already an RCHU account
    if not RCHU.query.first():
        default_rchu = RCHU(username="default_admin")
        
        # Set the password and hash it
        default_rchu.set_password("default_password") 

        print("Setting up RCHU account with hashed password:", default_rchu.password_hash)

        db.session.add(default_rchu)
        db.session.commit()
        print("Default RCHU account created successfully.")
    else:
        print("RCHU account already exists.")

# Download Predictions as CSV
@app.route('/download-predictions/<int:barangay_id>')
def download_predictions(barangay_id):
    # Query all relevant prediction data, filtered by barangay_id
    predictions = db.session.query(
        PredictionData.child_first_name,
        PredictionData.child_last_name,
        PredictionData.age,
        PredictionData.prediction_result,
        PredictionData.sex,
        PredictionData.prediction_date,
        Household.father_first_name,
        Household.father_last_name,
        Household.address,
        Household.mother_first_name,
        Household.mother_last_name,
        PredictionData.vitamin_a,
        PredictionData.birth_order,
        PredictionData.breastfeeding,
        PredictionData.comorbidity_status,
        PredictionData.type_of_birth,
        PredictionData.size_at_birth,
        PredictionData.dietary_diversity_score,
        PredictionData.mothers_age,
        PredictionData.mothers_education_level,
        PredictionData.fathers_education_level,
        PredictionData.womens_autonomy_tertiles,
        PredictionData.toilet_facility,
        PredictionData.source_of_drinking_water,
        PredictionData.bmi_of_mother,
        PredictionData.number_of_children_under_five,
        PredictionData.mothers_working_status,
        PredictionData.household_size,
        Barangay.name.label('barangay_name')
    ).join(Household, PredictionData.household_id == Household.id)\
     .join(Barangay, PredictionData.barangay_id == Barangay.id)\
     .filter(PredictionData.barangay_id == barangay_id)\
     .all()

    # Use StringIO for in-memory CSV creation
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV header with new fields
    writer.writerow([
        'Prediction Date', 'Child First Name', 'Child Last Name', 'Age', 'Sex', 'Prediction Result',
        'Father First Name', 'Father Last Name', 'Address', 'Mother First Name', 'Mother Last Name',
        'Vitamin A', 'Birth Order', 'Breastfeeding', 'Comorbidity Status', 'Type of Birth',
        'Size at Birth', 'Dietary Diversity Score', "Mother's Age", "Mother's Education Level",
        "Father's Education Level", "Women's Autonomy Tertiles", 'Toilet Facility',
        'Source of Drinking Water', "BMI of Mother", "Number of Children Under Five",
        "Mother's Working Status", 'Household Size', 'Barangay Name'
    ])

    # Write each prediction's row
    for pred in predictions:
        writer.writerow([
            pred.prediction_date.strftime('%Y-%m-%d') if pred.prediction_date else '',
            pred.child_first_name, pred.child_last_name, pred.age, pred.sex, pred.prediction_result,
            pred.father_first_name, pred.father_last_name, pred.address,
            pred.mother_first_name, pred.mother_last_name, pred.vitamin_a, pred.birth_order,
            pred.breastfeeding, pred.comorbidity_status, pred.type_of_birth, pred.size_at_birth,
            pred.dietary_diversity_score, pred.mothers_age, pred.mothers_education_level,
            pred.fathers_education_level, pred.womens_autonomy_tertiles, pred.toilet_facility,
            pred.source_of_drinking_water, pred.bmi_of_mother, pred.number_of_children_under_five,
            pred.mothers_working_status, pred.household_size, pred.barangay_name
        ])

    # Set up the CSV response
    output.seek(0)  # Rewind the StringIO object for reading
    headers = {
        "Content-Disposition": f"attachment; filename=predictions_barangay_{barangay_id}.csv"
    }
    return Response(output, mimetype="text/csv", headers=headers)
#--------------------------------user content--------------------------------
# User login
@app.route('/user/', methods=['GET', 'POST'])
def userIndex():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('userDashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('userIndex'))

    return render_template('System4/login.html')


# User dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')

    user_id = session.get('user_id')
    user = User.query.filter_by(id=user_id).first()

    # Fetch household related to the user
    household = Household.query.filter_by(user_id=user_id).first()

    # Fetch predictions related to the user
    predictions = PredictionData.query.filter_by(parent_id=user_id).all()

    # Use `user.barangay.name` directly instead of `str()` or `repr()`
    barangay_name = user.barangay.name if user.barangay else "Unknown Barangay"

    return render_template(
        'System4/home.html',
        title="User Dashboard",
        user=user,
        household=household,
        barangay_name=barangay_name,
        predictions=predictions
    )


@app.route('/user/results/<int:prediction_id>')
def userViewResults(prediction_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You are not logged in.')
        return redirect(url_for('userIndex'))

    # Get the user ID from session
    user_id = session.get('user_id')
    
    # Fetch prediction data associated with this user
    prediction = PredictionData.query.filter_by(id=prediction_id, parent_id=user_id).first()

    # If the prediction is not found or doesn't belong to the user, redirect with a message
    if not prediction:
        flash('Prediction not found or you do not have access to this prediction.')
        return redirect(url_for('userDashboard'))

    # Fetch household data associated with the prediction
    household = Household.query.get(prediction.household_id)
    
    # Generate meal plan based on child's age and risk level
    child_age_in_months = prediction.age
    risk_level = prediction.prediction_result
    meal_plan = generate_meal_plan(child_age_in_months, risk_level)

    # Render the results template with prediction, household, and meal plan data
    return render_template(
        'System4/results.html',
        prediction=prediction,
        household=household,
        meal_plan=meal_plan
    )


@app.route('/user/view_profile', methods=['GET', 'POST'])
def viewProfile():
    user_id = session.get('user_id')

    if not user_id:
        flash('You need to be logged in to view this page.', 'danger')
        return redirect(url_for('userIndex'))  # Redirect to the login page if not logged in

    form = HouseholdForm()

    # Fetch household data from the database
    household = Household.query.filter_by(user_id=user_id).first()
    user = User.query.get(user_id)

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('userDashboard'))  # Redirect to user's dashboard or any relevant page

    if household:
        form.address.data = household.address
        form.mother_first_name.data = household.mother_first_name
        form.mother_last_name.data = household.mother_last_name
        form.father_first_name.data = household.father_first_name
        form.father_last_name.data = household.father_last_name
        form.mother_age.data = household.mother_age
        form.father_age.data = household.father_age
    else:
        # Use the address from the user if no household information is present
        form.address.data = user.barangay

    if form.validate_on_submit():
        if household:
            household.address = form.address.data
            household.mother_first_name = form.mother_first_name.data
            household.mother_last_name = form.mother_last_name.data
            household.father_first_name = form.father_first_name.data
            household.father_last_name = form.father_last_name.data
            household.mother_age = form.mother_age.data
            household.father_age = form.father_age.data
        else:
            household = Household(
                user_id=user_id,
                address=form.address.data,
                mother_first_name=form.mother_first_name.data,
                mother_last_name=form.mother_last_name.data,
                father_first_name=form.father_first_name.data,
                father_last_name=form.father_last_name.data,
                mother_age=form.mother_age.data,
                father_age=form.father_age.data
            )
            db.session.add(household)
        db.session.commit()
        flash('Profile information updated successfully.', 'success')
        return redirect(url_for('viewProfile'))  # Redirect to the same page after saving

    return render_template('System4/view_profile.html', form=form, user=user)

@app.route('/user/results/history', methods=['GET'])
def userResultsHistory():
    child_id = request.args.get('child_id', type=int)
    if not child_id:
        flash("Child ID is missing or invalid.", "danger")
        return redirect(url_for('userDashboard'))

    # Fetch the child and all predictions for the child, ordered by date
    child = Child.query.get(child_id)
    if not child:
        flash("Child not found.", "danger")
        return redirect(url_for('userDashboard'))
    
    predictions = PredictionData.query.filter_by(child_id=child_id).order_by(PredictionData.prediction_date.desc()).all()

    return render_template('System4/results_history.html', child=child, predictions=predictions)


# User Logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')
    
    session.clear()  # Clear all session data
    flash('You have been logged out', 'success')
    return redirect('/')


# About
@app.route('/user/about')
def about():
    if not session.get('user_id'):
        flash('User not logged in', 'danger')
        return redirect(url_for('userIndex'))
    return render_template('System4/about.html', title="e-OPT")
    

# ---------------------------- Prediction Section -------------------------------------------------- #
@app.route('/admin/predict', methods=['GET', 'POST'])
def adminPredict():
    # Ensure the admin is logged in
    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Admin login required.', 'danger')
        return redirect(url_for('adminIndex'))

    # Retrieve child_id and is_update flag from request arguments
    child_id = request.args.get('child_id', type=int)
    is_update = request.args.get('is_update', 'false').lower() == 'true'

    if not child_id:
        flash("Child ID is missing or invalid.", "danger")
        return redirect(url_for('bhw_manage_child'))

    # Fetch child and household information
    child = Child.query.get(child_id)
    household = Household.query.filter_by(user_id=child.user_id).first()
    barangay_id = household.barangay_id if household else None

    # Fetch the latest prediction to pre-fill the form, if available
    latest_prediction = PredictionData.query.filter_by(child_id=child_id).order_by(PredictionData.prediction_date.desc()).first()
    form = PredictionForm()

    # Pre-fill form if is_update is true and latest prediction data exists
    if latest_prediction and is_update:
        # Populate form fields from latest prediction data
        form.age.data = latest_prediction.age
        form.sex.data = latest_prediction.sex
        form.vitamin_a.data = latest_prediction.vitamin_a
        form.birth_order.data = latest_prediction.birth_order
        form.breastfeeding.data = latest_prediction.breastfeeding
        form.comorbidity_status.data = latest_prediction.comorbidity_status
        form.type_of_birth.data = latest_prediction.type_of_birth
        form.size_at_birth.data = latest_prediction.size_at_birth
        form.dietary_diversity_score.data = latest_prediction.dietary_diversity_score
        form.mothers_age.data = latest_prediction.mothers_age
        form.mothers_education_level.data = latest_prediction.mothers_education_level
        form.fathers_education_level.data = latest_prediction.fathers_education_level
        form.womens_autonomy_tertiles.data = latest_prediction.womens_autonomy_tertiles
        form.toilet_facility.data = latest_prediction.toilet_facility
        form.source_of_drinking_water.data = latest_prediction.source_of_drinking_water
        form.bmi_of_mother.data = latest_prediction.bmi_of_mother
        form.number_of_children_under_five.data = latest_prediction.number_of_children_under_five
        form.household_size.data = latest_prediction.household_size
        form.mothers_working_status.data = latest_prediction.mothers_working_status

    # Check if form has been submitted and validate
    if form.validate_on_submit():
        try:
            # Prepare the input data in the format expected by the model
            data = np.array([[ 
                form.age.data,  # Age
                1 if form.sex.data == 'M' else 0,  # Sex
                1 if form.vitamin_a.data == 'Yes' else 0,  # Vitamin A
                form.birth_order.data,  # Birth Order
                1 if form.breastfeeding.data == 'Yes' else 0,  # Breastfeeding
                1 if form.comorbidity_status.data == 'Yes' else 0,  # Comorbidity Status
                1 if form.type_of_birth.data == 'Singleton' else 0,  # Type of Birth
                {'Smaller than average': 0, 'Average': 1, 'Larger than average': 2}[form.size_at_birth.data],  # Size at Birth
                {'Below minimum requirement': 0, 'Minimum Requirement': 1, 'Maximum Requirement': 2}[form.dietary_diversity_score.data],  # Dietary Diversity Score
                form.mothers_age.data,  # Mother's Age
                {'Elementary': 0, 'Highschool': 1, 'College': 2}[form.mothers_education_level.data],  # Mother's Education
                {'Elementary': 0, 'Highschool': 1, 'College': 2}[form.fathers_education_level.data],  # Father's Education
                {'Low': 0, 'Medium': 1, 'High': 2}[form.womens_autonomy_tertiles.data],  # Women's Autonomy Tertiles
                1 if form.toilet_facility.data == 'Improved' else 0,  # Toilet Facility
                1 if form.source_of_drinking_water.data == 'Improved' else 0,  # Source of Drinking Water
                {'Underweight': 0, 'Normal': 1, 'Overweight': 2, 'Obese': 3}[form.bmi_of_mother.data],  # BMI of Mother
                form.number_of_children_under_five.data,  # Number of Children Under Five
                form.household_size.data,  # Household Size
                1 if form.mothers_working_status.data == 'Working' else 0  # Mother's Working Status
            ]])

            print("Prediction input data:", data)  # Debugging line

            # Predict malnutrition risk
            predictions = model.predict(data)
            weight_for_age, height_for_age, weight_for_length_height = predictions[0]

            # Mapping prediction results
            status_map = {
                'Weight for Age': {0: 'Severely Underweight', 1: 'Underweight', 2: 'Normal', 3: 'Overweight'},
                'Height for Age': {0: 'Severely Stunted', 1: 'Stunted', 2: 'Normal', 3: 'Tall'},
                'Weight for Length/Height': {0: 'Severely Wasted', 1: 'Wasted', 2: 'Normal', 3: 'Overweight', 4: 'Obese'}
            }

            weight_status = status_map['Weight for Age'].get(weight_for_age, "Unknown")
            height_status = status_map['Height for Age'].get(height_for_age, "Unknown")
            weight_length_status = status_map['Weight for Length/Height'].get(weight_for_length_height, "Unknown")

            # Create a new prediction entry in the database
            new_prediction = PredictionData(
                child_id=child.id,
                child_first_name=child.first_name,
                child_last_name=child.last_name,
                age=form.age.data,
                sex=form.sex.data,
                vitamin_a=form.vitamin_a.data,
                birth_order=form.birth_order.data,
                breastfeeding=form.breastfeeding.data,
                comorbidity_status=form.comorbidity_status.data,
                type_of_birth=form.type_of_birth.data,
                size_at_birth=form.size_at_birth.data,
                dietary_diversity_score=form.dietary_diversity_score.data,
                mothers_age=form.mothers_age.data,
                mothers_education_level=form.mothers_education_level.data,
                fathers_education_level=form.fathers_education_level.data,
                womens_autonomy_tertiles=form.womens_autonomy_tertiles.data,
                toilet_facility=form.toilet_facility.data,
                source_of_drinking_water=form.source_of_drinking_water.data,
                bmi_of_mother=form.bmi_of_mother.data,
                number_of_children_under_five=form.number_of_children_under_five.data,
                household_size=form.household_size.data,
                mothers_working_status=form.mothers_working_status.data,
                prediction_result=f'Weight: {weight_status}, Height: {height_status}, Weight-Length: {weight_length_status}',
                weight_status=weight_status,
                height_status=height_status,
                weight_length_status=weight_length_status,
                prediction_date=datetime.now(),
                parent_id=child.user_id,
                household_id=household.id if household else None,
                admin_id=admin_id,
                barangay_id=barangay_id
            )

            # Save the new prediction to the database
            db.session.add(new_prediction)
            db.session.commit()
            flash('Prediction saved successfully!', 'success')
            return redirect(url_for('adminResults', prediction_id=new_prediction.id))

        except IntegrityError as ie:
            db.session.rollback()
            flash('A database error occurred.', 'warning')
            app.logger.warning(f"IntegrityError: {ie}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Prediction error: {e}")
            flash(f'Error during prediction: {e}', 'danger')

    else:
        if form.errors:
            app.logger.error(f"Form validation errors: {form.errors}")

    return render_template('admin/predict.html', form=form, child=child, household=household, is_update=is_update)


# Admin Results
@app.route('/admin/results/<int:prediction_id>')
def adminResults(prediction_id):
    # Ensure admin is logged in
    if not session.get('admin_id'):
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

    # Retrieve the specific prediction by ID
    prediction = PredictionData.query.get(prediction_id)
    if not prediction:
        flash('Prediction not found', 'danger')
        return redirect(url_for('bhw_manage_child'))

    # Fetch associated household and child details
    household = Household.query.get(prediction.household_id)
    child = Child.query.get(prediction.child_id)

    # Generate a meal plan based on the child's age and risk level
    meal_plan = generate_meal_plan(prediction.age, prediction.prediction_result)

    # Render the results.html template with the fetched data
    return render_template(
        'admin/results.html',
        prediction=prediction,
        household=household,
        child=child,
        meal_plan=meal_plan
    )


@app.route('/admin/viewResults/<int:prediction_id>')
def adminViewResultsButton(prediction_id):
    if not session.get('admin_id'):
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

    # Fetch prediction data and its associated household and child details
    prediction = PredictionData.query.get(prediction_id)
    household = Household.query.get(prediction.household_id) if prediction else None
    child = Child.query.get(prediction.child_id) if prediction else None

    if not prediction:
        flash('Prediction not found', 'danger')
        return redirect(url_for('adminDashboard'))

    # Fetch the child’s age from PredictionData and the risk level
    child_age_in_months = prediction.age
    risk_level = prediction.prediction_result

    # Generate meal plan
    meal_plan = generate_meal_plan(child_age_in_months, risk_level)

    return render_template(
        'admin/results.html',
        prediction=prediction,
        household=household,
        child=child,
        meal_plan=meal_plan
    )

@app.route('/admin/results/history', methods=['GET'])
def adminResultsHistory():
    child_id = request.args.get('child_id', type=int)
    if not child_id:
        flash("Child ID is missing or invalid.", "danger")
        return redirect(url_for('bhw_manage_child'))

    # Fetch the child and all predictions for the child, ordered by date
    child = Child.query.get(child_id)
    if not child:
        flash("Child not found.", "danger")
        return redirect(url_for('bhw_manage_child'))
    
    predictions = PredictionData.query.filter_by(child_id=child_id).order_by(PredictionData.prediction_date.desc()).all()

    return render_template('admin/results_history.html', child=child, predictions=predictions)


@app.route('/admin/dashboard', methods=['GET'])
def adminDashboard():
    admin_id = session.get('admin_id')
    if not admin_id:
        flash('Admin login required.', 'danger')
        return redirect(url_for('adminIndex'))

    # Get BHW's assigned barangays
    admin = Admin.query.get(admin_id)
    assigned_barangays = admin.barangays
    assigned_barangay_ids = [barangay.id for barangay in assigned_barangays]

    # Count users and children in assigned barangays
    total_users = db.session.query(User).filter(User.barangay_id.in_(assigned_barangay_ids)).count()
    total_children = db.session.query(Child).join(User).filter(User.barangay_id.in_(assigned_barangay_ids)).count()

    # Initialize metrics, age groups, and gender counts
    malnutrition_metrics = {
        'Weight for Age': {'Severely Underweight': 0, 'Underweight': 0, 'Normal': 0, 'Overweight': 0},
        'Height for Age': {'Severely Stunted': 0, 'Stunted': 0, 'Normal': 0, 'Tall': 0},
        'Weight for Length/Height': {'Severely Wasted': 0, 'Wasted': 0, 'Normal': 0, 'Overweight': 0, 'Obese': 0}
    }
    age_groups = {'0-5': 0, '6-12': 0, '13-18': 0, '19-50': 0, '50+': 0}
    gender_counts = {'M': 0, 'F': 0, 'Other': 0}

    # Initialize data for barangay-based total predictions
    barangay_data = {barangay.name: 0 for barangay in assigned_barangays}

    # Filter PredictionData by assigned barangays
    predictions = PredictionData.query.filter(PredictionData.barangay_id.in_(assigned_barangay_ids)).all()

    for prediction in predictions:
        # Aggregate malnutrition metrics
        malnutrition_metrics['Weight for Age'][prediction.weight_status or "Normal"] += 1
        malnutrition_metrics['Height for Age'][prediction.height_status or "Normal"] += 1
        malnutrition_metrics['Weight for Length/Height'][prediction.weight_length_status or "Normal"] += 1

        # Update barangay-specific total predictions
        barangay_name = next((b.name for b in assigned_barangays if b.id == prediction.barangay_id), "Unknown")
        if barangay_name in barangay_data:
            barangay_data[barangay_name] += 1  # Increment total predictions count for this barangay

        # Age group categorization
        if prediction.age <= 5:
            age_groups['0-5'] += 1
        elif 6 <= prediction.age <= 12:
            age_groups['6-12'] += 1
        elif 13 <= prediction.age <= 18:
            age_groups['13-18'] += 1
        elif 19 <= prediction.age <= 50:
            age_groups['19-50'] += 1
        else:
            age_groups['50+'] += 1

        # Gender categorization
        gender = prediction.sex if prediction.sex in gender_counts else 'Other'
        gender_counts[gender] += 1

    return render_template(
        'admin/testDashboard.html',
        total_users=total_users,
        total_children=total_children,
        malnutrition_metrics=malnutrition_metrics,
        age_groups=age_groups,
        gender_counts=gender_counts,
        barangay_data=barangay_data 
    )



# Delete Prediction
@app.route('/admin/delete_prediction/<int:prediction_id>', methods=['POST'])
def deletePrediction(prediction_id):
    if 'admin_id' not in session:
        flash('You are not logged in or do not have the required permissions.', 'danger')
        return redirect(url_for('adminIndex'))

    # Retrieve the prediction data
    prediction = PredictionData.query.get_or_404(prediction_id)
    delete_child = request.form.get('delete_child') == 'true'  # Determine deletion scope
    
    try:
        # Fetch barangay info if needed for redirection
        barangay = prediction.household.address if prediction.household else None

        # If delete_child is true, delete the associated child and their predictions
        if delete_child:
            child = prediction.child
            if child:
                for pred in child.predictions:
                    db.session.delete(pred)  # Delete all related predictions
                db.session.delete(child)  # Delete the child record
                flash('Prediction and associated child data deleted successfully.', 'success')
            else:
                flash('Associated child data not found.', 'warning')
        else:
            # Only delete the selected prediction
            db.session.delete(prediction)
            flash('Prediction deleted successfully.', 'success')

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting prediction: {e}', 'danger')

    # Redirect to the appropriate page after deletion
    return redirect(url_for('adminBarangayPredictions', barangay=barangay))


# Meal Plan Generation
def generate_meal_plan(age_in_months, risk_level):
    if age_in_months <= 6:
        if risk_level == 'Low Risk':
            return ["Exclusive breastfeeding or infant formula."]
        elif risk_level == 'Mid Risk':
            return ["Breastfeeding or formula with vitamin D supplements."]
        else:  # High Risk
            return ["Fortified formula with iron and vitamin D supplements. Consider more frequent feeding."]

    elif 7 <= age_in_months <= 12:
        if risk_level == 'Low Risk':
            return [
                "Breakfast: Mashed banana with formula.",
                "Lunch: Soft-cooked vegetables with chicken.",
                "Snack: Soft fruits like mango puree.",
                "Dinner: Rice cereal with mashed carrots."
            ]
        elif risk_level == 'Mid Risk':
            return [
                "Breakfast: Fortified cereal with formula.",
                "Lunch: Mashed lentils with carrots and chicken.",
                "Snack: Iron-rich fruits like pureed apricot.",
                "Dinner: Rice with spinach puree and mashed meat."
            ]
        else:  # High Risk
            return [
                "Breakfast: High-calorie, iron-fortified cereal with formula.",
                "Lunch: Mashed beans, fortified sweet potatoes with chicken.",
                "Snack: Soft fruits with iron supplement.",
                "Dinner: Fortified rice porridge with beef and spinach."
            ]
    
    # For toddlers and older children
    elif 13 <= age_in_months <= 24:
        if risk_level == 'Low Risk':
            return [
                "Breakfast: Oatmeal with mashed banana.",
                "Lunch: Chicken with rice and vegetables.",
                "Snack: Yogurt with fruit.",
                "Dinner: Vegetable stew with beef and potatoes."
            ]
        elif risk_level == 'Mid Risk':
            return [
                "Breakfast: Scrambled eggs with whole wheat toast.",
                "Lunch: Fish with rice and peas.",
                "Snack: Fortified yogurt with fruits.",
                "Dinner: Lentil soup with chicken and vegetables."
            ]
        else:  # High Risk
            return [
                "Breakfast: Fortified oatmeal with eggs and milk.",
                "Lunch: High-protein chicken stew with rice.",
                "Snack: High-fat yogurt with fruit.",
                "Dinner: Protein-rich foods like beef stew with beans."
            ]

    elif 25 <= age_in_months <= 60:  # Preschool age (up to 5 years)
        if risk_level == 'Low Risk':
            return [
                "Breakfast: Scrambled eggs with toast and milk.",
                "Lunch: Grilled chicken with rice and broccoli.",
                "Snack: Apple slices with cheese.",
                "Dinner: Vegetable stew with lean beef."
            ]
        elif risk_level == 'Mid Risk':
            return [
                "Breakfast: Whole-grain cereal with milk and fruit.",
                "Lunch: Fish with rice and spinach.",
                "Snack: Peanut butter sandwich on whole grain bread.",
                "Dinner: Beef and vegetable stew with lentils."
            ]
        else:  # High Risk
            return [
                "Breakfast: Iron-fortified cereal with milk.",
                "Lunch: High-protein lentils with rice and vegetables.",
                "Snack: Whole milk with peanut butter toast.",
                "Dinner: Mashed beans with beef and spinach."
            ]
    else:
        return ["Meal plan not available for this age."]  # For children older than 5 years


@app.route('/admin/test_predict', methods=['GET'])
def test_predict():
    # Log the initial URL, args, and form for debugging
    app.logger.info(f"Test Request URL: {request.url}")
    app.logger.info(f"Test request.args: {request.args}")
    app.logger.info(f"Test request.form: {request.form}")

    # Retrieve child_id and log it
    child_id = request.args.get('child_id')
    app.logger.info(f"Received child_id in test route: {child_id}")

    if not child_id:
        app.logger.error("child_id is missing in request.args.")
        flash("Child ID is missing or invalid in test route.", "danger")
        return redirect(url_for('bhw_manage_child'))

    # Try parsing child_id as an integer to confirm validity
    try:
        child_id = int(child_id)
    except ValueError:
        app.logger.error(f"Invalid child_id format in test route: {child_id}")
        flash("Invalid child ID format in test route.", "danger")
        return redirect(url_for('bhw_manage_child'))

    # Log the final parsed child_id and return a success message
    app.logger.info(f"Successfully parsed child_id in test route: {child_id}")
    return f"Test route received child_id: {child_id}"



@app.before_request
def insert_barangays():
    barangays = [
        'Aganan', 'Amparo', 'Anilao', 'Balabag', 'Cabugao Norte', 'Cabugao Sur',
        'Jibao-an', 'Mali-ao', 'Pagsanga-an', 'Pal-agon', 'Pandac', 'Purok 1',
        'Purok 2', 'Purok 3', 'Purok 4', 'Tigum', 'Ungka 1', 'Ungka 2'
    ]

    # Check if there are existing barangays before inserting
    existing_barangays = Barangay.query.first()
    if not existing_barangays:
        for name in barangays:
            new_barangay = Barangay(name=name)
            db.session.add(new_barangay)
        db.session.commit()
        
with app.app_context():
        initialize_rchu_account()
        create_db_tables()
        
if __name__ == '__main__':
    app.run(debug=True)