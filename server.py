from flask import Flask, render_template, redirect, url_for, flash, request,session,jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor

import os

from groq import Groq

GROQ_APIKEY="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"
app = Flask(__name__)

app.secret_key = 'seoscriberFlask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///seoscriber.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    projects = db.relationship('Project', backref='user', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Save')


class ParaphraseForm(FlaskForm):
    text = TextAreaField('Text', validators=[DataRequired()], render_kw={"placeholder": "Enter text to paraphrase..."})
    submit = SubmitField('Suggestions')

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route("/")
def home():
    logged_in = current_user.is_authenticated
    name = current_user.username if logged_in else None
    return render_template("index.html", logged_in=logged_in, name=name)

@app.route("/login", methods=['GET', 'POST'])
def login():
    login_errors = {}
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            login_user(user)
            return redirect(url_for('home'))
        else:
            login_errors['email'] = ['Invalid email or password.']
    return render_template('login_signup.html', login_errors=login_errors, signup_errors={})

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    signup_errors = {}
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password != confirm:
            signup_errors['confirm'] = ['Passwords must match.']
        else:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                signup_errors['email'] = ['Email already exists. Please log in.']
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, email=email, password=hashed_password)
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Account created successfully!', 'success')
                    login_user(new_user)
                    return redirect(url_for('login'))
                except Exception as e:
                    db.session.rollback()
                    signup_errors['general'] = [f'Error creating account: {e}']
    return render_template('login_signup.html', login_errors={}, signup_errors=signup_errors)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/projects")
@login_required
def projects():
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    form = ProjectForm()
    return render_template("projects.html", projects=user_projects, form=form)

@app.route("/projects/new", methods=['GET', 'POST'])
@login_required
def new_project():
    form = ProjectForm()
    if form.validate_on_submit():
        new_project = Project(title=form.title.data, description=form.description.data, user_id=current_user.id)
        db.session.add(new_project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('keyword_generation'))
    return render_template('project_form.html', form=form)

@app.route("/projects/<int:project_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('You are not authorized to edit this project.', 'danger')
        return redirect(url_for('projects'))

    form = ProjectForm()
    if form.validate_on_submit():
        project.title = form.title.data
        project.description = form.description.data
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('projects'))

    form.title.data = project.title
    form.description.data = project.description
    return render_template('project_form.html', form=form)

@app.route("/projects/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('You are not authorized to delete this project.', 'danger')
        return redirect(url_for('projects'))

    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('projects'))


class KeywordForm(FlaskForm):
    keyword = StringField('Keyword', validators=[DataRequired()])

@app.route("/keyword_generation", methods=['GET', 'POST'])
def keyword_generation():
    long_tail_keywords = []
    lsi_keywords = []
    keyword = ''

    form = KeywordForm()

    if request.method == 'POST' and form.validate_on_submit():
        keyword = request.form.get('keyword')

        client = Groq(api_key=GROQ_APIKEY)  # Replace with your actual API key
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": f"Generate long tail keywords and LSI keywords for: {keyword} , dont use inverted commas and any other thing just generate keywords as mentioned and dont even give number mentioned of keyword just only word, dont use astericks at the start of word even"
                }
            ],
            model="llama3-8b-8192",
        )

        response = chat_completion.choices[0].message.content

        # Process the response to extract the keywords
        long_tail_keywords_section = False
        lsi_keywords_section = False

        for line in response.splitlines():
            line = line.strip()
            if "Long Tail Keywords" in line:
                long_tail_keywords_section = True
                lsi_keywords_section = False
                continue
            elif "LSI Keywords" in line:
                long_tail_keywords_section = False
                lsi_keywords_section = True
                continue

            if long_tail_keywords_section and line:
                long_tail_keywords.append(line)
            elif lsi_keywords_section and line:
                lsi_keywords.append(line)

        session['long_tail_keywords'] = long_tail_keywords
        session['lsi_keywords'] = lsi_keywords

    return render_template('keywordtoolhml.html', long_tail_keywords=long_tail_keywords, lsi_keywords=lsi_keywords, keyword=keyword, form=form)




from flask import Flask, render_template, request, jsonify
from groq import Groq  # Assuming you have imported Groq API client

@app.route('/paraphrase', methods=['GET', 'POST'])
def paraphrase():
    if request.method == 'POST':
        data = request.json
        original_text = data.get('editor_content', '')

        # Create the prompt for the Groq API
        prompt = (
            f"Analyze the following text and provide suggestions for improvement:\n\n"
            f"Text: {original_text}\n\n"
            "Suggestions:\n"
            "- Rewrite hard to read sentences.\n"
            "- Consider using active voices.\n"
            "- Replace too complex words.\n"
        )

        client = Groq(api_key=GROQ_APIKEY)  # Replace with your actual API key
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama3-8b-8192",
        )

        response = chat_completion.choices[0].message.content
        suggestions = response
        print(suggestions)
        return jsonify({'suggestions': suggestions})

    # For GET request, render the template
    long_tail_keywords = session.get('long_tail_keywords', [])
    lsi_keywords = session.get('lsi_keywords', [])
    return render_template('paraphrase.html', long_tail_keywords=long_tail_keywords, lsi_keywords=lsi_keywords)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


# keyboard and paraphrase no restrictiion
# writing assisstant restriction


