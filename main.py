from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comment = relationship("CommentPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    author = relationship("User", back_populates="posts")

    comment = relationship("CommentPost", back_populates="post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class CommentPost(db.Model):
    __tablename__ = "post_comment"
    id = db.Column(db.Integer, primary_key=True)
    # romimy łączę z główną bazą relacyjną
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    author = relationship("User", back_populates="comment")
    comment_body = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comment")




db.create_all()



login_manager = LoginManager()
login_manager.init_app(app)
# element ten ma zczytać lokalne id sesji
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
def get_all_posts():
    # current = flask_login.current_user
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("This user already exist pliss log in")
            return redirect(url_for('login'))
        else:
            password_hashed = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=password_hashed
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        inputed_email = form.email.data
        inputed_password = form.password.data
        detect_user = User.query.filter_by(email=inputed_email).first()
        if detect_user:
            if check_password_hash(password=inputed_password, pwhash=detect_user.password):
                login_user(user=detect_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash(message="Inputed password is incorrect plis try again")
                return redirect(url_for('login', form=form))
        else:
            flash(message="Inputed email is incorrect plis try again")
            return redirect(url_for('login', form=form))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)

    # poniżej form będzie duuużo zmian
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_anonymous:
            flash("Plis log in to add a comment", category="error")
            form2 = LoginForm()
            return redirect(url_for('login', form=form2))
        new_comment = CommentPost(
            comment_body=form.comment_body.data,
            post=requested_post,
            author=current_user
        )
        db.session.add(new_comment)
        db.session.commit()
        # return redirect(url_for("post.html", post=requested_post, form=form))
        # return render_template("post.html", post=requested_post, form=form)
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,          
            # author=current_user.name,
            # Jako że baza danych jest relacyjna a author jest właśnie określany realacyjnie wywali nam
            # error należy usunąć stare określanie autora i pozwolić relacji ustanowić wartość
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )

        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author_id = current_user.id
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
