from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LogInUser, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

#gravatar 이미지 생성
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


# flask login 생성
login_manager = LoginManager()
login_manager.init_app(app)

# id를 기반으로 로그인
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 계정 보호 데코레이터 생성
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 유저 아이디가 1이 아니면 403 에러 발생
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

# 블로그 테이블
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key를 users.id로 지정한다. users는 User 테이블을 참조한다.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # User를 참조하는 관계를 지정한다.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Comment와의 관계 지정
    comments = relationship("Comment", back_populates="parent_post")

# 유저 테이블
class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    name = db.Column(db.String(250))

    # BlogPost의 author에 접근한다.
    posts = relationship("BlogPost", back_populates="author")

    # Comment의 comment author에 접근한다.
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key를 User 테이블의 users id로 생성한다.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # User를 를 참조하는 관계를 지정한다.
    comment_author = relationship("User", back_populates="comments")

    # Foreign Key = BlogPost.id
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # BlogPost와 관계
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)

db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods = ["GET", "POST"])
def register():
    # 폼 전달
    form = RegisterForm()

    # 검증 성공시 새로운 유저 db에 등록
    if form.validate_on_submit():

        # 비밀번호 해싱하기
        hased_password = generate_password_hash(
            password=form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )

        # 새로운 유저 등록
        new_user = User(
            email=form.email.data,
            password=hased_password,
            name=form.name.data,
        )
        if User.query.filter_by(email=new_user.email).first() :
            flash(message="이미 존재하는 이메일입니다. 로그인 해주세요.")
            return redirect(url_for('login'))

        db.session.add(new_user)
        db.session.commit()

        # 새로운 유저 로그인 인증
        login_user(new_user)
        # 홈페이지로 리다이렉트
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    # 폼 전달
    form = LogInUser()

    # 검증이 완료된 경우
    if form.validate_on_submit():

        email = form.email.data
        password = form.password.data

        #db에서 유저 찾기
        user = User.query.filter_by(email=email).first()

        # 이메일 존재 X
        if not user :
            flash(message="이메일이 존재하지 않습니다. 다시 시도해주세요.")
            return redirect(url_for('login'))

        # 패스워드 일치 X
        elif not check_password_hash(pwhash=user.password, password=password) :
            flash(message="비밀번호가 일치하지 않습니다. 다시 시도해주세요.")
            return redirect(url_for('login'))

        # 성공적 로그인
        else :
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


# 로그아웃하기
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    # 검증 완료시
    if form.validate_on_submit():

        # 로그인이 안되어있을 경우
        if not current_user.is_authenticated :
            flash("로그인을 해주세요.")
            return redirect(url_for('login'))

        new_comment = Comment(
            text = form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
