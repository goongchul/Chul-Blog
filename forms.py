from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("이메일", validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    name = StringField("이름", validators=[DataRequired()])
    submit = SubmitField("회원가입")

class LogInUser(FlaskForm):
    email = StringField("이메일", validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    submit = SubmitField("로그인")

class CommentForm(FlaskForm) :
    comment = CKEditorField("댓글", validators=[DataRequired()])
    submit = SubmitField("확인")