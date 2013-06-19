# encoding=utf-8
#!/usr/bin/env python

import urllib
import logging
import webapp2
import cgi
import codecs
import re
import jinja2
import random
import string
import hashlib
import hmac
import json
from datetime import datetime

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'),
                               autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PWD_RE = re.compile(r"^.{3,20}$")
def valid_pwd(pwd):
    return PWD_RE.match(pwd)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def get_form():
    return get_content('play.html')

def get_rot13_page():
    return get_content('rot13.html')

def get_signup_page():
    return get_content('signup.html')

def get_welcome_page():
    return get_content('welcome.html')

# cookies stuff
SECRET = 'iZfCbzSPhQ'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# pwd stuff
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = make_salt()):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    hash, salt = h.split(',')
    if hash == make_pw_hash(name, pw, salt).split(',')[0]:
        return True

class BlogPost(db.Model):
    content = db.TextProperty(required = True)
    subject = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def to_json(self):
        return {"subject": self.subject,
                "content": self.content}

class Users(db.Model):
    username = db.StringProperty(required = True)
    pwd = db.TextProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def register(cls, username, pwd, email = None):
        password_hash = make_pw_hash(username, pwd)
        return Users(username = username,
                    pwd  = password_hash,
                    email = email)

    @classmethod
    def by_name(cls, username):
        u = Users.all().filter('username =', username).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id(uid)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        """Write to response"""
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        """Render template with given params"""
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kwargs):
        """Render html template to response"""
        self.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.write(self.render_str(template, **kwargs))

    def write_json(self, obj):
        self.response.headers['Content-Type'] = 'application/json; charset=utf-8'
        self.write(json.dumps(obj))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def clear_cookie(self, name):
        self.response.headers.add_header(
            'Set-Cookie', '%s=; Path=/' % name)

    def logout(self):
        self.clear_cookie('user_id')

    def read_user_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_user_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))

class ThanksHandler(Handler):
    def get(self):
        self.response.write('That is greate!')

class Rot13Handler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
        self.write_response()

    def write_response(self, text=""):
        self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
        self.render("rot13.html", rot=text)

    def post(self):
        self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
        rotted = codecs.encode(self.request.get('text'), 'rot13')
        self.write_response(rotted)

class SignupHandler(Handler):
    def write_form(self, username="", email="",
                         username_error="", password_error="",
                         verify_error="", email_error=""):
        self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
        self.render("signup.html", **{"username": username,
                                      "email": email,
                                      "username_error": username_error,
                                      "password_error": password_error,
                                      "verify_error": verify_error,
                                      "email_error": email_error})

    def get(self):
        self.write_form()

    def post(self):
        args = dict(zip(self.request.arguments(),
                        map(lambda it: self.request.get(it), self.request.arguments())))

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_error = "" if valid_username(username) else "Invalid username"
        password_error = "" if valid_pwd(password) else "Wrong password lenght"
        verify_error = "" if password == verify else "Passwords didn't match"
        email_error = "" if not email or valid_email(email) else "Wrong email format"

        if not username_error:
            e = Users.all().filter('username =', username).get()
            if e:
                username_error = "User with the same username already exists"

        if not (username_error or password_error or verify_error or email_error):
            # set cookies
            new_user = Users.register(username = username,
                                      pwd = password,
                                      email = email )
            new_user.put()
            self.login(new_user)

            self.redirect('/welcome')
        else:
            self.write_form(username, email, username_error, password_error,
                            verify_error, email_error)

def get_cache(cache_key = 'all', update = False):
    val = memcache.get(str(cache_key))
    if update or val is None:
        if cache_key == 'all':
            val = BlogPost.gql("ORDER BY created DESC")
            val = (list(val), datetime.utcnow())
            memcache.set(cache_key, val)
        else:
            val = BlogPost.get_by_id(cache_key)
            if val:
                val = (val, datetime.utcnow())
                memcache.set(str(cache_key), val)
    return val

class Blog(Handler):
    def render_front(self, posts, sec):
        self.render("blog.html", posts=posts, sec=sec)

    def get(self, method):
        posts, gen_time = get_cache()
        d = datetime.utcnow() - gen_time
        
        if method and method.endswith('.json'):
            jsn = [x.to_json() for x in posts]
            self.write_json(jsn)
        else:
            self.render_front(posts, d.seconds)

class NewPost(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = BlogPost(subject = subject, content = content)
            key = post.put()
            get_cache(update = True)
            self.redirect('/%d' % key.id())
        else:
            error = "Subject and content are needed!"
            self.render_front(subject = subject, content = content, error = error)

class PostHandler(Handler):
    def get(self, post_id, method):
        ok = post_id.isdigit()

        id_int = int(post_id)
        ok &= (id_int != 0)

        post = None
        gen_time = None

        if ok:
            post, gen_time = get_cache(id_int)
            ok &= True if post else False

        if ok:
            if method and method.endswith('.json'):
                self.write_json(post.to_json())
            else:
                d = datetime.utcnow() - gen_time
                self.render("post.html", post=post, sec=d.seconds)
        else:
            self.redirect('/')

class LoginHandler(Handler):
    def write_form(self, username="", error=""):
        self.render("login.html", username = username, error = error)
    
    def get(self):
        self.write_form()
        
    def post(self):
        username = self.request.get('username')
        pwd = self.request.get('password')

        user = Users.by_name(username)
        
        if user and valid_pw(username, pwd, user.pwd):
            self.login(user)
            self.redirect('/welcome')
        else:
            self.write_form(username, "Invalid login or/and password")

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render("welcome.html", username = self.user.username)
        else:
            self.redirect('/signup')

class GameMain(Handler):
    """Main game page
    """
    def get(self):
        self.render("index.html");

class FlushHandler(Handler):
    """Flush memcache
    """
    def flush(self):
        memcache.flush_all()
        self.redirect('/')
        
    def post(self):
        self.flush()

    def get(self):
        self.flush()

routes = [('/', GameMain)]

app = webapp2.WSGIApplication(routes, debug=True)
