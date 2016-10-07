# Lots of help from Homework 4 solutions

import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

from user import User
from post import Post
from comment import Comment
from like import Like

# Secret for encryption of cookies
secret = '010'

# Global Helper Functions

	# Global Render Template function
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

	# Encrypt and verify cookie values
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def blog_key(name='default'):
	return db.Key.from_path('blogs', name)

# Handler with universal helper functions
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self,template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', 
										'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

""" Render "/" redirect logged in and non logged in users to appropriate page
	and display 10 most recent posts
"""
class MainHandler(Handler):
    def get(self):
    	posts = db.GqlQuery("select * from Post order by created desc limit 10")
    	if self.user:
    		self.render("frontuser.html", posts = posts, username = self.user.name)
    	else:
	        self.render('front.html', posts = posts)

# Render Log In page, verify information and redirect appropritely
class LogIn(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
			self.login(u)
			self.render('welcome.html', username = username)
		else:
			msg = 'Invalid login'
			self.render('login.html', error = msg)

# Log Out User - redirect to log out page.
class LogOut(Handler):
	def get(self):
		self.logout()
		self.render('logout.html')

# Character restrictions for username, pw, and email
USER_RE = re.compile(r"^[a-zA-z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

# Verify registration fields and create User
class Register(Handler):
	def get(self):
		self.render("register.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if have_error:
			self.render('register.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		u = User.by_name(self.username)
		if u:
			msg = 'That username is already taken!'
			self.render('register.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.render('welcome.html', username = self.username)

# Verify subject and content and create new Post
class NewPost(Handler):
	def get(self):
		self.render("newpost.html", username = self.user.name)

	def post(self):
		if not self.user:
			self.redirect('/login', error = "You need to be logged in to post!")

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject != '' and len(content) > 7:
			p = Post(parent=blog_key(), user_id=self.user.key().id(),
				subject=subject, content=content, username = self.user.name)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "Please include a Subject title AND Content for your Post!"
			self.render("newpost.html", subject=subject,
						content=content, error=error)

# Delete current Post from database
class DeletePost(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if post.user_id == self.user.key().id():
				post.delete()
				self.render("deletedpost.html")
				return
			else:
				self.redirect("/blog/" +post_id+ "?error=You cannot delete this post.")
		else:
			self.render("login.html", error="You need to be logged in to delete posts.")

# Edit current Post
class EditPost(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if post.user_id == self.user.key().id():
				self.render("editpost.html", subject=post.subject,
							content=post.content)
			else:
				self.redirect("/blog/" +post_id+ "?error=You cannot edit this post.")

		else:
			self.render("login.html", error="You need to be logged in to edit posts.")

	def post(self, post_id):
		if not self.user:
			self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			p = db.get(key)
			p.subject = subject
			p.content = content
			p.put()
			self.redirect('/blog/%s' % post_id)
		else:
			error = "Please include a Subject title AND Content for your Post!"
			self.render("editpost.html", subject=subject,
						content=content, error=error)

""" Render Post content from database to new /blog/# page
	with appropriate comments, likes, and icon buttons.
"""
class BlogPost(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		comments = db.GqlQuery("select * from Comment where post_id = " +
								post_id + " order by created desc")
		likes = db.GqlQuery("select * from Like where post_id=" +post_id)

		if not post:
			self.error(404)
			return

		error = self.request.get('error')

		self.render("permalink.html", post=post, numLikes=likes.count(),
			comments=comments, error=error)

	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		c = ''

		if not post:
			self.error(404)
			return

		if(self.user):
			if(self.request.get('like') and
				self.request.get('like') == "update"):
				likes = db.GqlQuery("select * from Like where post_id = " +
									post_id + " and user_id = " +
									str(self.user.key().id()))

				if self.user.key().id() == post.user_id:
					self.redirect("/blog/" + post_id +
								"?error=You cannot like your own post.&username=" +
								self.user.name)
					return
				elif likes.count() == 0:
					l = Like(parent=blog_key(), user_id=self.user.key().id(),
							post_id= int(post_id))
					l.put()

			if self.request.get('comment') != '':
				c = Comment(parent=blog_key(), user_id=self.user.key().id(),
							post_id = int(post_id),
							comment=self.request.get('comment'))
				c.put()

		else:
			self.render("login.html", error="Log in before commenting or liking.")
			return

		comments = db.GqlQuery("select * from Comment where post_id = " +
								post_id + " order by created desc")
		likes = db.GqlQuery("select * from Like where post_id=" + post_id)
		self.render("permalink.html", post=post, comments=comments,
					numLikes=likes.count(), new=c, post_id=post_id)
		self.redirect("/blog/" + post_id)

# Delete current Comment from database
class DeleteComment(Handler):
	def get(self, post_id, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
			c = db.get(key)
			if c.user_id == self.user.key().id():
				c.delete()
				self.redirect("/blog/" +post_id+ "?deleted_comment_id=" +
								comment_id)
			else:
				self.redirect("/blog/" +post_id+ "?error=You cannot delete this comment.")
		else:
			self.render("login.html", error="You need to be logged in to delete comments.")

# Edit current Comment
class EditComment(Handler):
	def get(self, post_id, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id),
									parent=blog_key())
			c = db.get(key)
			if c.user_id == self.user.key().id():
				self.render("editcomment.html", comment=c.comment)
			else:
				self.redirect("/blog/" +post_id+ 
							"?error= You cannot edit this comment.")
		else:
			self.render("login.html", error="You need to be logged in to edit comments.")

	def post(self, post_id, comment_id):
		if not self.user:
			self.redirect('/')

		comment = self.request.get('comment')

		if comment:
			key = db.Key.from_path('Comment',
									int(comment_id), parent=blog_key())
			c = db.get(key)
			c.comment = comment
			c.put()
			self.redirect('/blog/%s' % post_id)
		else:
			error = "You cannot leave comment blank."
			self.render("editcomment.html", comment = c.comment)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', LogIn),
    ('/logout', LogOut),
    ('/register', Register),
    ('/blog/newpost', NewPost),
    ('/blog/deletepost/([0-9]+)', DeletePost),
    ('/blog/editpost/([0-9]+)', EditPost),
    ('/blog/([0-9]+)', BlogPost),
    ('/blog/deletecomment/([0-9]+)/([0-9]+)', DeleteComment),
    ('/blog/editcomment/([0-9]+)/([0-9]+)', EditComment)
], debug=True)
