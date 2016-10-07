from google.appengine.ext import db

from user import User
import main

""" Database for Posts, 
capturing username - username,
user who submitted comment - user_id,
subject & content - subject, content,
and created/modified times - created, last_modified """
class Post(db.Model):
    username = db.StringProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # Return name of user who submitted Post
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    # Render current post to post.html
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return main.render_str("post.html", p=self)
