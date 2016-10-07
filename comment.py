from google.appengine.ext import db

from user import User

""" Database for Comments, 
capturing user who submitted comment - user_id,
and post where it occurred - post_id,
comment content - comment,
and created/modified times - created. last_modified """
class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

     # Return name of user who submitted Comment
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name
