from google.appengine.ext import db

from user import User

""" Database for Likes, 
capturing user who submitted Like - user_id,
and post where it occurred - post_id """
class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

     # Return name of user who submitted Like
    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name