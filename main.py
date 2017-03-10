import random
import string
import webapp2
import jinja2
import os
from google.appengine.ext import db
import re
import hashlib
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# this is the main handler class

class Handler(webapp2.RequestHandler):
    def wirte(self, *a, **kw):  # this function show massage on the screen
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):  # this function render the html pages
        self.wirte(self.render_str(template, **kw))

    # this function set cookies
    def setSecureCookie(self, name, val, remember):
        cooki = Hashing().secureCookie(val)
        if remember == "on":
            self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Expires=Sun, 15 Jul 2020 00:00:01 GMT;  path=/'
                % (name, cooki))
        else:
            self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Expires=0;  path=/' % (name, cooki))

    def readScureCookie(self, name):  # this function read user cookies
        cookie = self.request.cookies.get(name)
        return cookie and Hashing().check_secure(cookie)

    def deleteCookie(self):  # this function delete user cookie
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=;  path=/')

    # this function ger the cookie if it exist and return it
    def getCookie(self):
        fullCookie = self.request.cookies.get('user_id')
        if fullCookie:
            cookie = fullCookie.split('|')[0]
            return cookie

    def loggedIn(self):  # this login check function
        logged = self.request.cookies.get('user_id')
        if logged == "" or logged is None:
            return False
        else:
            return True


# this is the key which used in hashing
secret = 'asgvsf-sadvbaf.afsgvasf%dsf#F3@&54(fsavf_fbazdfsb+)*FVS'


# this is the hashing class which have all hashing functions
class Hashing():
    # this function hashing any val with the secret key and return it
    def make_secure(self, val):
        secured = [val, hmac.new(secret, val).hexdigest()]
        return secured

    # this function check the val with the secret key
    def check_secure(self, secured):
        val = secured[0]
        if Hashing().make_secure(val) == secured:
            return val

    # this function hashing the password with random key and store it
    def hashPassword(self, name, password, key=None):
        if not key:
            key = ''.join(random.choice(string.letters) for x in range(5))
        hashed = [hashlib.sha256(name + password + key).hexdigest(), key]
        return hashed

    # this function check if the password with right or not
    def valiedPassword(self, name, password, hashed):
        key = hashed[1]
        return hashed == Hashing().hashPassword(name, password, key)

    # this function which hashing the cookie before store it
    def secureCookie(self, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# this class make sure that the user enter valied info. when sign up
class Verification():
    def nameValied(self, name):  # this function make sure the name is valied
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(name)

    # this function make sure the passwoed is valied
    def passwordValied(self, pasword):
        PASS = re.compile("^.{3,20}$")
        return PASS.match(pasword)

    # this function match the password we verfiy password
    def verfiyPassword(self, pasword, verfiy):
        if pasword == verfiy:
            return True
        else:
            return False

    # this function make sure that the email is vailed if it exist
    def emailValied(self, email):
        if email != "":
            MAIL = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
            return MAIL.match(email)
        else:
            return True


# this is the class post have title and body
# and the user who make it and the time order
class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateProperty(auto_now_add=True)
    order = db.DateTimeProperty(auto_now_add=True)


# this is the class comments have the comment and the post
# and user who post the comment and date
class Comments(db.Model):
    post = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    user = db.StringProperty(required=True)
    date = db.DateProperty(auto_now_add=True)


# this is the class like have the post which be liked
# and user who like and the date
class Like(db.Model):
    post = db.StringProperty(required=True)
    user = db.StringProperty(required=True)
    date = db.DateProperty(auto_now_add=True)


# this is the class user which have his name and password hash
# and the key used in hashing and his email if it exist
class User(db.Model):
    name = db.StringProperty(required=True)
    hash = db.TextProperty(required=True)
    hashKey = db.StringProperty(required=True)
    email = db.EmailProperty()

    @classmethod
    # this function search for user name and return it if it exist
    def searchName(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    # this function login take the username
    # and paswword and if it right the user login
    def login(cls, username,
              password):
        u = User.searchName(username)
        if u:
            hashed = [u.hash, u.hashKey]
            if Hashing().valiedPassword(username, password, hashed):
                return u


# this class represent the home page
class MainHandler(Handler):
    # in function get i get all the posts and display it
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY order DESC limit 10")
        check = self.loggedIn()
        user = self.getCookie()
        if user:  # if the user logged in i get his name and display it too
            key = db.Key.from_path("User", long(user))
            account = db.get(key)
            name = account.name
        else:
            name = ""

        # this list will hold number of likes for each post
        like = []
        # this list will hold  boolean value of which posts the user like
        likeunlike = []
        # this list will hold number of comments for each post
        comment = []

        # in this loop i count the number of likes and comments
        # in each post and if the user like this post before or not
        for post in posts:
            postID = post.key().id()
            likes = db.GqlQuery("SELECT * FROM Like WHERE post = :1",
                                str(postID))
            likes_user = db.GqlQuery("SELECT * FROM Like WHERE post = :1 AND "
                                     "user= :2",
                                     str(postID), str(user))
            comments = db.GqlQuery("SELECT * FROM Comments WHERE post = :1",
                                   str(postID))
            # append the number of likes
            like.append(likes.count())
            # append the number of comments
            comment.append(comments.count())
            if likes_user.count() >= 1:
                # append True if the user didn't like the post
                likeunlike.append(True)
            else:
                # append False if the user like the post
                likeunlike.append(False)

        # then reverse the lists because it's pop from the end
        # and that mean the first post will get the last post info
        # so reverse it make the first post pop no the last one
        like.reverse()
        comment.reverse()
        likeunlike.reverse()
        self.render("home.html", posts=posts,
                    logged=check, user=name,
                    like=like, comment=comment,
                    unlike=likeunlike)

    # the post function and the user logged in and liked the post
    #  before can unlike and and if didn't like before can lke
    # if he wasn't a user and click the like button will go to login page
    def post(self):
        cookie = self.getCookie()
        key = db.Key.from_path("User", long(cookie))
        account = db.get(key)
        name = account.name
        if self.request.get("action") == "like" and cookie != "":
            post = self.request.get("post")
            check = Post.get_by_id(long(post))
            if check.username != name:
                likes = db.GqlQuery("SELECT * FROM Like WHERE post = : 1 AND "
                                    " user = : 2 ", post, cookie)
                if likes.count() >= 1:
                    db.delete(likes)
                    self.redirect('/')
                else:
                    l = Like(user=cookie, post=post)
                    l.put()
                    self.redirect('/')
            else:
                self.render("errors.html",
                            message="You can't like your own post")
        else:
            self.redirect('/login')


# this class new post responsible for creating new post
class NewPost(Handler):
    # in the get methond i just make sure that
    # a user make the post and pass his name
    def get(self):
        if self.loggedIn():
            user = self.getCookie()
            if user:
                key = db.Key.from_path("User", long(user))
                account = db.get(key)
                name = account.name
            self.render("post.html", user=name, action="Post !")
        else:
            self.redirect("/register")

    # in the post function i take the title and the body
    # and make sure that he is a user again then the all info valid
    # save the post in DB
    def post(self):
        title = self.request.get("title")
        body = self.request.get("text")
        cookie = self.getCookie()
        # if the user click on cancel button
        if self.request.get("action") == "Cancel":
            self.redirect("/porfile")
        else:
            if title and body:
                # this like here replace every new line with break
                newBody = body.replace('\n', '<br>')
                key = db.Key.from_path("User", long(cookie))
                user = db.get(key)
                name = user.name
                if title and body and user:
                    a = Post(title=title, body=newBody, username=name)
                    self.wirte(newBody)
                    a.put()
                self.redirect("/post/%s" % str(a.key().id()))
            # if not valied i render the page again  but with
            # the title and body to let the user edit it again
            else:
                error = "Please submit all the filed"
                self.render("post.html", ti=title, ar=body, er=error)


# after user submit the post redirect to single
# post page which this class handel it
class PostPage(Handler):
    # first get the post id then retrieve the post data then display
    def get(self, postID):
        check = self.loggedIn()
        post = Post.get_by_id(int(postID))
        # in addition to that this page the users can comment on
        # the post on that why i retrive all comment  to the post
        c = db.GqlQuery("SELECT * FROM Comments WHERE post= :1 ", postID)
        user = self.getCookie()
        key = db.Key.from_path("User", long(user))
        account = db.get(key)
        name = account.name
        # then i ckeck if one of this comment the logged in user write
        # it so enable to him delete and edit button
        # this list have true if the
        # comment belong to the current user false if not
        userComments = []
        for comment in c:
            if comment.user == name:
                userComments.append(True)
            else:
                userComments.append(False)

        userComments.reverse()
        self.render('singlepost.html', post=post,
                    logged=check, comments=c,
                    user=name, commented=userComments)

    # in this page u can do 2 thing 1-user can add
    # comment 2-user can edit/delete his comment
    def post(self, postID):
        body = self.request.get("text")
        newBody = body.replace('\n', '<br>')
        cookie = self.getCookie()
        key = db.Key.from_path("User", long(cookie))
        user = db.get(key)
        name = user.name
        # here take the body of the comment
        # and user and the post then store in DB
        if newBody and user and postID:
            c = Comments(post=postID, body=newBody, user=name)
            c.put()
            self.redirect('/post/%s' % str(postID))

        # here if user click on delete button in one of his
        # comments i get this comments then delete it from the DB
        elif self.request.get("action") == "delete":
            commentID = self.request.get("comment")
            c = Comments.get_by_id(long(commentID))
            if c:
                if c.user == name:
                    db.delete(c)
                    self.redirect('/post/%s' % str(postID))
                else:
                    self.render("errors.html",
                                massage="This is not your comment")

        # here if user click on edit button then i get the
        # comment id then redirect to edit page with this id
        elif self.request.get("action") == "edit":
            commentID = self.request.get("comment")
            c = Comments.get_by_id(long(commentID))
            if commentID:
                if c.user == name:
                    self.redirect('/edit_comment/%s' % str(commentID))
                else:
                    self.render("errors.html",
                                massage="This is not your comment")


# thie class made for to handle the sign up page
class NewUser(Handler):
    def get(self):
        check = self.loggedIn()
        self.render("register.html", logged=check)

    # in the post i get the info the user entered
    def post(self):
        name = self.request.get("username")
        password = self.request.get("pasword")
        verfiy = self.request.get("verfiy")
        email = self.request.get("email")

        haveError = False

        params = dict(username=name, email=email)
        # then check if the user info valied if not
        # then will make the boolean value be false
        if not Verification().nameValied(name):
            params['nameError'] = "That's not a valid username."
            haveError = True

        if not Verification().passwordValied(password):
            params['passwordError'] = "That wasn't a valid password."
            haveError = True

        if not Verification().verfiyPassword(password, verfiy):
            params['verifyError'] = "Your passwords didn't match."
            haveError = True

        if not Verification().emailValied(email):
            params['emailError'] = "That's not a valid email."
            haveError = True
        # if the boolean value be false that's
        # mean one of the values it's not valied
        if not haveError:
            u = User.searchName(name)
            if u:
                msg = 'the user already exist'
                self.render('register.html', userError=msg)
            # if it valied and the username was unique
            # then save the account in DB
            else:
                hashed = Hashing().hashPassword(name, password)
                if email != "":
                    new = User(name=name, hash=hashed[0],
                               hashKey=hashed[1], email=email)
                else:
                    new = User(name=name, hash=hashed[0], hashKey=hashed[1])
                new.put()
                self.redirect('/welcome')

        else:
            check = self.loggedIn()
            params['logged'] = check
            self.render('register.html', **params)


# this page made for login
class Login(Handler):
    def get(self):
        if self.loggedIn():
            self.redirect('/')
        else:
            check = self.loggedIn()
            self.render("login.html", logged=check)

    # get the username and password form the user and then
    # send it to login function and if return user that;s mean it's
    # valied info then login if not then show error massage
    def post(self):
        name = self.request.get("username")
        password = self.request.get("password")
        remember = self.request.get("remember")
        u = User.login(name, password)
        if u:
            # the cookie be hashed before stored
            # to not allow the user to edit on it
            self.setSecureCookie('user_id', str(u.key().id()), remember)
            self.redirect('/welcome')
        else:
            msg = 'please enter a valid name and valid password'
            self.render("login.html", passwordWong=msg)


# this class for welcome page which appear
class Welcome(Handler):
    def get(self):
        cookie = self.getCookie()
        check = self.loggedIn()
        # if no cookies will redirect to login page
        if cookie == "" or cookie is None:
            self.redirect('/login')
        else:  # if there cookie will redirect welcome page
            key = db.Key.from_path("User", long(cookie))
            user = db.get(key)
            self.render("welcome.html", user=user.name, logged=check)


# this class made for my profile page
class Profile(Handler):
    def get(self):
        cookie = self.getCookie()
        # check if this a user get all hi post form db and display
        if cookie:
            key = db.Key.from_path("User", long(cookie))
            user = db.get(key)
            name = user.name
            p = db.GqlQuery("SELECT * FROM Post WHERE username = :1",
                            name)
            # this retrieve all posts with this user name
            check = self.loggedIn()
            self.render("myprofile.html", posts=p, logged=check, user=name)
        # else redirect him to login page to login
        else:
            self.redirect('/login')

    # in the profile the user can edit/delete his posts
    def post(self):
        # take the value of clicked button
        user = self.getCookie()
        key = db.Key.from_path("User", long(user))
        account = db.get(key)
        name = account.name
        # if it was delete button get the post then delete from DB
        action = self.request.get("action")
        if (action == "delete"):
            postID = self.request.get("post")
            check = Post.get_by_id(long(postID))
            if check.username == name:
                p = Post.get_by_id(long(postID))
                if p:
                    db.delete(p)
                    self.redirect('/profile')
                else:
                    self.redirect('/profile')
            else:
                self.render("errors.html", message="This is not your post")
        # if it was edit button get the post
        #  from DB then send it id to edit page
        elif (action == ("edit")):
            postID = self.request.get("post")
            p = Post.get_by_id(long(postID))
            if p.username == name:
                self.redirect("/edit_post/%s" % str(p.key().id()))
            else:
                self.render("errors.html", message="This is not your post")


# this class made for edit post take the post id
class EditPost(Handler):
    # form post id get body and title and show it to user to edit on it
    def get(self, postID):
        p = Post.get_by_id(long(postID))
        title = p.title
        body = p.body
        self.render("post.html", title=title, body=body, action="Update")

    # after user click update i get the title and body and update if in DB
    def post(self, postID):
        title = self.request.get("title")
        body = self.request.get("text")
        user = self.getCookie()
        key = db.Key.from_path("User", long(user))
        account = db.get(key)
        name = account.name
        p = Post.get_by_id(long(postID))
        if p.username == name:
            if p and title != "" and body != "":
                p.title = title
                p.body = body
                p.put()
                self.redirect('/profile')
            # if user leave the title and the body empty it will be deleted
            else:
                db.delete(p)
                self.redirect('/profile')
        else:
            self.render("errors.html", message="This is not your post")


# this class responsible for editing comments
class EditComment(Handler):
    # i get the comment body and display to the user to edit it
    def get(self, commentID):
        c = Comments.get_by_id(long(commentID))
        self.render("editcomment.html", body=c.body)

    # after that user click update then i get the body and update if in DB
    def post(self, commentID):
        user = self.getCookie()
        key = db.Key.from_path("User", long(user))
        account = db.get(key)
        name = account.name
        c = Comments.get_by_id(long(commentID))
        if c.user == name:
            body = self.request.get("text")
            if body != "":
                c.body = body
                c.put()
                self.redirect("/post/%s" % str(c.post))
            # and if the comment body was empty the
            # comment will be deleted after submit
            else:
                db.delete(c)
                self.redirect("/post/%s" % str(c.post))
        else:
            self.render("errors.html", message="This is not your comment")


# this class work when click in sign out then call
# function then delete the cookies the redirect to login page
class Logout(Handler):
    def get(self):
        self.deleteCookie()
        self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/post', NewPost),
    ('/register', NewUser),
    (r'/post/([0-9]+)', PostPage),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
    ('/profile', Profile),
    (r'/edit_post/([0-9]+)', EditPost),
    (r'/edit_comment/([0-9]+)', EditComment)
], debug=True)
