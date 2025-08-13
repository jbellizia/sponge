from flask import Flask, request, render_template, redirect, url_for, flash, abort, jsonify, Markup, session, send_from_directory
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import date, datetime, timedelta
from dotenv import load_dotenv
import os
import re
from PIL import Image, ImageOps
import uuid
from base64 import b64decode
from enum import Enum
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app)


#load env file
load_dotenv()


#set up flask app config
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['PROFILE_PIC_FOLDER'] = 'static/profile_pictures'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_DEFAULT_SENDER'] = ('Sponge', os.getenv('MAIL_USERNAME'))
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024 
app.config['TEMPLATES_AUTO_RELOAD'] = True


mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

DB_FILE =  os.getenv("DATABASE_PATH", "users.db")

#set up flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



#class for each sponge user
class User(UserMixin):
    def __init__(self, id, email, password, username, bio, profile_pic_filename, notifications_enabled):
        self.id = id
        self.email = email
        self.password = password
        self.username = username
        self.bio = bio
        self.profile_pic_filename = profile_pic_filename
        self.notifications_enabled = notifications_enabled
        
#class for each post on sponge
class Post:
    def __init__(self, id, user_id, caption, image_filename, timestamp, repost_id):
        self.id = id
        self.user_id = user_id
        self.caption = caption
        self.image_filename = image_filename
        self.timestamp = timestamp
        self.repost_id = repost_id
        
#class for each notification   
class Notification:
    def __init__(self, id, user_id, from_user_id, post_id, comment_id, type, is_read, timestamp):
        self.id = id
        self.user_id = user_id
        self.from_user_id = from_user_id
        self.post_id = post_id
        self.comment_id = comment_id
        self.type = type
        self.is_read = is_read
        self.timestamp = timestamp
        
#enum for determining type of notif   
class NotificationType(Enum):
    FOLLOW = "follow"
    COMMENT = "comment"
    MENTION = "mention"
    REPLY = "reply"
    LIKE_MILESTONE = "like_milestone"
    RESPONGE = "responge"
    MENTION_IN_COMMENT = "mention_in_comment"

#establishes connection with database and enables FKs
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

#helper function for inserting into notifications table
def insert_notification(conn, recipient_id, actor_id=None, post_id=None, comment_id=None, notif_type=None, is_read=False):
    #verify notif type
    if notif_type is None:
        raise ValueError("notif_type must be provided")
    if not isinstance(notif_type, NotificationType):
        raise ValueError("notif_type must be an instance of NotificationType Enum")
    
    #insert notif
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notifications (user_id, from_user_id, post_id, comment_id, type, is_read)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (recipient_id, actor_id, post_id, comment_id, notif_type.value, int(is_read)))
        conn.commit()
    except Exception as e:
        print("Notification insert failed:", e)



#function for validating username characters
def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None


#verify uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


#initialize DB function
def db_setup():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE  IF NOT EXISTS "pending_codes" (
                "email" TEXT PRIMARY KEY,
                "code" TEXT,
                "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ''')
        cur.execute('''
            CREATE TABLE  IF NOT EXISTS "whitelist" (
                "id" INTEGER,
                "name" TEXT,
                "email" TEXT UNIQUE,
                PRIMARY KEY("id" AUTOINCREMENT)
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS "users" (
                "id" INTEGER,
                "email" TEXT,
                "password_hash" TEXT,
                "username" TEXT,
                "bio" TEXT,
                "profile_pic_filename" TEXT DEFAULT 'default_profile_pictures/default.png',
                "notifications_enabled" INTEGER DEFAULT 1,
                PRIMARY KEY("id" AUTOINCREMENT)
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER NOT NULL,
                followed_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (follower_id, followed_id),
                FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (followed_id) REFERENCES users(id) ON DELETE CASCADE
            );
            ''')
        cur.execute('''
            CREATE TABLE  IF NOT EXISTS comments (
                id INTEGER,
                user_id INTEGER,
                post_id INTEGER,
                comment_text TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(id AUTOINCREMENT),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS "posts" (
                "id" INTEGER,
                "user_id" INTEGER,
                "caption" TEXT,
                "image_filename" TEXT,
                "timestamp" DATETIME DEFAULT CURRENT_TIMESTAMP,
                "repost_id" INTEGER DEFAULT -1, last_notified_likes INTEGER DEFAULT 0,
                
                PRIMARY KEY("id" AUTOINCREMENT),
                FOREIGN KEY("repost_id") REFERENCES "posts"("id") ON DELETE SET NULL,
                FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER,
                user_id INTEGER,
                post_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                PRIMARY KEY(id AUTOINCREMENT),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                UNIQUE(user_id, post_id) 
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS email_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT,
                subject TEXT,
                body TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                from_user_id INTEGER,
                post_id INTEGER,
                comment_id INTEGER,
                
                type TEXT NOT NULL CHECK (type IN (
                    'follow',
                    'comment',
                    'mention',
                    'reply',
                    'like_milestone',
                    'responge',
                    'mention_in_comment'
                )),
                
                is_read BOOLEAN NOT NULL DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(user_id) REFERENCES "users"(id) ON DELETE CASCADE,
                FOREIGN KEY(from_user_id) REFERENCES "users"(id) ON DELETE SET NULL,
                FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );

            ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS updates_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                header TEXT,
                body TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ''')
        # Insert a sentinel "system" user (if not already present)
        cur.execute('''
            INSERT OR IGNORE INTO users (id, email, password_hash, username, bio)
            VALUES (-1, 'system@example.com', '', 'System', 'System placeholder user')
        ''')

        # Insert a sentinel post for non-reposts (if not already present)
        cur.execute('''
            INSERT OR IGNORE INTO posts (id, user_id, caption, image_filename, repost_id)
            VALUES (-1, -1, 'Sentinel post', '', NULL)
        ''')
        
        conn.commit()

# helper function to get user object by userid
def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username, bio, profile_pic_filename, notifications_enabled FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None

# helper function to get username  by userid
def get_username_by_id(user_id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None
    
# helper function to get userid  by username
def get_id_by_username(username):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row[0] if row else None
    
# helper function to get username  by userid
def get_user_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, username, bio, profile_pic_filename, notifications_enabled FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None

#login manager jawn
@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# helper function that determines if user1 is following user2
def is_following(user_id_1, user_id_2):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM follows WHERE follower_id = ? and followed_id = ?", (user_id_1, user_id_2,))
    row = cur.fetchone()
    if row:
        return True
    return False

#helper function to get a post object by its post id
def get_post_by_id(id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, caption, image_filename, timestamp, repost_id FROM posts WHERE id = ?", (id,))
    row = cur.fetchone()
    conn.close()
    return Post(*row) if row else None

#for getting the OP object from a post id
def get_user_by_post_id(post_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT users.*
        FROM users
        JOIN posts ON users.id = posts.user_id
        WHERE posts.id = ?;
        """, (post_id,))
    row = cur.fetchone()
    conn.close()
    return User(*row) if row else None
   
#takes text and returns list of user objects that have been mentioned ie @username. uses regex written by chat
def extract_mentions(text):
    usernames = list(set(re.findall(r'@(\w+)', text)))

    if not usernames:
        return []
    
    placeholders = ','.join(['?'] * len(usernames))
    query = f"SELECT id, email, password_hash, username, bio, profile_pic_filename, notifications_enabled FROM users WHERE LOWER(username) IN ({placeholders})"
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(query, usernames)
    rows = cur.fetchall()
    
    conn.close()
    return [User(*row) for row in rows]    

#written mostly by chat
#replaces usernames in comments with link to their profile
@app.template_filter('link_mentions')
def link_mentions_filter(text):
    # Extract all mentioned usernames
    mentioned_usernames = set(re.findall(r'@(\w+)', text))

    if not mentioned_usernames:
        return Markup(text)

    # Fetch existing usernames from the DB
    placeholders = ','.join(['?'] * len(mentioned_usernames))
    query = f"SELECT username FROM users WHERE username IN ({placeholders})"

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, list(mentioned_usernames))
        rows = cur.fetchall()

    existing_usernames = set(row[0] for row in rows)

    # Replace only if username exists
    def replace_mention(match):
        username = match.group(1)
        if username in existing_usernames:
            profile_url = url_for('profile', username=username)
            return f'<a href="{profile_url}" class="mention">@{username}</a>'
        else:
            return f'@{username}'  # Leave plain text

    linked_text = re.sub(r'@(\w+)', replace_mention, text)
    return Markup(linked_text)

#easter egg template filter that gives my account a unique style. kinda fun
@app.template_filter("style_username")
def style_username(username):
    if username.lower() == "james":
        return f'<span class="dev-username">{username}</span>'
    return username


# helper function to log emails in DB
def log_email(conn, recipient, subject, body):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO email_log (recipient, subject, body)
        VALUES (?, ?, ?)
    """, (recipient, subject, body))
    conn.commit()    

    
#landing page
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))
    
#feed page, login required
@app.route('/home')
@login_required
def home():
    session['last_safe_url'] = request.url #this helps with edit post when deleting. basically so that we can redirect backwards without getting a 404
    ten_days_ago = datetime.now() - timedelta(days=10) 
    page = int(request.args.get('page', 1)) #pagination was helped by chat, essentially ten posts per page
    per_page = 10
    offset = (page - 1) * per_page

    with get_db_connection() as conn:
        cur = conn.cursor()

        # Count total posts from followed users
        cur.execute("""
            SELECT COUNT(*)
            FROM posts
            WHERE posts.user_id IN (
                SELECT followed_id FROM follows WHERE follower_id = ?
                UNION
                SELECT ?
            )
            AND posts.timestamp >= ? AND posts.id != -1
        """, (current_user.id, current_user.id, ten_days_ago))
        total_posts = cur.fetchone()[0]

        #get paginated posts from followed users
        cur.execute("""
            SELECT 
                posts.id, 
                posts.user_id, 
                users.username, 
                users.profile_pic_filename,
                posts.caption, 
                posts.image_filename, 
                posts.timestamp, 
                posts.repost_id,

                (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS likes,

                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE likes.post_id = posts.id 
                    AND likes.user_id = ?
                ) AS liked,
                
                (SELECT COUNT(*) FROM posts AS p2 WHERE p2.repost_id = posts.id) AS repost_count,
                (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) AS comment_count

            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.user_id IN (
                SELECT followed_id FROM follows WHERE follower_id = ?
                UNION
                SELECT ?
            )
            AND posts.timestamp >= ?
            AND posts.id != -1
            ORDER BY posts.timestamp DESC
            LIMIT ? OFFSET ?

            """, (current_user.id, current_user.id, current_user.id, ten_days_ago, per_page, offset))


        posts = cur.fetchall()
    #pass number of pages and currpage as well as all the posts within the last 10 days on the page. passing other functions for frontend jinja use
    total_pages = (total_posts + per_page - 1) // per_page
    return render_template('home.html', posts=posts, page=page, total_pages=total_pages, get_post_by_id=get_post_by_id, get_user_by_id=get_user_by_id)


    
# the landing page for logged out users
@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        user = get_user_by_username(username)
        password = request.form['password']
        
        #recommended by chat for security against timing attacks
        if user:
            valid = check_password_hash(user.password, password)
        else:
            # Run dummy comparison to prevent timing attack
            valid = check_password_hash(DUMMY_HASH, password)
        
        
        if valid and user:
            login_user(user)
            return redirect(url_for('home'))
        flash("Invalid credentials", 'login')
    username = request.args.get('username', '').lower()
    return render_template('login.html', username=username)

#logs user out
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#check email is the route for verifying a persons email is on the whitelist and emailing them code
@app.route('/check_email', methods=['GET', 'POST'])
def check_email():
    if request.method == 'POST':
        #get input email
        email = request.form['email'].strip().lower()
        #connect to DB and scan whitelist, making a new code if on whitelist and no user already exists with that email
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("You're not on the whitelist. Think you should be? <a href='mailto:jbellizia29@gmail.com?subject=Sponge%20Me&body=Write%20your%20favorite%20thing%20about%20me%20here:'>Email me!</a>", 'check_email')
                return redirect(url_for('check_email'))

            cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
            if cur.fetchone():
                flash("You already have an account.", 'check_email')
                return redirect(url_for('check_email'))

            code = secrets.token_urlsafe(8)
            cur.execute('REPLACE INTO pending_codes (email, code) VALUES (?, ?)', (email, code))
            conn.commit()

        #email token
        msg = Message('Your One-Time Registration Code for Sponge', recipients=[email])
        msg.body = f"Use this code to register: {code}"
        mail.send(msg)
        log_email(conn, email, 'Your One-Time Registration Code for Sponge', f"Use this code to register: {code}")
        print(f"Sent code to: {email}")
        
        #redirect to register page
        flash_message = 'A registration code was sent to ' + email
        flash(flash_message, 'register')
        return redirect(url_for('register', email=email))

    else:
        return render_template('check_email.html')

#app route for registration (credentials) page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        
        #get form info
        email = request.form['email'].strip().lower()
        code = request.form['code'].strip()
        username = request.form['username'].strip().lower()
        password = request.form['password']
        
        #connect to database
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute('SELECT code FROM pending_codes WHERE email = ?', (email,))
            row = cur.fetchone()
             
            #check for expired code
            if not row or row[0] != code:
                flash('Invalid or expired code.', 'register')
                return redirect(url_for('register'))
            
            
            #check for username already in use
            cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            if cur.fetchone():
                flash("This username is already in use", 'register')
                return redirect(url_for('register'))
            
            #check if username is valid
            
            if not is_valid_username(username):
                flash("Username can only contain letters, numbers, underscores, and hyphens.", "register")
                return redirect(url_for('register'))
            
            
            #check if username is too long
            if len(username) >= 50:
                flash("Username too long.", "register")
                return redirect(url_for('register'))
            
            #check for email already in use or wrong email
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("The email you entered is not on the whitelist.", 'register')
                return redirect(url_for('register'))
            
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
            if cur.fetchone():
                flash("This email is already in use", 'register')
                return redirect(url_for('register'))
            
            #password must be 8 characters
            if len(password) < 8:
                flash("Lengthen your password, fool. 8 characters MINIMUM.", 'register')
                return redirect(url_for('register'))
            
            #make and insert default bio
            today = date.today()
            bio = username + " has been soaking it up since " + today.strftime("%m %d %Y")
            
            #hash password and insert all into database
            password_hash = generate_password_hash(password)
            cur.execute('INSERT INTO users (email, password_hash, username, bio) VALUES (?, ?, ?, ?)',
                        (email, password_hash, username, bio))
            cur.execute('DELETE FROM pending_codes WHERE email = ?', (email,))
            conn.commit()
        #notify user of registration, redirect to login
        flash('Account created successfully! You can now log in.', 'register')
        return redirect(url_for('login', username=username))
    email = request.args.get('email', '')
    return render_template('register.html', email=email)


#for uploading a post 
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        #get uploaded stuff
        caption = request.form['caption'].strip()
        file = request.files.get('upload-image')
        
        #check for null post
        if (not caption and not file):
            flash("Your post must include either an image or a caption.", "upload")
            return redirect(url_for('upload'))

        #check file, assign filename, get filepath, rotate if weird iphone rotation true, compress, save to server. assisted by chat here heavy
        filename = None
        if file and allowed_file(file.filename):
            ext = os.path.splitext(file.filename)[1]
            filename = secure_filename(f"{uuid.uuid4().hex}{ext}")
            upload_path = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_path, exist_ok=True)
            filepath = os.path.join(upload_path, filename)
            try:
                image = Image.open(file)
                image = ImageOps.exif_transpose(image)
                image = image.convert("RGB")
                compressed_path = os.path.join(upload_path, filename)
                image.save(compressed_path, format='JPEG', optimize=True, quality=70)
                print("Saved file as:", compressed_path)
            except Exception as e:
                flash("Error saving file.", "upload")
                return redirect(url_for('upload'))

        #make new post in DB
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO posts (user_id, caption, image_filename, repost_id)
                VALUES (?, ?, ?, ?)
            """, (current_user.id, caption, filename, -1,))
            
            #get the id of the new post so that we can redirect to it 
            post_id = cur.lastrowid
            conn.commit()
            
        # Notify mentioned users
        mentioned_users = extract_mentions(caption)
        #loop through mentioned users
        for user in mentioned_users:
            #dont notify self
            if user.username == get_username_by_id(current_user.id):
                continue
            #check enabled email notifs, then email
            if user.notifications_enabled:
                msg = Message('Mentioned in a Post', recipients=[user.email])
                msg.body = f"You were mentioned in a post by {current_user.username}: {url_for('view_post', id=post_id, _external=True)}"
                try:
                    mail.send(msg)
                    log_email(conn, user.email, 'Mentioned in a Post', f"You were mentioned in a post by {current_user.username}: {url_for('view_post', id=post_id, _external=True)}")
                
                except Exception as e:
                    print(f"Failed to send email to {user.email}: {e}")
            #log notif so they get it on sponge even if email notifs off    
            insert_notification(
                conn, 
                recipient_id=user.id,
                actor_id=current_user.id,
                post_id=post_id,
                notif_type=NotificationType.MENTION
            )    
        flash('Post created!', "upload")
        return redirect(url_for('view_post', id=post_id))

    return render_template('upload.html')


#for viewing a users profile
@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profile(username):
    session['last_safe_url'] = request.url #for edit post deletion safety

    with get_db_connection() as conn:
        cur = conn.cursor()
        
        # Get user info
        cur.execute("SELECT id, bio, profile_pic_filename, notifications_enabled FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        
        if not user:
            abort(404)  # User doesn't exist
        
        #unpack user. made before get_user_by_username existed, will prob upgrade this eventually but essentially the same
        user_id, bio, profile_pic, notifications_enabled = user

        # Get user's posts
        cur.execute("""
            SELECT id, caption, image_filename, timestamp, repost_id,
            
            (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS likes,

            EXISTS (
                SELECT 1 FROM likes 
                WHERE likes.post_id = posts.id 
                AND likes.user_id = ?
            ) AS liked,
            
            (SELECT COUNT(*) FROM posts AS p2 WHERE p2.repost_id = posts.id) AS repost_count,
            (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) AS comment_count


            FROM posts
            WHERE user_id = ?
            AND id != -1
            ORDER BY timestamp DESC
        """, (current_user.id, user_id,))
        
        posts = cur.fetchall()
    #pass allat to profile and display that boy
    return render_template("profile.html",
                           username=username,
                           bio=bio,
                           profile_pic_filename=profile_pic,
                           posts=posts,
                           user_id=user_id,
                           is_following=is_following,
                           get_user_by_id=get_user_by_id,
                           get_post_by_id=get_post_by_id)


#for viewing an individual post and commenting
@app.route('/view_post/<int:id>', methods=['GET', 'POST'])
@login_required
def view_post(id):

    with get_db_connection() as conn:
        cur = conn.cursor()
        
        # Get post info from DB
        post = get_post_by_id(id)
        post_user = get_user_by_id(post.user_id)
        
        if request.method == 'POST': #means there was a comment made
            
            #get comment info
            comment_text = request.form.get('comment_text', '').strip()
            post_id = id
            user_id = current_user.id
            
            #check for null comment
            if not comment_text:
                flash('Comment cannot be empty.', 'view_post')
                return redirect(url_for('view_post', id=id))
            
            #add comment to DB
            cur.execute("""
                INSERT INTO comments (user_id, post_id, comment_text)
                VALUES (?, ?, ?)
            """, (user_id, post_id, comment_text))
            comment_id = cur.lastrowid 
            conn.commit()
        
        
            #get tagged users and notify them
            mentioned_users = extract_mentions(comment_text)
        
            for user in mentioned_users:
                #skip notifying self for mentioning self, idk why youd do that but 
                if user.id == current_user.id:
                    continue
                #if notifs enabled, email them and log it
                if user.notifications_enabled:
                    msg = Message('Mentioned in a Comment', recipients=[user.email])
                    msg.body = (f"You were mentioned in a comment by {get_username_by_id(current_user.id)}!\n\n"
                                f"Check it out here: {url_for('view_post', id=post_id, _external=True)}")
                    try:
                        mail.send(msg)
                        log_email(conn, user.email, 'Mentioned in a Comment', f"You were mentioned in a comment by {get_username_by_id(current_user.id)}: \n\n {comment_text}\n\nCheck it out here: {url_for('view_post', id=post_id, _external=True)}")
                        
                    except Exception as e:
                        print(f"Failed to send email to {user.email}: {e}")
                #insert notif    
                insert_notification(
                    conn, 
                    recipient_id=user.id,
                    actor_id=current_user.id,
                    post_id=post_id,
                    comment_id=comment_id,
                    notif_type=NotificationType.MENTION_IN_COMMENT
                )        
            
            #get all the mentioned usernames to avoid notifying twice if someone commented on another persons post and mentioned them
            mentioned_usernames = [user.username.lower() for user in mentioned_users]        #cred to chat this line
            #if the user wasnt mentioned in the comment on their post and they are not the one commenting, notify them
            if post_user.username not in mentioned_usernames and post_user.id != current_user.id:
                if post_user.notifications_enabled:
                    msg = Message('Peep the new comment on your post', recipients=[post_user.email])
                    msg.body = (f"{current_user.username} left a comment on your post!\n\n {comment_text}\n\n"
                                f"Check it out here: {url_for('view_post', id=post_id, _external=True)}")
                    
                    try:
                        mail.send(msg)
                        log_email(conn, post_user.email, 'Peep the new comment on your post', f"{current_user.username} left a comment on your post: \n\n {comment_text}\n\nCheck it out here: {url_for('view_post', id=post_id, _external=True)}")
                        
                    except Exception as e:
                        print(f"Failed to send email to {post_user.email}: {e}")
                #log notif regardless of email notifications enabled    
                insert_notification(
                    conn, 
                    recipient_id=post_user.id,
                    actor_id=current_user.id,
                    post_id=post_id,
                    comment_id=comment_id,
                    notif_type=NotificationType.COMMENT
                )
        
            flash('Comment created!', "view_post")
            return redirect(url_for('view_post', id=post_id) + "#comments")
        
        #get info about post likes, reposts and comments for display
        cur.execute("""
            SELECT 
                (SELECT COUNT(*) FROM likes WHERE likes.post_id = ?) AS likes,
                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE likes.post_id = ? AND likes.user_id = ?
                ) AS liked,
                (SELECT COUNT(*) FROM posts WHERE posts.repost_id = ?) AS repost_count,
                (SELECT COUNT(*) FROM comments WHERE comments.post_id = ?) AS comment_count


        """, (id, id, current_user.id, id, id,))
        #unpack
        likes, liked, repost_count, comment_count= cur.fetchone()
        
        #get all comments from post and the users attached
        cur.execute("""
            SELECT
                comments.id,
                comments.user_id, 
                users.username, 
                users.profile_pic_filename,
                comments.comment_text, 
                comments.timestamp
            FROM comments
            JOIN users ON comments.user_id = users.id
            WHERE comments.post_id = ?
            ORDER BY comments.timestamp ASC
        """, (id,))
        comments = cur.fetchall()
        
        if not post:
            abort(404)  # Post doesn't exist
           
        # cheeky use of -1 sentinel post for non reposts. prob need to change eventually to add is_repost field to post table
        #basically, if there is a post and its a repost, get the repost and repost user, else none
        if post and post.repost_id != -1:
            repost = get_post_by_id(post.repost_id)
            if repost:
                repost_user = get_user_by_id(repost.user_id)
            else:
                repost_user = None
        else:
            repost = None
            repost_user = None
            
        
        
    #pass that baby
    return render_template("post.html",
                           repost = repost,
                           repost_user=repost_user,
                           post=post,
                           post_user = post_user,
                           comments=comments,
                           get_username_by_id = get_username_by_id,
                           get_user_by_id=get_user_by_id,
                           likes=likes,
                           liked=liked,
                           repost_count=repost_count,
                           comment_count=comment_count)


#for viewing users own page, personal fav route
@app.route('/myprofile')
@login_required
def myprofile():
    username = get_username_by_id(current_user.id)
    return redirect(url_for('profile', username=username))

#for settings changes
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    with get_db_connection() as conn:
        cur = conn.cursor()

        if request.method == 'POST':
            #for making sure something actually happened when they clicked save changes
            changes_made = False
            
            cur.execute("SELECT profile_pic_filename FROM users WHERE id = ?", (current_user.id,))
            row = cur.fetchone()
            old_pic_filename = row[0]

            #get form values for profile pic
            default_pic = 'default_profile_pictures/default.png'
            remove_pic = request.form.get("remove_profile_pic")
            file = request.files.get('profile-pic')

            new_pic_filename = None  
            
            #alert if type not allowed
            if file and not allowed_file(file.filename):
                flash('Filetype not supported. Use .png, .jpg, .jpeg, or .gif','settings')
            
            #if upload is chill, update users info to have new filename
            elif file and allowed_file(file.filename):
                ext = os.path.splitext(file.filename)[1]
                filename = secure_filename(f"{uuid.uuid4().hex}{ext}") 
                upload_path = app.config['PROFILE_PIC_FOLDER']
                os.makedirs(upload_path, exist_ok=True)
                filepath = os.path.join(upload_path, filename)

                try:
                    
                    image = Image.open(file)
                    image = ImageOps.exif_transpose(image)
                    image = image.convert("RGB")
                    image.save(filepath, format='JPEG', optimize=True, quality=70)
                    cur.execute("UPDATE users SET profile_pic_filename = ? WHERE id = ?", (filename, current_user.id))
                    new_pic_filename = filename
                    changes_made = True
                except Exception as e:
                    flash("Error saving profile picture.", "settings")
                    return redirect(url_for('settings'))
            #if they decided to remove their picture, try to remove the file and reassign to default pic. ignored if also uploading
            elif remove_pic and old_pic_filename != default_pic:
                try:
                    os.remove(os.path.join(app.config['PROFILE_PIC_FOLDER'], old_pic_filename))
                except FileNotFoundError:
                    pass
                cur.execute("UPDATE users SET profile_pic_filename = ? WHERE id = ?", (default_pic, current_user.id))
                changes_made = True
                old_pic_filename = default_pic  
            #rm old file
            if new_pic_filename and old_pic_filename != default_pic:
                try:
                    os.remove(os.path.join(app.config['PROFILE_PIC_FOLDER'], old_pic_filename))
                    print("Deleted old profile picture from server.")
                except FileNotFoundError:
                    pass

            
            # Update bio, username, email, notifications
            bio = request.form.get('bio', '').strip()
            username = request.form.get('username', '').strip().lower()
            email = request.form.get('email', '').strip().lower()
            notifications_enabled = 1 if request.form.get('notifications_enabled') else 0
            
            user = get_user_by_id(current_user.id)
            
            
            #check if newusername is valid
            
            if not is_valid_username(username):
                flash("Username can only contain letters, numbers, underscores, and hyphens.", "settings")
                return redirect(url_for('settings'))
            
            #check if username is too long
            if len(username) >= 50:
                flash("Username too long.", "register")
                return redirect(url_for('settings'))
            
            #if username in form is different from current user username, make sure another account is not using it
            if user.username != username:
                cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cur.fetchone():
                    flash("This username is already in use", 'settings')
                    return redirect(url_for('settings'))
                changes_made = True
            
            #check for email already in use or wrong email
            
            cur.execute('SELECT 1 FROM whitelist WHERE email = ?', (email,))
            if not cur.fetchone():
                flash("The email you entered is not on the whitelist.", 'settings')
                return redirect(url_for('settings'))
            
            
            #if email in form is different from current user email, make sure another account is not using it
            if user.email != email:
                cur.execute('SELECT 1 FROM users WHERE email = ?', (email,))
                if cur.fetchone():
                    flash("This email is already in use", 'settings')
                    return redirect(url_for('settings'))
                changes_made = True
            
            
            # Check if bio changed
            if (user.bio or '') != bio:
                changes_made = True

            # Check if notification setting changed
            if user.notifications_enabled != notifications_enabled:
                changes_made = True

            # If changes were made, update the DB
            if changes_made:
                cur.execute("""
                    UPDATE users
                    SET bio = ?, username = ?, email = ?, notifications_enabled = ?
                    WHERE id = ?
                """, (bio, username, email, notifications_enabled, current_user.id))
                conn.commit()
                flash("Settings updated successfully.", category="settings")
            return redirect(url_for('settings'))

        #fetch current user info
        cur.execute("SELECT username, email, bio, profile_pic_filename, notifications_enabled FROM users WHERE id = ?", (current_user.id,))
        user = cur.fetchone()
        if not user:
            flash("User not found.", category="settings")
            return redirect(url_for('home'))

        username, email, bio, profile_pic_filename, notifications_enabled = user

    return render_template(
        'settings.html',
        username=username,
        email=email,
        bio=bio,
        profile_pic_filename=profile_pic_filename,
        notifications_enabled=bool(notifications_enabled)
    )
    
#settings embedded route
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    with get_db_connection() as conn:
        cur = conn.cursor()
        #form 
        if request.method == 'POST':
            #get old password from form and check it
            old_password = request.form['old_password']
            
            user = get_user_by_id(current_user.id)
            if not user or not check_password_hash(user.password, old_password):
                flash("Incorrect password", 'change_password')
                return redirect(url_for('change_password'))

            #get new password and confirmation and check
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            if new_password != confirm_new_password:
                flash("Passwords do not match.", "change_password")
                return redirect(url_for('change_password'))
            
            #check valid password
            if len(new_password) < 8:
                flash("Lengthen your password. 8 characters MINIMUM.", 'change_password')
                return redirect(url_for('change_password'))
            #update password in DB
            password_hash = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, current_user.id))
            conn.commit()
            flash("Password changed successfully.", "change_password")
            return redirect(url_for('change_password'))
    return render_template("change_password.html")
 
#edit post route
@app.route('/view_post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        # Get post info
        cur.execute("""
            SELECT id, user_id, caption, image_filename, timestamp
            FROM posts
            WHERE id = ?
        """, (post_id,))
        result = cur.fetchone()

        if not result:
            abort(404) #post doesnt exist

        post_id_db, user_id, caption, image_filename, timestamp = result
        
        #check user
        if user_id != current_user.id:
            flash('You are not authorized to edit this post.')
            return redirect(url_for('home'))
    
        if request.method == 'POST':
            #if delete, delete post and redirect to last safe url (not editpost or viewpost)
            if 'delete' in request.form:
                if image_filename:
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                    try:
                        os.remove(filepath)
                    except Exception as e:
                        print(f"File delete error: {e}")

                cur.execute('DELETE FROM posts WHERE id = ?', (post_id,))
                conn.commit()
                flash('Post deleted.')
                

                return redirect(session.get('last_safe_url') or url_for('profile', username=get_username_by_id(current_user.id)))

            # Update caption
            new_caption = request.form.get('caption')
            cur.execute('UPDATE posts SET caption = ? WHERE id = ?', (new_caption, post_id))
            
            
            #get tagged users and notify them
            mentioned_users = extract_mentions(new_caption)
        
            for user in mentioned_users:
                # Skip notifying self for mentioning self
                if user.id == current_user.id:
                    continue
                if user.notifications_enabled:
                    msg = Message('Mentioned in a post', recipients=[user.email])
                    msg.body = (f"You were mentioned in a post by {get_username_by_id(current_user.id)}!\n\n"
                                f"Check it out here: {url_for('view_post', id=post_id, _external=True)}")
                    try:
                        mail.send(msg)
                        log_email(conn, user.email, 'Mentioned in a post', f"You were mentioned in a post by {get_username_by_id(current_user.id)}!\n\nCheck it out here: {url_for('view_post', id=post_id, _external=True)}")
                        
                    except Exception as e:
                        print(f"Failed to send email to {user.email}: {e}")
                insert_notification(
                    conn, 
                    recipient_id=user.id,
                    actor_id=current_user.id,
                    post_id=post_id,
                    notif_type=NotificationType.MENTION
                )                    
            conn.commit()
            flash('Post updated.')
            return redirect(url_for('view_post', id=post_id))

    # Only pass what you need to the template
    post_data = {
        'id': post_id_db,
        'user_id': user_id,
        'caption': caption,
        'image_filename': image_filename,
        'timestamp': timestamp,
    }

    return render_template('edit_post.html', post=post_data)

#route that shows all users on Sponge
@app.route('/users', methods=['GET'])
@login_required
def users():
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        #get all users info and pass to users.html
        cur.execute("""
            SELECT id, username, profile_pic_filename
            FROM users
            ORDER BY username
        """)
        users = cur.fetchall()
        
        return render_template('users.html', users=users, is_following=is_following)

#toggles current user following given user    
@app.route('/toggle_follow', methods=['POST'])
@login_required
def toggle_follow():
    # get follower/following ids
    follower_id = current_user.id
    followed_id = request.form['followed_id']

    # see if curr user follows the other user
    following_user = is_following(follower_id, followed_id)

    #connect to db
    with get_db_connection() as conn:
        cur = conn.cursor()
        #if curr is following other user, unfollow (delete row in db) else make new row
        if following_user:
            cur.execute("DELETE FROM follows WHERE follower_id = ? AND followed_id = ?", (follower_id, followed_id))
        else:
            cur.execute("INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)", (follower_id, followed_id))
            
            user = get_user_by_id(followed_id)
            username_of_follower = get_username_by_id(follower_id)
            if user.notifications_enabled:
                msg = Message('New follower', recipients=[user.email])
                msg.body = (f"{username_of_follower} just followed you!\n\n"
                            f"Check out their profile here: {url_for('profile', username=username_of_follower, _external=True)}")
                try:
                    mail.send(msg)

                    log_email(conn, user.email, 'New follower',
                        f"{username_of_follower} just followed you!\n\n"
                            f"Check out their profile here: {url_for('profile', username=username_of_follower, _external=True)}"
                    )

                except Exception as e:
                    print(f"Failed to send email to {user.email}: {e}")
            
            insert_notification(
                conn, 
                recipient_id=followed_id, 
                actor_id=follower_id,     
                notif_type=NotificationType.FOLLOW
            )

        conn.commit()
        
    return redirect(request.referrer or url_for('home'))
     
#route for followers of <username>
@app.route('/followers/<username>', methods=['GET'])
@login_required
def followers(username):
    #get relevant user id
    user_id = get_id_by_username(username)
    #connect to DB
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        #get all users that follow user
        cur.execute("""
            SELECT users.id, users.username, users.profile_pic_filename
            FROM follows
            JOIN users ON follows.follower_id = users.id
            WHERE follows.followed_id = ?;

        """, (user_id,))
        
        users = cur.fetchall()
        
        #render html and pass info
        return render_template('followers.html', username=username, users=users, is_following=is_following)

#route for who <username> is following
@app.route('/following/<username>', methods=['GET'])
@login_required
def following(username):
    #get the relevant user id
    user_id = get_id_by_username(username)
    
    #connect to DB
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        # select all the users information that follow the given user
        cur.execute("""
            SELECT users.id, users.username, users.profile_pic_filename
            FROM follows
            JOIN users ON follows.followed_id = users.id
            WHERE follows.follower_id = ?;
        """, (user_id,))
        users = cur.fetchall()
        
        #render html and pass info
        return render_template('following.html', username=username, users=users, is_following=is_following)

#making a new responge
@app.route('/responge/<int:post_id>', methods=['GET', 'POST'])
@login_required
def responge(post_id):
    if request.method == 'POST':
        #get caption and image file
        caption = request.form['caption'].strip()
        file = request.files.get('image')

        #save file if allowed
        filename = None
        if file and allowed_file(file.filename):
            ext = os.path.splitext(file.filename)[1]
            filename = secure_filename(f"{uuid.uuid4().hex}{ext}")
            upload_path = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_path, exist_ok=True)
            filepath = os.path.join(upload_path, filename)
            try:
                image = Image.open(file)
                image = image.convert("RGB")
                compressed_path = os.path.join(upload_path, filename)  
                image.save(compressed_path, format='JPEG', optimize=True, quality=70)
                print("Saved responge file as:", compressed_path)
            except Exception as e:
                flash("Error saving file.", "responge")
                return redirect(url_for('responge', post_id=post_id))

        #insert into DB
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO posts (user_id, caption, image_filename, repost_id)
                VALUES (?, ?, ?, ?)
            """, (current_user.id, caption, filename, post_id))
            
            #get the id of the new repost so that we can redirect to it 
            repost_id = cur.lastrowid
            
            conn.commit()
            
            
        #get tagged users and notify them
        mentioned_users = extract_mentions(caption)
    
        for user in mentioned_users:
            # Skip notifying self for mentioning self
            if user.id == current_user.id:
                continue
            if user.notifications_enabled:
                msg = Message('Mentioned in a Responge', recipients=[user.email])
                msg.body = (f"You were mentioned in a responge by {get_username_by_id(current_user.id)}!\n\n"
                            f"Check it out here: {url_for('view_post', id=repost_id, _external=True)}")
                try:
                    mail.send(msg)
                    log_email(conn, user.email, 'Mentioned in a Responge',
                        f"You were mentioned in a responge by {get_username_by_id(current_user.id)}:\n\n"
                        f"{caption}\n\nCheck it out here: {url_for('view_post', id=repost_id, _external=True)}"
                    )
                    
                except Exception as e:
                    print(f"Failed to send email to {user.email}: {e}")
            insert_notification(
                conn, 
                recipient_id=user.id,
                actor_id=current_user.id,
                post_id=post_id,
                notif_type=NotificationType.MENTION
            )    
                    
        post_user = get_user_by_post_id(post_id)
        mentioned_usernames = [user.username.lower() for user in mentioned_users]        
        #notifying when someone responges your post
        if post_user.username not in mentioned_usernames  and post_user and post_user.username != get_username_by_id(current_user.id):
            if post_user.notifications_enabled:
                msg = Message('Responge town population you', recipients=[post_user.email])
                msg.body = (f"{get_username_by_id(current_user.id)} responged your jawn!\n\n"
                            f"Check it out here: {url_for('view_post', id=repost_id, _external=True)}")
                try:
                    mail.send(msg)
                    log_email(conn, post_user.email, 'Responge town population you', f"{get_username_by_id(current_user.id)} responged your jawn!\n\nCheck it out here: {url_for('view_post', id=repost_id, _external=True)}")
                    
                except Exception as e:
                    print(f"Failed to send email to {post_user.email}: {e}")
            insert_notification(
                conn, 
                recipient_id=post_user.id,
                actor_id=current_user.id,
                post_id=post_id,
                notif_type=NotificationType.RESPONGE
            )


        
        flash('Post created!', "view_post")
        return redirect(url_for('view_post', id=repost_id))
    
    #if get, render responge.html
    return render_template('responge.html', post=get_post_by_id(post_id), get_username_by_id=get_username_by_id, get_user_by_id=get_user_by_id)

@app.route('/toggle_like/<int:post_id>', methods=['POST'])
@login_required
def toggle_like(post_id):
    # get liker id and post info
    user_id = current_user.id
    post = get_post_by_id(post_id)
    
    if not post:
        abort(404)
    #connect to db
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (user_id, post_id))
        liked_id = cur.fetchone()
        #if there is liked post, unlike (delete row in db) else make new row
        if liked_id:
            cur.execute("DELETE FROM likes WHERE user_id = ? AND post_id = ?", (user_id, post_id))
            user_liked = False
        else:
            user_liked = True
            cur.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", (user_id, post_id))
        #get likes count
        conn.commit()
        cur.execute("SELECT COUNT(id) FROM likes WHERE  post_id = ?", (post_id,))
        likes_count = cur.fetchone()[0]
        
        post_user = get_user_by_post_id(post_id)
        
        cur.execute("SELECT last_notified_likes FROM posts WHERE id = ?", (post_id,))
        row = cur.fetchone()
        last_notified_likes = row[0] if row else 0
        
        #notify for every interval of 5, change if thats too much
        if user_liked and likes_count % 5 == 0 and likes_count > last_notified_likes and post_user:
            if post_user.notifications_enabled:
                msg = Message('Hella likes on your jawn', recipients=[post_user.email])
                msg.body = (f"Your sponge has {likes_count} likes!\n\n"
                            f"Check it out here: {url_for('view_post', id=post_id, _external=True)}")
                try:
                    cur.execute("UPDATE posts SET last_notified_likes = ? WHERE id = ?", (likes_count, post_id))
                    conn.commit()
                    mail.send(msg)
                    log_email(conn, post_user.email, 'Hella likes on your jawn', f"Your sponge has {likes_count} likes!\n\nCheck it out here: {url_for('view_post', id=post_id, _external=True)}")
                    
                except Exception as e:
                    print(f"Failed to send email to {post_user.email}: {e}")
            insert_notification(
                conn, 
                recipient_id=post_user.id,
                post_id=post_id,
                notif_type=NotificationType.LIKE_MILESTONE
            )
    return jsonify({
        'success': True,
        'likes': likes_count,
        'liked': user_liked
    })

#for viewing who liked
@app.route('/post/<int:id>/likes', methods=['GET'])
@login_required
def view_likes(id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        #get all users info (who liked the post) and pass to users.html
        cur.execute("""
            SELECT users.id, users.username, users.profile_pic_filename
            FROM users
            JOIN likes ON users.id = likes.user_id
            WHERE likes.post_id = ?
            ORDER BY likes.timestamp;
        """, (id,))
        users = cur.fetchall()
        
        return render_template('users.html', users=users, is_following=is_following)
    
#for viewing who responged
@app.route('/post/<int:id>/responges', methods=['GET'])
@login_required
def view_responges(id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        #get all users info (who reposted the post) and pass to users.html
        cur.execute("""
            SELECT users.id, users.username, users.profile_pic_filename
            FROM users
            JOIN posts ON users.id = posts.user_id
            WHERE posts.repost_id = ?
            ORDER BY posts.timestamp;
        """, (id,))
        users = cur.fetchall()
        
        return render_template('users.html', users=users, is_following=is_following)
    
#for displaying notifs page (last 10 days)
@app.route('/notifications', methods=['GET'])
@login_required
def show_notifications():
    ten_days_ago = datetime.now() - timedelta(days=10)

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, user_id, from_user_id, post_id, comment_id, type, is_read, timestamp
            FROM notifications
            WHERE user_id = ? AND notifications.timestamp >= ?
            ORDER BY notifications.timestamp DESC;
        """, (current_user.id, ten_days_ago, ))
        notifs = cur.fetchall()
        
        
        return render_template('notifications.html',
                               notifs=[Notification(*notification) for notification in notifs],
                               get_username_by_id=get_username_by_id,
                               get_user_by_id=get_user_by_id)

#this route is triggered after loading the notifications page, marks all notifs as read and changes appearance once reloaded
@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE notifications SET is_read = 1 WHERE user_id = ?;
        """, (current_user.id,))
        conn.commit()
    return '', 204

#route for getting favicon, i dont think is needed but keeping
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.svg')

#for deleting a comment made by curruser
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        
        # Get comment info
        cur.execute("""
            SELECT id, user_id, post_id, comment_text, timestamp
            FROM comments
            WHERE id = ?
        """, (comment_id,))
        result = cur.fetchone()

        if not result:
            abort(404)

        id, user_id, post_id, comment_text, timestamp = result

        if user_id != current_user.id:
            flash('You are not authorized to delete this comment.')
            return redirect(url_for('view_post', post_id) or url_for('home'))

        if request.method == 'POST':
            if 'delete' in request.form:

                cur.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
                conn.commit()
                flash('Comment deleted.', 'view_post')
                
                return redirect(url_for('view_post', id=post_id) or url_for('home'))
            return redirect(url_for('view_post', id=post_id) or url_for('home'))
#this is for all the blog posts i make, kinda dumb but fun
@app.route('/updates', methods=['GET'])
@login_required
def updates():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT *
            FROM updates_log
            ORDER BY timestamp DESC
        """)
        updates = cur.fetchall()
        
        return render_template('updates.html',
                               updates=updates)
    
db_setup()
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
