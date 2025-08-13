CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE pending_codes (
                        email TEXT PRIMARY KEY,
                        code TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE "whitelist" (
	"id"	INTEGER,
	"name"	TEXT,
	"email"	TEXT UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "users" (
	"id"	INTEGER,
	"email"	TEXT,
	"password_hash"	TEXT,
	"username"	TEXT,
	"bio"	TEXT,
	"profile_pic_filename"	TEXT DEFAULT 'default_profile_pictures/default.png',
	"notifications_enabled"	INTEGER DEFAULT 1,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE follows (
    follower_id INTEGER NOT NULL,
    followed_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (follower_id, followed_id),
    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (followed_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE comments (
	id INTEGER,
	user_id INTEGER,
	post_id INTEGER,
	comment_text TEXT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(id AUTOINCREMENT),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
);
CREATE TABLE "posts" (
	"id"	INTEGER,
	"user_id"	INTEGER,
	"caption"	TEXT,
	"image_filename"	TEXT,
	"timestamp"	DATETIME DEFAULT CURRENT_TIMESTAMP,
	"repost_id"	INTEGER DEFAULT -1, last_notified_likes INTEGER DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT),
	FOREIGN KEY("repost_id") REFERENCES "posts"("id") ON DELETE SET NULL,
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE likes (
    id INTEGER,
    user_id INTEGER,
    post_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(id AUTOINCREMENT),
	FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
	FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
    UNIQUE(user_id, post_id) 
);

CREATE TABLE email_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT,
    subject TEXT,
    body TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE notifications (
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
        'resplooge',
		'mention_in_comment'
    )),
    
    is_read BOOLEAN NOT NULL DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id) REFERENCES "users"(id) ON DELETE CASCADE,
    FOREIGN KEY(from_user_id) REFERENCES "users"(id) ON DELETE SET NULL,
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY(comment_id) REFERENCES comments(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO users (id, email, password_hash, username, bio)
    VALUES (-1, 'system@example.com', '', 'System', 'System placeholder user');


INSERT OR IGNORE INTO posts (id, user_id, caption, image_filename, repost_id)
    VALUES (-1, -1, 'Sentinel post', '', NULL);