
# Sponge

Sponge is a private, whitelisted social server where users can post, comment, follow, and interact with each other. Built with Python + Flask + Jinja2 and designed for small friend groups, it includes authentication, email verification, and an SQLite database.

## Features

- Whitelisted access — only approved users can join
- Posting & commenting
- Follow system
- Email verification via Flask-Mail
- HTML templates (Jinja2) and CSS included

---

## Requirements

Install dependencies from `requirements.txt`:

```
Flask
Flask-Login
Flask-Mail
python-dotenv
Pillow
itsdangerous
Werkzeug
flask-limiter
```

Install with:

```bash
pip install -r requirements.txt
```

> Tip: Use a virtual environment (`python -m venv venv && source venv/bin/activate` on macOS/Linux or `venv\Scripts\activate` on Windows) before installing.

---

## Setup

### 1) Clone the repository

```bash
git clone https://github.com/yourusername/sponge.git
cd sponge
```

### 2) Create a `.env` file

Create a `.env` file in the project root:

```
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
SECRET_KEY=your_secret_key
DATABASE_PATH=users.db
```

Use a strong, random value for `SECRET_KEY`.

### 3) Database initialization

An empty `users.db` is included in the repository, and `app.py` contains initialization logic to ensure required tables exist.

Add whitelisted users with:

```bash
python add_user.py "Full Name" "email@example.com"
```

---

## Running Locally

Start the development server:

```bash
python app.py
```

By default, the app runs on port 5000. Visit:

```
http://<your-local-ip>:5000
```

Example:

```
http://127.0.0.1:5000
```

If you’re running on another device (e.g., Raspberry Pi) on your network, use that device’s IP with `:5000`.

---

## Production (gunicorn + nginx)

Run gunicorn from the project directory:

```bash
gunicorn --bind 0.0.0.0:5000 app:app
```

Configure nginx to reverse proxy to `http://127.0.0.1:5000`. Ensure your environment variables are available to the gunicorn/nginx-managed process (e.g., via a systemd unit that loads the `.env` or exports the variables).

---

## Project Notes

- Templates live in `templates/`, static assets in `static/`.
- Routes, DB access, and whitelist checks are in `app.py`.
- Whitelisting is the only way to register new users; public signups are disabled.
- If `users.db` becomes corrupted or you want a fresh start, stop the server, remove `users.db`, and start the app again to allow re-initialization (you will need to re-whitelist users).

---

## Example User Flow

1. Admin runs `add_user.py` to whitelist a friend’s name and email.
2. The friend visits Sponge and signs up using that email.
3. They receive a verification email via Flask-Mail.
4. Once verified, they can post, comment, and follow.

---

## License

MIT License. You may modify and share; please credit the original project.
