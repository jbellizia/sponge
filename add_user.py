#super simple python file to add a user to the whitelist, just write name and then email as arguments when running

import sys
import sqlite3



DB_FILE = 'users.db'

def add_user(name, email):
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        
        cur.execute('INSERT INTO whitelist (name, email) VALUES (?, ?)', (name, email,))
        conn.commit()
        print("Entered data: \n name: " + name + "\nemail = " + email)
if __name__ == "__main__":
    add_user(sys.argv[1], sys.argv[2])
        