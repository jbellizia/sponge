#this code just runs in the terminal and logs updates i make, just a helper so i dont have to manually insert every time


import sqlite3
from dotenv import load_dotenv
from app import get_db_connection
import os
from datetime import date, datetime, timedelta


load_dotenv()

DB_FILE =  os.getenv("DATABASE_PATH", "users.db")
if __name__ == "__main__":
    with get_db_connection() as conn:
        cur = conn.cursor()
        header = input("Update header: ")
        body = input("Update body: ")
        timestamp = datetime.now()
        
        with open("updates_log.txt", "a") as uf:
            uf.write(header + "\n\n" + body + "\n\n" + str(timestamp) + "\n\n")
            
        cur.execute("""
            INSERT INTO updates_log (header, body)
            VALUES (?, ?)
            """, (header, body, ))
        conn.commit()
        
        
