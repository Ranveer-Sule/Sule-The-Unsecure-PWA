import sqlite3 as sql
import time
import random
import bcrypt

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    )
    stored_hashed_password = cur.fetchone()
    if stored_hashed_password:
        hashed_value = stored_hashed_password[0]
        if isinstance(hashed_value, str):
            hashed_value = hashed_value.encode("utf-8")
        hashed_password = bcrypt.checkpw(password.encode("utf-8"), hashed_value)
    else:
        hashed_password = False
    con.close()
    if hashed_password:
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))        
        return True
    else:        return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(f"INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT feedback FROM feedback").fetchall()
    con.close()
    return [row[0] for row in data]
