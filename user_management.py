import sqlite3 as sql
import time
import random
import bcrypt

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    salt = b"$2b$12$ieYNkQp8QumgedUo30nuPO"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt=salt)
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    salt = b"$2b$12$ieYNkQp8QumgedUo30nuPO"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt=salt)
    cur.execute(
        "SELECT username, password FROM users WHERE username = ? AND password = ?", (username, hashed_password)
    )
    data = cur.fetchone()
    con.close()
    if data:
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
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
