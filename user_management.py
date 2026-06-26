import sqlite3 as sql
from cryptography.fernet import Fernet
import secrets, bcrypt, pyotp

with open('encryption.key', 'rb') as key_file:
    fernet = Fernet(key_file.read())

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    secret = pyotp.random_base32()  
    encrypted_secret = fernet.encrypt(secret.encode("utf-8")).decode("utf-8")
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth,secret) VALUES (?,?,?,?)",
        (username, hashed_password, DoB, encrypted_secret),
    )
    con.commit()
    con.close()
    return secret


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

def getUserSecret(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if row:
        return fernet.decrypt(row[0].encode("utf-8")).decode("utf-8")
    return None

def generateRecoveryCodes(username, count=8):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    plain_codes = []
    for _ in range(count):
        code = secrets.token_hex(8)  # Generate a random 8-character hexadecimal code
        plain_codes.append(code)
        code_hash = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt())
        cur.execute(
            "INSERT INTO recovery_codes (username, code_hash, used) VALUES (?, ?, 0)",
            (username, code_hash),
        )
    con.commit()
    con.close()
    return plain_codes

def useRecoveryCode(username, code):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT id, code_hash FROM recovery_codes WHERE username = ? AND used = 0",
        (username,),
    )

    rows = cur.fetchall()
    for row_id, code_hash in rows:
        if isinstance(code_hash, str):
            code_hash = code_hash.encode("utf-8")
        if bcrypt.checkpw(code.encode("utf-8"), code_hash):
            cur.execute(
                "UPDATE recovery_codes SET used = 1 WHERE id = ?", (row_id,)
            )
            con.commit()
            con.close()
            return True
    con.close()
    return False

def getUserData(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT id, username, dateOfBirth FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row

def deleteUser(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    cur.execute("DELETE FROM recovery_codes WHERE username = ?", (username,))
    con.commit()
    con.close()
