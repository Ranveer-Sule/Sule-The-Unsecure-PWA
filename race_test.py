import threading
import user_management as db

# Make a test account and reset the counter to 0
db.insertUser("racetest", "Password1!", "2000-01-01")
open("visitor_log.txt", "w").write("0")

# Log in 50 times all at once
def login():
    db.retrieveUsers("racetest", "Password1!")

threads = [threading.Thread(target=login) for _ in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Should print 50 if the race condition is fixed
print("Counter:", open("visitor_log.txt").read().strip(), "(expected 50)")

db.deleteUser("racetest")
