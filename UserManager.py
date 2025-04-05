import os
import json

groups = {}

def initModule():
    global groups
    groups = {}
    if not os.path.exists("./usermanager/"):
        os.makedirs("./usermanager")
        getGroup("default")
        getGroup("default").addUser("admin", "admin")
        getGroup("default").addUser("admin2", "admin2")

def getGroup(groupname):
    if not groupname in groups:
        groups[groupname] = UserGroup(groupname)
    return groups[groupname]


class UserGroup:
    def __init__(self, groupname):
        self.groupname = groupname
        self.users = {}
        self.grouppath = f"./usermanager/{groupname}"
        self.load()

    def load(self):
        if not os.path.exists(f"{self.grouppath}/group.json"):
            if not os.path.exists(self.grouppath):
                os.makedirs(self.grouppath)
            if not os.path.exists(f"{self.grouppath}/users"):
                os.makedirs(f"{self.grouppath}/users")
            
            # Create default group.json
            default_group = {
                "users": {},
                "bindDomains": ["localhost", "localhost.com", "127.0.0.1"]
            }

            with open(f"{self.grouppath}/group.json", 'w') as f:
                json.dump(default_group, f, indent=4)
        
        with open(f"{self.grouppath}/group.json", 'r') as f:
            js = json.load(f)
            self.users   = js["users"]
            self.domains = js["bindDomains"]

    def getDomains(self):
        return self.domains
    
    def getErrorMailFrom(self):
        return "noreply@"+self.domains[0]+".com"

    def save(self):
        with open(f"{self.grouppath}/group.json", 'w') as f:
            json.dump({"users": self.users, "bindDomains": self.domains}, f, indent=4)

    def check(self, username, password):
        username = self.turnToUserName(username)
        if username in self.users:
            return self.users[username]["password"] == password
        return False

    def isIn(self, email):
        username = self.turnToUserName(email)
        return username in self.users
    
    def getDomain(self, email):
        return email.split('@')[1] if '@' in email else ''

    def addUser(self, username, password, permissions=None):
        if permissions is None:
            permissions = ["receive", "send"]
        
        user_path = f"{self.grouppath}/users/{username}"
        if not os.path.exists(user_path):
            os.makedirs(user_path)

        self.users[username] = {
            "password": password,
            "permissions": permissions,
            "path": user_path
        }
        self.save()
        return True

    def removeUser(self, username):
        username = self.turnToUserName(username)
        if username in self.users:
            del self.users[username]
            self.save()
            return True
        return False

    def getUserPath(self, username):
        username = self.turnToUserName(username)
        if username in self.users:
            return self.users[username]["path"]
        return None

    def getUserPermissions(self, username):
        username = self.turnToUserName(username)
        if username in self.users:
            return self.users[username]["permissions"]
        return None
    
    def turnToUserName(self, email):
        return email.split('@')[0]