
import os

file = None

def checkLog():
    if not os.path.isdir("./logs"):
        os.mkdir("./logs")


def init():
    global file
    checkLog()
    if os.path.exists("./logs/wmailserver.log"):
        file = open("./logs/wmailserver.log", 'a', encoding='utf-8')
    else:
        file = open("./logs/wmailserver.log", 'w', encoding='utf-8')

def write(*args):
    if not file:
        init()
    if len(args):
        file.write(" ".join(list(args))+"\n")
        print(*args)
    save()
def save():
    file.close()
    init()