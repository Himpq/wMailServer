import socket
import threading
import os
import json
import base64
import UserManager

loginfo = None
conf = None

POP3Ctxs = {
    "greeting": "POP3 Server Ready",
    "capabilities": [
        "USER",         # 支持用户名/密码认证
        "UIDL",        # 支持唯一标识符
        "TOP",         # 支持获取邮件头和指定行数
        "RESP-CODES",  # 支持响应代码
        "PIPELINING",  # 支持命令管道
        "UTF8"         # 支持UTF8编码
    ]
}

def initModule(log, cfg):
    global loginfo, conf
    loginfo = log
    conf = cfg

def handle_capa(conn, state):
    conn.send("+OK Capability list follows\r\n".encode())
    for cap in POP3Ctxs.get('capabilities'):
        conn.send(f"{cap}\r\n".encode())
    conn.send(".\r\n".encode())

def handle_uidl(conn, cmds, tempData):
    mailList = tempData['mailList']
    if len(cmds) == 1:
        conn.send(f"+OK {len(mailList)} messages\r\n".encode())
        for i, mail in enumerate(mailList, 1):
            conn.send(f"{i} {mail['id']}\r\n".encode())
        conn.send(".\r\n".encode())
    else:
        try:
            msgNum = int(cmds[1]) - 1
            if 0 <= msgNum < len(mailList):
                conn.send(f"+OK {msgNum + 1} {mailList[msgNum]['id']}\r\n".encode())
            else:
                loginfo.write(f"[{conn.getpeername()}][POP3] UIDL error: No message{msgNum+1}")
                conn.send("-ERR No such message\r\n".encode())
        except ValueError:
            loginfo.write(f"[{conn.getpeername()}][POP3] UIDL error: Invalid message number")
            conn.send("-ERR Invalid message number\r\n".encode())

def handle_user(conn, cmds, tempData):
    if len(cmds) >= 2:
        username = cmds[1]
        tempData['username'] = username

        loginfo.write(f"[{conn.getpeername()}][POP3] USER: {username}")
        conn.send("+OK User accepted\r\n".encode())
    else:
        loginfo.write(f"[{conn.getpeername()}][POP3] USER error: Syntax error")
        conn.send("-ERR Syntax error\r\n".encode())

def handle_pass(conn, cmds, tempData, userGroup):
    if 'username' not in tempData:
        loginfo.write(f"[{conn.getpeername()}][POP3] PASS error: No username provided")
        conn.send("-ERR Need username first\r\n".encode())
        return "AUTHORIZATION"

    if len(cmds) >= 2:
        password = cmds[1]
        if userGroup.check(tempData['username'], password):
            mailPath = userGroup.getUserPath(tempData['username'])
            tempData['mailpath'] = mailPath
            tempData['mailList'] = list_mails(mailPath)
            loginfo.write(f"[{conn.getpeername()}][POP3] Auth suc: {tempData['username']}")
            conn.send("+OK Logged in\r\n".encode())
            return "TRANSACTION"
        else:
            loginfo.write(f"[{conn.getpeername()}][POP3] Auth failed: {tempData['username']}")
            conn.send("-ERR Invalid login\r\n".encode())
    else:
        loginfo.write(f"[{conn.getpeername()}][POP3] PASS error: Syntax error")
        conn.send("-ERR Syntax error\r\n".encode())
    return "AUTHORIZATION"

def handle_stat(conn, tempData):
    mailList = tempData['mailList']
    totalSize = sum(mail['size'] for mail in mailList)
    conn.send(f"+OK {len(mailList)} {totalSize}\r\n".encode())
    loginfo.write(f"[{conn.getpeername()}][POP3] STAT: num={len(mailList)}, size={totalSize}")

def handle_list(conn, cmds, tempData):
    mailList = tempData['mailList']
    if len(cmds) == 1:
        conn.send(f"+OK {len(mailList)} messages\r\n".encode())
        for i, mail in enumerate(mailList, 1):
            conn.send(f"{i} {mail['size']}\r\n".encode())
        conn.send(".\r\n".encode())
    else:
        try:
            msgNum = int(cmds[1]) - 1
            if 0 <= msgNum < len(mailList):
                conn.send(f"+OK {msgNum + 1} {mailList[msgNum]['size']}\r\n".encode())
            else:
                loginfo.write(f"[{conn.getpeername()}][POP3] LIST error: No msg{msgNum+1}")
                conn.send("-ERR No such message\r\n".encode())
        except ValueError:
            loginfo.write(f"[{conn.getpeername()}][POP3] LIST error: Invalid message number")
            conn.send("-ERR Invalid message number\r\n".encode())

def handle_retr(conn, cmds, temp_data):
    if len(cmds) >= 2:
        try:
            mailList = temp_data['mailList']
            msg_num = int(cmds[1]) - 1
            if 0 <= msg_num < len(mailList):
                mail = mailList[msg_num]
                with open(os.path.join(mail['path'], 'content.txt'), 'r', encoding='utf-8') as f:
                    content = f.read()

                conn.send(f"+OK {mail['size']} octets\r\n".encode())

                for line in content.splitlines():
                    if line.startswith('.'):
                        line = '.' + line
                    conn.send(f"{line}\r\n".encode())
                conn.send(".\r\n".encode())
                
                loginfo.write(f"[{conn.getpeername()}][POP3] RETR: {msg_num+1}")
            else:
                loginfo.write(f"[{conn.getpeername()}][POP3] RETR error: No msg{msg_num+1}")
                conn.send("-ERR No such message\r\n".encode())
        except ValueError:
            loginfo.write(f"[{conn.getpeername()}][POP3] RETR error: Invalid message number")
            conn.send("-ERR Invalid message number\r\n".encode())
    else:
        loginfo.write(f"[{conn.getpeername()}][POP3] RETR error: Syntax error")
        conn.send("-ERR Syntax error\r\n".encode())

def handle_dele(conn, cmds, temp_data):
    if len(cmds) >= 2:
        try:
            mailList = temp_data['mailList']
            msg_num = int(cmds[1]) - 1
            if 0 <= msg_num < len(mailList):
                mailList[msg_num]['deleted'] = True
                loginfo.write(f"[{conn.getpeername()}][POP3] DEL: {msg_num+1}")
                conn.send("+OK Message deleted\r\n".encode())
            else:
                loginfo.write(f"[{conn.getpeername()}][POP3] DELE error: No msg{msg_num+1}")
                conn.send("-ERR No such message\r\n".encode())
        except ValueError:
            loginfo.write(f"[{conn.getpeername()}][POP3] DELE error: Invalid message number")
            conn.send("-ERR Invalid message number\r\n".encode())
    else:
        loginfo.write(f"[{conn.getpeername()}][POP3] DELE error: Syntax error")
        conn.send("-ERR Syntax error\r\n".encode())

def handle_rset(conn, temp_data):
    mailList = temp_data['mailList']
    for mail in mailList:
        mail['deleted'] = False
    conn.send("+OK\r\n".encode())
    loginfo.write(f"[{conn.getpeername()}][POP3] RSET.")

def handle_quit(conn, state, temp_data):
    if state == "TRANSACTION":
        mailList = temp_data['mailList']
        deleted_count = 0
        for mail in mailList:
            if mail.get('deleted', False):
                try:
                    mail_dir = mail['path']
                    for file in os.listdir(mail_dir):
                        os.remove(os.path.join(mail_dir, file))
                    os.rmdir(mail_dir)
                    deleted_count += 1
                except:
                    loginfo.write(f"[{conn.getpeername()}][POP3] DELE Error: {mail_dir}")
        loginfo.write(f"[{conn.getpeername()}][POP3] {deleted_count} messages deleted")

    loginfo.write(f"[{conn.getpeername()}][POP3] Disconnected.")
    conn.send("+OK Bye\r\n".encode())

def list_mails(mailpath):
    mails = []
    if not os.path.exists(mailpath):
        return mails
    
    for mail_id in os.listdir(mailpath):
        mail_dir = os.path.join(mailpath, mail_id)
        if not os.path.isdir(mail_dir):
            continue

        try:
            with open(os.path.join(mail_dir, 'mail.json'), 'r') as f:
                mail_info = json.load(f)
            with open(os.path.join(mail_dir, 'content.txt'), 'r', encoding='utf-8') as f:
                content = f.read()
            mails.append({
                'id': mail_info['id'],
                'size': len(content),
                'path': mail_dir,
                'deleted': False
            })
        except:
            continue
    return mails

def handle(conn: socket.socket, addr, user_group):
    state = "AUTHORIZATION"
    temp_data = {}
    
    connfile = conn.makefile('r', encoding='utf-8')
    loginfo.write(f"[{conn.getpeername()}][POP3] Connected.")
    conn.send(f"+OK {POP3Ctxs.get('greeting')}\r\n".encode())

    while True:
        try:
            data = connfile.readline()
            if not data:
                loginfo.write(f"[{conn.getpeername()}][POP3] Connection closed by client")
                break

            cmds = data.strip().split(" ")
            cmd = cmds[0].upper()
            loginfo.write(f"\n[{conn.getpeername()}][POP3] > {cmd}")

            if state == "AUTHORIZATION":
                if cmd == "USER":
                    handle_user(conn, cmds, temp_data)
                elif cmd == "PASS":
                    state = handle_pass(conn, cmds, temp_data, user_group)
                elif cmd == "QUIT":
                    handle_quit(conn, state, temp_data)
                    break
                else:
                    loginfo.write(f"[{conn.getpeername()}][POP3] Invalid command in AUTHORIZATION state: {cmd}")
                    conn.send("-ERR Invalid command in AUTHORIZATION state\r\n".encode())

            elif state == "TRANSACTION":
                if cmd == "STAT":
                    handle_stat(conn, temp_data)
                elif cmd == "LIST":
                    handle_list(conn, cmds, temp_data)
                elif cmd == "RETR":
                    handle_retr(conn, cmds, temp_data)
                elif cmd == "DELE":
                    handle_dele(conn, cmds, temp_data)
                elif cmd == "NOOP":
                    conn.send("+OK\r\n".encode())
                elif cmd == "RSET":
                    handle_rset(conn, temp_data)
                elif cmd == "QUIT":
                    handle_quit(conn, state, temp_data)
                    break
                elif cmd == "UIDL":
                    handle_uidl(conn, cmds, temp_data)
                elif cmd == "CAPA":
                    handle_capa(conn, state)
                else:
                    loginfo.write(f"[{conn.getpeername()}][POP3] Unknown command: {cmd}")
                    conn.send("-ERR Unknown command\r\n".encode())

        except Exception as e:
            loginfo.write(f"[{conn.getpeername()}][POP3] Error processing command: {str(e)}")
            try:
                conn.send("-ERR Server error\r\n".encode())
            except:
                pass
            break

    loginfo.write(f"[{conn.getpeername()}][POP3] Connection closed")
    connfile.close()
    conn.close()

class POP3Service:
    def __init__(self, bindIP, port, userGroup, ssl=False):
        self.socket = socket.socket()
        self.port = port
        self.userGroup = UserManager.getGroup(userGroup)
        self.socket.bind((bindIP, port))
        self.socket.listen(128)
        self.threadpools = []

    def startListen(self):
        self.listen()

    def listen(self):
        while True:
            try:
                conn, addr = self.socket.accept()
                self.threadpools.append(
                    threading.Thread(target=handle, args=(conn, addr, self.userGroup)))
                self.threadpools[-1].start()
            except Exception as e:
                loginfo.write(f"[POP3] Error: {self.port}: {str(e)}")