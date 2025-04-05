import socket
import os
import threading
import base64
import UserManager
import json
import time
import random
import string
import re
import ssl as ssl_lib

def extractEMail(line):
    pattern = r'^\w+\s*:\s*<?([^>\s]+)'
    match = re.search(pattern, line)
    if match:
        return match.group(1)
    return None

loginfo = None
conf = None

SMTPCtxs = {
    "greet": "SMTP Server Ready",
    "ehlo": "Hello (wMailServer)",
    "capabilities": [
        "PIPELINING",
        "SIZE 73400320",  # 约70MB的最大邮件大小
        "STARTTLS",
        "AUTH LOGIN PLAIN",  # 支持的认证方式
        "AUTH=LOGIN",
        "SMTPUTF8",
        "8BITMIME"
    ]
}

def initModule(log, cfg):
    global loginfo, conf
    loginfo = log
    conf = cfg

def loadErrorMailContent(sender, recipient, data, errorReason="Email delivery failed", detail="The recipient's email address was not found on this server."):

    error_template = None
    template_path = conf.get("UserGroups", {}).get("default", {}).get("errorPath")

    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            error_template = f.read()
    except:
        loginfo.write(f"[{sender}][SMTP] Error loading error mail template from {template_path}.")
        error_template  = "From: <wMailServer@himpqblog.cn>\r\n"
        error_template += f"To: <{sender}>\r\n\r\n"
        error_template += "<h1>We cant not process your email because of some error.</h1>"
        error_template += "<p>We are sorry for the inconvenience.</p>"
        error_template += "<p>Best regards,</p>"
        error_template += "<p>wMailServer</p>"
        error_template += "<p>Time: $TIME</p>"

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S %z")

    replacements = {
        "$TIME": current_time,
        "$MAIL_FROM": sender,
        "$MAIL_TO": recipient,
        "$ERROR_MAIL_ID": ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "$USERGROUP_DOMAIN": recipient.split('@')[1],
        "$TITLE": errorReason,
        "$RECIPIENT": recipient,
        "$REASON": errorReason,
        "$DETAIL": detail
    }

    for key, value in replacements.items():
        error_template = error_template.replace(key, value)

    return error_template

def handle_helo(conn, cmds, tempData):
    if cmds[0].upper() == 'EHLO':
        # 发送扩展功能列表
        conn.send(f"250-{SMTPCtxs.get('ehlo')}\r\n".encode())
        for capability in SMTPCtxs.get('capabilities')[:-1]:
            conn.send(f"250-{capability}\r\n".encode())
        # 最后一行不带连字符
        conn.send(f"250 {SMTPCtxs.get('capabilities')[-1]}\r\n".encode())
    else:
        # HELO 只返回基本问候
        conn.send(f"250 {SMTPCtxs.get('ehlo')}\r\n".encode())
    
    loginfo.write(f"[{conn.getpeername()}][SMTP] HELO/EHLO response sent")

def handle_starttls(conn, cmds, tempData, userGroup):
    if tempData.get('usingTLS'):
        loginfo.write(f"[{conn.getpeername()}][SMTP] STARTTLS error: Already using TLS")
        conn.send("454 TLS not available due to temporary reason\r\n".encode())
        return conn

    loginfo.write(f"[{conn.getpeername()}][SMTP] STARTTLS starting")
    conn.send("220 Ready to start TLS\r\n".encode())
    
    try:
        # 获取SSL配置
        sslConfig = conf.get("UserGroups", {}).get(userGroup.groupname, {}).get("sslCert", {})
        
        # 创建SSL上下文
        context = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl_lib.TLSVersion.TLSv1_2
        context.maximum_version = ssl_lib.TLSVersion.TLSv1_3
        
        # 加载证书
        context.load_cert_chain(
            certfile=sslConfig.get("cert"),
            keyfile=sslConfig.get("key")
        )
        
        # 包装socket
        conn2 = context.wrap_socket(
            conn, 
            server_side=True,
            do_handshake_on_connect=False
        )
        conn2.do_handshake()
        
        tempData['usingTLS'] = True
        loginfo.write(f"[{conn.getpeername()}][SMTP] STARTTLS successful")
    except Exception as e:
        loginfo.write(f"[{conn.getpeername()}][SMTP] STARTTLS failed: {str(e)}")
        conn.send("454 TLS not available due to temporary reason\r\n".encode())
        return conn
    
    return conn2

def handle_auth_login(conn, cmds, tempData, userGroup):
    """处理LOGIN认证方式"""
    connfile = conn.makefile('r', encoding='utf-8')
    # 请求用户名
    conn.send("334 VXNlcm5hbWU6\r\n".encode()) # Base64编码的"Username:"
    try:
        usernameB64 = connfile.readline().strip()
        username = base64.b64decode(usernameB64).decode()
    except:
        loginfo.write(f"[{conn.getpeername()}] SMTP AUTH LOGIN error: Invalid username encoding")
        conn.send("501 Invalid username encoding\r\n".encode())
        return False
        
    # 请求密码
    conn.send("334 UGFzc3dvcmQ6\r\n".encode()) # Base64编码的"Password:"
    try:
        passwordB64 = connfile.readline().strip()
        password = base64.b64decode(passwordB64).decode()
    except:
        loginfo.write(f"[{conn.getpeername()}] SMTP AUTH LOGIN error: Invalid password encoding")
        conn.send("501 Invalid password encoding\r\n".encode())
        return False

    return username, password

def handle_auth_plain(conn, cmds, tempData, userGroup):
    connfile = conn.makefile('r', encoding='utf-8')

    if len(cmds) < 2:
        conn.send("334\r\n".encode())
        try:
            authData = connfile.readline().strip()

            decoded = base64.b64decode(authData)
            # PLAIN格式: \0username\0password
            parts = decoded.split(b'\0') 
            if len(parts) != 3:  # 应该分成3部分：authorize-id, username, password
                raise ValueError("Invalid credential format")
            username = parts[1].decode() 
            password = parts[2].decode()
        except Exception as e:
            loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH PLAIN error: {str(e)}")
            conn.send("501 Invalid credentials format\r\n".encode())
            return False
    else:
        try:
            decoded = base64.b64decode(cmds[2]) 
            parts = decoded.split(b'\0')
            if len(parts) != 3:
                raise ValueError("Invalid credential format")
            username = parts[1].decode()
            password = parts[2].decode()
        except Exception as e:
            loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH PLAIN error: {str(e)}")
            conn.send("501 Invalid credentials format\r\n".encode())
            return False
            
    return username, password

def handle_auth(conn, cmds, tempData, userGroup):
    if len(cmds) < 2:
        loginfo.write("[SMTP] AUTH error: Invalid syntax")
        conn.send("501 Syntax error\r\n".encode())
        return

    authType = cmds[1].upper()
    if authType not in ['LOGIN', 'PLAIN']:
        loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH error: Unsupported auth type: {authType}")
        conn.send("504 Authentication mechanism not supported\r\n".encode())
        return
    # 获取认证信息
    loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH Typ: {authType}")
    if authType == 'LOGIN':
        result = handle_auth_login(conn, cmds, tempData, userGroup)
    else: # PLAIN
        result = handle_auth_plain(conn, cmds, tempData, userGroup)
        
    if not result:
        return
        
    username, password = result
    
    # 验证用户名密码
    if userGroup.check(username, password):
        loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH Suc: {username}")
        conn.send("235 Authentication successful\r\n".encode())
        tempData['authenticated'] = True
        tempData['user'] = {'username': username, 'password': password}
    else:
        loginfo.write(f"[{conn.getpeername()}][SMTP] AUTH Fal: {username}")
        conn.send("535 Authentication failed\r\n".encode())

def handle_mail_from(conn, cmds, tempData):
    if len(cmds) < 2:
        loginfo.write(f"[{conn.getpeername()}][SMTP] MAIL FROM error: Syntax error")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    fullCommand = ' '.join(cmds[1:])

    if not "FROM:" in fullCommand.upper():
        loginfo.write(f"[{conn.getpeername()}][SMTP] MAIL FROM error: Missing FROM:")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    mailFrom = extractEMail(fullCommand)
    if not mailFrom:
        loginfo.write(f"[{conn.getpeername()}][SMTP] MAIL FROM error: Missing address")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    if not '@' in mailFrom:
        loginfo.write(f"[{conn.getpeername()}][SMTP] MAIL FROM error: Invalid address: {mailFrom}")
        conn.send("501 Invalid mail from address\r\n".encode())
        return

    loginfo.write(f"[{conn.getpeername()}][SMTP] MAIL FROM accepted: {mailFrom}")
    conn.send("250 Mail from ok.\r\n".encode())
    tempData['MailFrom'] = mailFrom

def handle_rcpt_to(conn, cmds, tempData, userGroup):
    if len(cmds) < 2:
        loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO error: Syntax error")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    fullCommands = ' '.join(cmds[1:])

    if not "TO:" in fullCommands.upper():
        loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO error: Missing TO:")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    mailTo = extractEMail(fullCommands)
    if not mailTo:
        loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO error: Missing address")
        conn.send("501 Syntax error\r\n".encode())
        return
    
    if not '@' in mailTo:
        loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO error: Invalid address: {mailTo}")
        conn.send("501 Invalid recipient address\r\n".encode())
        return

    if not userGroup.getDomain(mailTo) in userGroup.getDomains():
        services = conf.get("SMTPServices")
        if not services or not services.get("MailRelay", {}).get("enable", False):
            loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO error: Relay not allowed for {userGroup.getDomain(mailTo)}, domains: {userGroup.getDomains()}")
            conn.send("550 Relay not allowed\r\n".encode())
            return
        tempData['MailRelay'] = True
        loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO: Relay allowed for {userGroup.getDomain(mailTo)}, domains: {userGroup.getDomains()}")
    else:
        tempData['MailRelay'] = False

    loginfo.write(f"[{conn.getpeername()}][SMTP] RCPT TO accepted: {mailTo}")
    conn.send("250 Recipient ok\r\n".encode())
    tempData['MailTo'] = mailTo

def handle_data(conn, temp_data):
    loginfo.write(f"[{conn.getpeername()}][SMTP] DATA command received")

    if not 'MailFrom' in temp_data or not 'MailTo' in temp_data:
        loginfo.write(f"[{conn.getpeername()}][SMTP] DATA error: Bad sequence")
        conn.send("503 Bad sequence of commands\r\n".encode())
        return False

    loginfo.write(f"[{conn.getpeername()}][SMTP] DATA starting")
    conn.send("354 Start mail input; end with <CRLF>.<CRLF>\r\n".encode())
    temp_data['data'] = ''
    return True

def handle(conn: socket.socket, addr, user_group):
    commandCount    = 0
    isReceivingData = False
    connfile        = conn.makefile('r', encoding='utf-8')
    tempData        = {}

    loginfo.write(f"[{conn.getpeername()}] Connected.")
    conn.send(f"220 {SMTPCtxs.get('greet')}\r\n".encode())
    
    while True:
        try:
            data = connfile.readline()
            if not data:
                loginfo.write(f"[{conn.getpeername()}][SMTP] EHLO.")
                break

            if isReceivingData:
                if data.strip() == '.':
                    loginfo.write(f"[{conn.getpeername()}][SMTP] DATA ended, processing mail")
                    isReceivingData = False

                    sendMail(tempData['MailFrom'], tempData['MailTo'], tempData['data'], tempData, user_group)

                    loginfo.write(f"[{conn.getpeername()}][SMTP] SMTP Mail delivered successfully")
                    conn.send("250 OK\r\n".encode())
                else: 
                    tempData['data'] += data
                continue
            
            cmds = data.strip().split(" ")
            cmd = cmds[0].upper()
            commandCount += 1

            loginfo.write(f"\n[{conn.getpeername()}][SMTP] > {data.strip()}")

            if cmd in ('HELO', 'EHLO'):
                handle_helo(conn, cmds, tempData)
            elif cmd == 'STARTTLS':
                conn = handle_starttls(conn, cmds, tempData, user_group)
                if tempData.get('usingTLS'):
                    conn.send(f"220 {SMTPCtxs.get('greet')}\r\n".encode())
                    connfile = conn.makefile('r', encoding='utf-8')
                    tempData.clear()
                    tempData['usingTLS'] = True
            elif cmd == 'AUTH':
                handle_auth(conn, cmds, tempData, user_group)
            elif cmd == 'MAIL':
                handle_mail_from(conn, cmds, tempData)
            elif cmd == 'RCPT':
                handle_rcpt_to(conn, cmds, tempData, user_group)
            elif cmd == 'DATA':
                isReceivingData = handle_data(conn, tempData)
            elif cmd == 'QUIT':
                conn.send("221 Bye\r\n".encode())
                break
            elif cmd == 'RSET':
                tempData.clear()
                isReceivingData = False
                conn.send("250 OK\r\n".encode())
            elif cmd == "NOOP":
                conn.send("250 OK\r\n".encode())
            else:
                loginfo.write(f"[{conn.getpeername()}][SMTP] Unknown command: {cmd}")
                conn.send("500 Unknown command\r\n".encode())

        except Exception as e:
            loginfo.write(f"[{conn.getpeername()}][SMTP] Error: {str(e)}")
            conn.send("500 Something wrong so bye.\r\n".encode())
            break

    loginfo.write(f"[{conn.getpeername()}][SMTP] Disconnected.")
    connfile.close()
    conn.close()

def sendMail(sender, recipient, data, tempData, userGroup):
    if tempData.get('MailRelay', False):
        loginfo.write(f"[{sender}][SMTP] Relay mail from {sender} to {recipient}")
        return mailRelay(sender, recipient, data, userGroup)
    
    if not userGroup.isIn(recipient):
        loginfo.write(f"[{sender}][SMTP] Mail sending error: User {recipient} not found")
        sendErrorMail(sender, recipient, data, userGroup)
        return False
    
    path = userGroup.getUserPath(recipient)
    mail_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    mail_dir = os.path.join(path, mail_id)

    loginfo.write(f"[{sender}][SMTP] Saving mail {mail_id} from {sender} to {recipient}")

    os.makedirs(mail_dir, exist_ok=True)

    with open(os.path.join(mail_dir, 'content.txt'), 'w', encoding='utf-8') as f:
        f.write(data)

    mail_info = {
        'sender': sender,
        'recipient': recipient,
        'timestamp': int(time.time()),
        'id': mail_id
    }
    with open(os.path.join(mail_dir, 'mail.json'), 'w', encoding='utf-8') as f:
        json.dump(mail_info, f, indent=2)
    loginfo.write(f"[{sender}][SMTP] Mail {mail_id} saved successfully")


def sendErrorMail(sender, recipient, data, userGroup, reason="Email delivery failed", detail="The recipient's email address was not found on this server."):
    """发送错误邮件"""
    path = userGroup.getUserPath(sender)
    error_mail_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    error_mail_dir = os.path.join(path, error_mail_id)
    loginfo.write(f"[{sender}][SMTP] Sending error mail {error_mail_id} from {sender} to {recipient}")
    os.makedirs(error_mail_dir, exist_ok=True)

    with open(os.path.join(error_mail_dir, 'content.txt'), 'w', encoding='utf-8') as f:
        f.write(loadErrorMailContent(sender, recipient, data, reason, detail))

    mail_info = {
        'sender': userGroup.getErrorMailFrom(),
        'recipient': sender,
        'timestamp': int(time.time()),
        'id': error_mail_id
    }
    with open(os.path.join(error_mail_dir, 'mail.json'), 'w', encoding='utf-8') as f:
        json.dump(mail_info, f, indent=2)
    loginfo.write(f"[{sender}][SMTP] Error mail {error_mail_id} sent successfully")

class SMTPService:
    def __init__(self, bindIP, port, userGroup, ssl=False):
        self.socket = socket.socket()
        self.port = port
        self.userGroupName = userGroup
        self.userGroup = UserManager.getGroup(userGroup)
        
        self.threadpools = []
        self.useSSL = ssl

        if ssl:
            sslConfig = conf.get("UserGroups", {}).get(userGroup, {}).get("sslCert", {})
            try:
                # 创建服务器端 SSL 上下文
                context = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
                # 设置安全级别
                context.minimum_version = ssl_lib.TLSVersion.TLSv1_2
                context.maximum_version = ssl_lib.TLSVersion.TLSv1_3
                # 加载证书和私钥
                context.load_cert_chain(
                    certfile=sslConfig.get("cert"),
                    keyfile=sslConfig.get("key")
                )
                # 包装 socket
                self.socket = context.wrap_socket(
                    self.socket, 
                    server_side=True,
                    do_handshake_on_connect=True
                )
                loginfo.write(f"[SMTP] SSL enabled on port {port} with cert: {sslConfig.get('cert')}")
            except Exception as e:
                loginfo.write(f"[SMTP] SSL error on port {port}: {str(e)}")
                raise e
        self.socket.bind((bindIP, port))
        self.socket.listen(128)
            

    def startListen(self):
        self.listen()

    def listen(self):
        while True:
            try:
                # reload user group to get the latest config
                self.userGroup = UserManager.getGroup(self.userGroupName)


                conn, addr = self.socket.accept()
                self.threadpools.append(
                    threading.Thread(target=handle, args=(conn, addr, self.userGroup)))
                self.threadpools[-1].start()
                
            except Exception as e:
                loginfo.write(f"[SMTP] Error {self.port}: {str(e)}")


def mailRelay(sender, recipient, data, userGroup:UserManager.UserGroup):
    """邮件中继功能"""
    services = conf.get("SMTPServices")
    relayHost = services.get("MailRelay", {}).get("relayHost")
    relayPort = services.get("MailRelay", {}).get("relayPort")
    relayUser = services.get("MailRelay", {}).get("relayUsername")
    relayPass = services.get("MailRelay", {}).get("relayPassword")
    ssl = services.get("MailRelay", {}).get("ssl", False)
    ruAsSender = services.get("MailRelay", {}).get("useRelayUsernameAsSender", True)

    if not relayHost or not relayPort:
        loginfo.write("[SMTP] Mail relay not configured")
        sendErrorMail(sender, recipient, data, userGroup, "Mail relay not configured",
                      "Mail relay host or port not specified. So your email cannot be sent.")
        return False
    
    conn = socket.socket()
    conn.connect((relayHost, int(relayPort)))

    loginfo.write(f"[{sender}][SMTP] Connected to relay server {relayHost}:{relayPort}")

    try:
        connfile = conn.makefile('r', encoding='utf-8')
        resp     = connfile.readline()
        if not resp.startswith('220'):
            raise Exception('Server not ready: '+ resp.strip())

        conn.send(f"EHLO {userGroup.getDomains()[0]}\r\n".encode())
        while True:
            resp = connfile.readline()
            if resp.startswith('250 '):
                break
            if not resp.startswith('250-'):
                raise Exception('EHLO failed')

        if relayUser and relayPass:
            conn.send(b"AUTH LOGIN\r\n")
            resp = connfile.readline()
            if not resp.startswith('334'):
                raise Exception('AUTH failed')

            conn.send(f"{base64.b64encode(relayUser.encode()).decode()}\r\n".encode())
            resp = connfile.readline()
            if not resp.startswith('334'):
                raise Exception('Username rejected')

            conn.send(f"{base64.b64encode(relayPass.encode()).decode()}\r\n".encode())
            resp = connfile.readline()
            if not resp.startswith('235'):
                raise Exception('Authentication failed')

        if ruAsSender:
            sender = relayUser

        conn.send(f"MAIL FROM:<{sender}>\r\n".encode())
        resp = connfile.readline()
        if not resp.startswith('250'):
            raise Exception('Sender rejected')

        conn.send(f"RCPT TO:<{recipient}>\r\n".encode())
        resp = connfile.readline()
        if not resp.startswith('250'):
            raise Exception('Recipient rejected')

        conn.send(b"DATA\r\n")
        resp = connfile.readline()
        if not resp.startswith('354'):
            raise Exception('DATA command failed')

        conn.send(data.encode() + b"\r\n.\r\n")
        resp = connfile.readline()
        if not resp.startswith('250'):
            raise Exception('Mail delivery failed')

        conn.send(b"QUIT\r\n")
        return True

    except Exception as e:
        loginfo.write(f"[SMTP] Relay error: {str(e)}")
        sendErrorMail(sender, recipient, data, userGroup, 
                     "Mail relay failed", f"Failed to relay email: {str(e)}")
        return False

    finally:
        try:
            connfile.close()
            conn.close()
        except:
            pass