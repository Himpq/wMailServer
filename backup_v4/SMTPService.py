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
import email.header
import ssl as ssl_lib
import fnmatch
import SocketUtils
import tempfile
import Configure
import AuthTracker
import html
import importlib

# 单个连接尝试的超时（秒）
SEND_TIMEOUT = 5

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
    global loginfo, conf, SEND_TIMEOUT
    loginfo = log
    conf = cfg
    # 确定用于直接外发（connect）的全局连接超时。
    # 优先使用 SMTPSettings.connectTimeout（更明确），回退到 SMTPSettings.timeout，
    # 最后仅在两者都未设置时回退到 SMTPServices.MailRelay.timeout（历史兼容）。
    try:
        smtp_settings = conf.get('SMTPSettings', {}) or {}
        timeout_cfg = smtp_settings.get('connectTimeout')
        if timeout_cfg is None:
            timeout_cfg = smtp_settings.get('timeout')
        if timeout_cfg is None:
            # 仅作最后退路：如果用户把全局 timeout 放在 MailRelay 中，这里兼容读取
            timeout_cfg = conf.get('SMTPServices', {}).get('MailRelay', {}).get('timeout')
        if timeout_cfg:
            SEND_TIMEOUT = int(timeout_cfg)
            loginfo.write(f"[SMTP] Global connect SEND_TIMEOUT set to {SEND_TIMEOUT}s from SMTPSettings/connectTimeout or fallback")
    except Exception:
        pass

    # 不在此处写入/规范化配置；配置初始化/默认填充应由 Configure.py 负责。
    try:
        loginfo.write("[SMTP] initModule: using Configure-provided configuration; defaults should be ensured by Configure.checkConf()/ensureDefaults()")
    except Exception:
        pass
    # provide log object to AuthTracker for detailed block logging
    try:
        AuthTracker.init(loginfo)
    except Exception:
        pass


def _get_peer_label(conn, tempData):
    """Return a stable peer label for logging. Prefer tempData['peer'] then conn.getpeername().n"""
    p = None
    if isinstance(tempData, dict):
        p = tempData.get('peer')
    if p:
        return p
    try:
        pn = conn.getpeername()
        return pn
    except Exception:
        return 'unknown'


def _safe_close(obj):
    try:
        if obj is None:
            return
        obj.close()
    except Exception:
        pass


def _peer_is_blocked(peer_ip):
    try:
        if not peer_ip:
            return False
        return AuthTracker.is_blocked(peer_ip)
    except Exception:
        return False


def _safe_send(conn, payload):
    if conn is None or payload is None:
        return False
    try:
        conn.send(payload)
        return True
    except Exception:
        return False


def _safe_unlink(path):
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _connection_prefix(temp_data, default_service='SMTP'):
    if not isinstance(temp_data, dict):
        peer_label = 'unknown'
        port_label = ''
    else:
        peer_label = temp_data.get('peer') or 'unknown'
        port_label = temp_data.get('log_port_label') or ''

    if port_label:
        return f"[{peer_label}][{default_service}:{port_label}] "
    return f"[{peer_label}][{default_service}] "


def _log_conn(temp_data, message, service='SMTP'):
    prefix = _connection_prefix(temp_data, default_service=service)
    try:
        loginfo.write(prefix + message)
    except Exception:
        pass

def loadErrorMailContent(sender, recipient, data, errorReason="Email delivery failed", detail="The recipient's email address was not found on this server.", severity='error', subject=None, dsn_table=None):

    """生成通知/错误邮件的 HTML 内容。
    severity: 'error' -> red, 'warning' -> yellow, 'info' -> green
    """
    error_template = None
    template_path = conf.get("UserGroups", {}).get("default", {}).get("errorPath")

    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            error_template = f.read()
    except Exception:
        loginfo.write(f"[{sender}][SMTP] Error loading error mail template from {template_path}.")
        # 默认模板（内嵌简单样式），支持替换占位符
        # Determine default From by mapping configured SMTP service ports -> userGroup.
        # Prefer the service with the lowest numeric port if multiple are configured.
        domain = None
        try:
            services = conf.get('SMTPServices', {}).get('services', {}) or {}
            if services:
                # find the lowest numeric port key available
                try:
                    ports = sorted(int(p) for p in services.keys())
                    chosen = services.get(str(ports[0]), {})
                except Exception:
                    # fallback: take first dict value
                    chosen = next(iter(services.values()))
                usergroup_name = chosen.get('userGroup') if isinstance(chosen, dict) else None
                if usergroup_name:
                    try:
                        ug = UserManager.getGroup(usergroup_name)
                        # UserGroup.load stores bindDomains into ug.domains
                        bind_domains = getattr(ug, 'domains', None) or []
                        if bind_domains:
                            domain = bind_domains[0]
                    except Exception:
                        domain = None
            # fallback: try default UserGroups.bindDomains
            if not domain:
                ug_default = conf.get('UserGroups', {}).get('default', {})
                bind_domains = ug_default.get('bindDomains') or []
                domain = bind_domains[0] if bind_domains else None
        except Exception:
            domain = None

        from_addr = f"wMailServer@{domain}" if domain else "wMailServer@localhost"
        error_template  = f"From: <{from_addr}>\r\n"
        error_template += f"To: <{sender}>\r\n\r\n"
        error_template += "<div style=\"font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border-radius: 5px;\">"
        error_template += "<h1 style=\"margin-bottom: 8px;\">$TITLE</h1>"
        error_template += "<div style=\"padding: 12px; border-radius: 4px; background: $BGCOLOR; color: $FONTCOLOR; margin-bottom: 12px;\">"
        error_template += "$DETAIL"
        error_template += "</div>"
        error_template += "<div style=\"color:#666; line-height:1.6;\">\n<p>Original message:</p>\n<pre style=\"white-space:pre-wrap; background:#fff; padding:10px; border:1px solid #eee;\">$ORIGINAL</pre>\n</div>"
        error_template += "<div style=\"margin-top: 12px; color: #999; font-size: 12px;\">This is an automatically generated message.</div>"
        error_template += "</div>"

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S %z")

    # 颜色主题
    colors = {
        'error': ('#fdecea', '#b71c1c'),   # light red bg, dark red text
        'warning': ('#fff8e1', '#f57f17'), # light yellow bg, amber text
        'info': ('#e8f5e9', '#2e7d32')     # light green bg, green text
    }
    bg, fg = colors.get(severity, colors['error'])

    replacements = {
        "$TIME": current_time,
        "$MAIL_FROM": sender,
        "$MAIL_TO": recipient,
        "$ERROR_MAIL_ID": ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "$USERGROUP_DOMAIN": recipient.split('@')[1],
        "$TITLE": errorReason,
        "$RECIPIENT": recipient,
        "$REASON": errorReason,
        "$DETAIL": detail,
        "$ORIGINAL": data,
        "$BGCOLOR": bg,
        "$FONTCOLOR": fg
    }

    # 支持额外占位符（用于 DSN 模板）
    replacements["$SUBJECT"] = subject or ''
    replacements["$DSN_TABLE"] = dsn_table or ''

    # 额外颜色占位（HEADER_COLOR/ACCENT_COLOR），根据 severity 选择
    header_color = '#b71c1c'
    accent_color = '#b71c1c'
    if severity == 'warning':
        header_color = '#f57f17'
        accent_color = '#f57f17'
    elif severity == 'info':
        header_color = '#2e7d32'
        accent_color = '#2e7d32'
    replacements['$HEADER_COLOR'] = header_color
    replacements['$ACCENT_COLOR'] = accent_color

    for key, value in replacements.items():
        error_template = error_template.replace(key, value)

    return error_template


def parse_subject(original_text):
    """从原始邮件头部解析 Subject，支持折行和 RFC2047 编码。"""
    if not original_text:
        return ''
    try:
        lines = original_text.splitlines()
        header_lines = []
        for line in lines:
            if line.strip() == '':
                break
            header_lines.append(line)

        # 收集 Subject（包括折行）
        subj = ''
        i = 0
        while i < len(header_lines):
            l = header_lines[i]
            if l.lower().startswith('subject:'):
                val = l.partition(':')[2].lstrip()
                i += 1
                # continuation lines
                while i < len(header_lines) and (header_lines[i].startswith(' ') or header_lines[i].startswith('\t')):
                    val += ' ' + header_lines[i].strip()
                    i += 1
                subj = val
                break
            i += 1

        if not subj:
            return ''

        # decode RFC2047 encoded words
        parts = email.header.decode_header(subj)
        decoded = ''
        for p, enc in parts:
            if isinstance(p, bytes):
                try:
                    decoded += p.decode(enc or 'utf-8', errors='replace')
                except Exception:
                    decoded += p.decode('utf-8', errors='replace')
            else:
                decoded += p
        return decoded
    except Exception:
        return ''

def handle_helo(conn, cmds, tempData):
    if cmds[0].upper() == 'EHLO':
        # 发送扩展功能列表
        _safe_send(conn, f"250-{SMTPCtxs.get('ehlo')}\r\n".encode())
        for capability in SMTPCtxs.get('capabilities')[:-1]:
            _safe_send(conn, f"250-{capability}\r\n".encode())
        # 最后一行不带连字符
        _safe_send(conn, f"250 {SMTPCtxs.get('capabilities')[-1]}\r\n".encode())
    else:
        # HELO 只返回基本问候
        _safe_send(conn, f"250 {SMTPCtxs.get('ehlo')}\r\n".encode())
    
    _log_conn(tempData, "HELO/EHLO response sent")

def handle_starttls(conn, cmds, tempData, userGroup):
    # prefer saved peer info (avoid calling getpeername on possibly-closed sockets)
    peer_label = _get_peer_label(conn, tempData)

    if tempData.get('usingTLS'):
        _log_conn(tempData, "STARTTLS error: Already using TLS")
        # Inform client and terminate the connection; raise so outer loop will clean up
        _safe_send(conn, "421 TLS already active, closing connection\r\n".encode())
        raise RuntimeError("STARTTLS requested but TLS already active")

    _log_conn(tempData, f"STARTTLS starting (fileno={getattr(conn, 'fileno', lambda: 'n/a')()})")
    # try to notify client; if send fails we'll continue to cleanup on handshake failure
    try:
        conn.send("220 Ready to start TLS\r\n".encode())
    except Exception as e:
        _log_conn(tempData, f"STARTTLS: failed to send 220: {e}")

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
        _log_conn(tempData, "STARTTLS successful")
    except Exception as e:
        # Ensure any partially-wrapped SSL socket is closed and close the base socket
        _safe_close(locals().get('conn2'))
        _safe_close(conn)
        # Log and re-raise so the outer handler can clean up and not continue using a broken socket
        fileno = -1
        try:
            fileno = conn.fileno()
        except Exception:
            fileno = -1
        _log_conn(tempData, f"STARTTLS failed: {str(e)} (fileno={fileno})")
        raise
    
    return conn2

def handle_auth_login(conn, cmds, tempData, userGroup):
    """处理LOGIN认证方式"""
    connfile = SocketUtils.make_connfile(conn, mode='r', encoding='utf-8')
    # 请求用户名
    _safe_send(conn, "334 VXNlcm5hbWU6\r\n".encode())  # Base64编码的"Username:"
    try:
        usernameB64 = connfile.readline().strip()
        username = base64.b64decode(usernameB64).decode()
    except Exception:
        _log_conn(tempData, "SMTP AUTH LOGIN error: Invalid username encoding")
        _safe_send(conn, "501 Invalid username encoding\r\n".encode())
        return False

    # 请求密码
    _safe_send(conn, "334 UGFzc3dvcmQ6\r\n".encode())  # Base64编码的"Password:"
    try:
        passwordB64 = connfile.readline().strip()
        password = base64.b64decode(passwordB64).decode()
    except Exception:
        _log_conn(tempData, "SMTP AUTH LOGIN error: Invalid password encoding")
        _safe_send(conn, "501 Invalid password encoding\r\n".encode())
        return False

    return username, password


def handle_auth_plain(conn, cmds, tempData, userGroup):
    connfile = SocketUtils.make_connfile(conn, mode='r', encoding='utf-8')

    if len(cmds) < 2:
        _safe_send(conn, "334\r\n".encode())
        try:
            authData = connfile.readline().strip()
            decoded = base64.b64decode(authData)
            # PLAIN格式: \0authorize-id\0username\0password (authorize-id may be empty)
            parts = decoded.split(b'\0')
            if len(parts) != 3:
                raise ValueError("Invalid credential format")
            username = parts[1].decode()
            password = parts[2].decode()
        except Exception as e:
            _log_conn(tempData, f"AUTH PLAIN error: {str(e)}")
            _safe_send(conn, "501 Invalid credentials format\r\n".encode())
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
            _log_conn(tempData, f"AUTH PLAIN error: {str(e)}")
            _safe_send(conn, "501 Invalid credentials format\r\n".encode())
            return False

    return username, password


def handle_auth(conn, cmds, tempData, userGroup):
    if len(cmds) < 2:
        loginfo.write("[SMTP] AUTH error: Invalid syntax")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return

    authType = cmds[1].upper()
    if authType not in ['LOGIN', 'PLAIN']:
        _log_conn(tempData, f"AUTH error: Unsupported auth type: {authType}")
        _safe_send(conn, "504 Authentication mechanism not supported\r\n".encode())
        return
    # 获取认证信息
    _log_conn(tempData, f"AUTH Typ: {authType}")
    if authType == 'LOGIN':
        result = handle_auth_login(conn, cmds, tempData, userGroup)
    else: # PLAIN
        result = handle_auth_plain(conn, cmds, tempData, userGroup)
        
    if not result:
        return
        
    username, password = result
    
    peer = None
    try:
        peer = conn.getpeername()[0]
    except Exception:
        peer = None
    ip_max = conf.get('wMailServerSettings', {}).get('ipMaxPwdTry', 5)
    if AuthTracker.is_blocked(peer):
        _log_conn(tempData, "AUTH blocked due to repeated failures")
        _safe_send(conn, "535 Authentication failed\r\n".encode())
        return

    # 验证用户名密码
    if userGroup.check(username, password):
        AuthTracker.record_success(peer)
        _log_conn(tempData, f"AUTH Suc: {username}")
        _safe_send(conn, "235 Authentication successful\r\n".encode())
        tempData['authenticated'] = True
        tempData['user'] = {'username': username, 'password': password}
    else:
        # Use configured block seconds so block duration matches settings
        block_s = conf.get('wMailServerSettings', {}).get('ipBlockSeconds', 3600)
        AuthTracker.record_failure(peer, max_tries=ip_max, block_seconds=block_s)
        _log_conn(tempData, f"AUTH Fal: {username}")
        _safe_send(conn, "535 Authentication failed\r\n".encode())

def handle_mail_from(conn, cmds, tempData):
    if len(cmds) < 2:
        _log_conn(tempData, "MAIL FROM error: Syntax error")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    fullCommand = ' '.join(cmds[1:])

    if not "FROM:" in fullCommand.upper():
        _log_conn(tempData, "MAIL FROM error: Missing FROM:")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    mailFrom = extractEMail(fullCommand)
    if not mailFrom:
        _log_conn(tempData, "MAIL FROM error: Missing address")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    if not '@' in mailFrom:
        _log_conn(tempData, f"MAIL FROM error: Invalid address: {mailFrom}")
        _safe_send(conn, "501 Invalid mail from address\r\n".encode())
        return

    _log_conn(tempData, f"MAIL FROM accepted: {mailFrom}")
    _safe_send(conn, "250 Mail from ok.\r\n".encode())
    tempData['MailFrom'] = mailFrom

def handle_rcpt_to(conn, cmds, tempData, userGroup):
    if len(cmds) < 2:
        _log_conn(tempData, "RCPT TO error: Syntax error")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    fullCommands = ' '.join(cmds[1:])

    if not "TO:" in fullCommands.upper():
        _log_conn(tempData, "RCPT TO error: Missing TO:")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    mailTo = extractEMail(fullCommands)
    if not mailTo:
        _log_conn(tempData, "RCPT TO error: Missing address")
        _safe_send(conn, "501 Syntax error\r\n".encode())
        return
    
    if not '@' in mailTo:
        _log_conn(tempData, f"RCPT TO error: Invalid address: {mailTo}")
        _safe_send(conn, "501 Invalid recipient address\r\n".encode())
        return

    # Determine recipient domain and decide routing/acceptance early.
    domain = None
    try:
        domain = userGroup.getDomain(mailTo)
    except Exception:
        try:
            domain = mailTo.split('@', 1)[1].lower()
        except Exception:
            domain = None

    # If recipient domain is one of this userGroup's domains, treat as local and
    # reject immediately if the specific user does not exist. This gives the
    # sending MTA instant feedback (550) instead of accepting then later DSN.
    try:
        if domain and domain in userGroup.getDomains():
            # userGroup.isIn expects full address (localpart@domain)
            if not userGroup.isIn(mailTo):
                _log_conn(tempData, f"RCPT rejected: Local recipient does not exist: {mailTo}")
                _safe_send(conn, f"550 5.1.1 <{mailTo}>: Recipient address rejected: User unknown\r\n".encode())
                return
            # existing local recipient; mark for local delivery
            tempData['MailRelay'] = False
            _log_conn(tempData, f"RCPT TO: Local delivery for {mailTo}")
        else:
            services = conf.get("SMTPServices", {})
            # 如果启用了配置中的 MailRelay 则走中继
            if services.get("MailRelay", {}).get("enable", False):
                # Only allow relay if the client is authenticated, or the
                # connection is already TLS/SSL, or the peer is localhost.
                peer_ip = None
                try:
                    peer_ip = tempData.get('peer')
                except Exception:
                    peer_ip = None
                is_local_peer = False
                try:
                    if peer_ip in ("127.0.0.1", "::1", "localhost") or (isinstance(peer_ip, str) and peer_ip.startswith('127.')):
                        is_local_peer = True
                except Exception:
                    is_local_peer = False

                if not (tempData.get('authenticated') or tempData.get('usingTLS') or is_local_peer):
                    _log_conn(tempData, f"RCPT TO rejected: relay not allowed for unauthenticated client {peer_ip}")
                    _safe_send(conn, "530 5.7.0 Authentication required for relay\r\n".encode())
                    return

                tempData['MailRelay'] = True
                _log_conn(tempData, f"RCPT TO: Relay allowed for {domain}, domains: {userGroup.getDomains()}")
            else:
                # 未配置中继：标记为直接投递（通过 MX/A 记录）
                tempData['MailRelay'] = 'direct'
                _log_conn(tempData, f"RCPT TO: Will attempt direct delivery for domain {domain}")
    except Exception:
        # On any unexpected error fall back to direct delivery
        tempData['MailRelay'] = 'direct'

    _log_conn(tempData, f"RCPT TO accepted: {mailTo}")
    _safe_send(conn, "250 Recipient ok\r\n".encode())
    # 支持多个 RCPT：把收件人加入列表
    if not tempData.get('MailTo'):
        tempData['MailTo'] = []
    # 检查最大收件人数
    max_rcpts = conf.get('SMTPServices', {}).get('settings', {}).get('maxRecipients', 5)
    if len(tempData['MailTo']) >= int(max_rcpts):
        _log_conn(tempData, "RCPT rejected: too many recipients")
        _safe_send(conn, "452 Too many recipients\r\n".encode())
        return
    tempData['MailTo'].append(mailTo)

def handle_data(conn, temp_data):
    _log_conn(temp_data, "DATA command received")

    if 'MailFrom' not in temp_data or 'MailTo' not in temp_data:
        _log_conn(temp_data, "DATA error: Bad sequence")
        _safe_send(conn, "503 Bad sequence of commands\r\n".encode())
        return False

    _log_conn(temp_data, "DATA starting")
    # 准备临时文件缓存，保存在配置的 tempPath 下
    temp_base = Configure.get('wMailServerSettings', {}).get('tempPath') or os.path.join('.', 'temp')
    try:
        os.makedirs(temp_base, exist_ok=True)
    except Exception:
        pass
    tf = tempfile.NamedTemporaryFile(delete=False, dir=temp_base, prefix='wmail_', suffix='.eml')
    temp_data['data_file'] = tf.name
    temp_data['data_fp'] = tf
    temp_data['data_size'] = 0
    _safe_send(conn, "354 Start mail input; end with <CRLF>.<CRLF>\r\n".encode())
    return True

def handle(conn: socket.socket, addr, user_group, listen_port):
    commandCount    = 0
    isReceivingData = False
    cmd_errors = 0
    connfile        = SocketUtils.make_connfile(conn, mode='r', encoding='utf-8')
    tempData        = {}

    # store peer/ip for permission checks (avoid calling getpeername after socket closed)

    # 缓存对端地址，避免在 socket 关闭后再次调用 getpeername 导致 OSError
    try:
        peer = conn.getpeername()
    except Exception:
        peer = addr

    # stash peer IP in tempData for later authorization checks
    try:
        tempData['peer'] = peer[0] if isinstance(peer, (list, tuple)) and len(peer) > 0 else str(peer)
    except Exception:
        tempData['peer'] = str(peer)

    # indicate whether this connection is already using implicit SSL (e.g., SMTPS)
    try:
        ssl_active = isinstance(conn, ssl_lib.SSLSocket)
    except Exception:
        # fallback: check for SSL-specific method
        ssl_active = hasattr(conn, 'getpeercert')
    # compute a padded port label for aligned logging. Use DebugLog.service_ports if present
    try:
        pad_char = getattr(loginfo, 'pad_char', ' ')
    except Exception:
        pad_char = ' '
    try:
        svc_ports = getattr(loginfo, 'service_ports', {}) or {}
        lens = [len(str(v)) for v in svc_ports.values() if v is not None]
    except Exception:
        svc_ports = {}
        lens = []
    try:
        lens.append(len(str(listen_port)))
    except Exception:
        pass
    try:
        max_len = max(lens) if lens else len(str(listen_port))
    except Exception:
        max_len = len(str(listen_port))
    padded = str(listen_port).rjust(max_len, pad_char)
    tempData['log_port_label'] = padded
    _log_conn(tempData, f"Connected (ssl={ssl_active})")
    try:
        _safe_send(conn, f"220 {SMTPCtxs.get('greet')}\r\n".encode())
    except Exception:
        # 发送失败说明连接可能已经断开，继续处理以便清理
        pass
    
    while True:
        try:
            data = connfile.readline()
            if not data:
                _log_conn(tempData, "EHLO.")
                break

            if isReceivingData:
                if data.strip() == '.':
                    _log_conn(tempData, "DATA ended, processing mail")
                    isReceivingData = False
                    # 支持多个收件人：tempData['MailTo'] 是列表
                    recipients = tempData.get('MailTo') or []
                    any_success = False
                    all_attempts = []  # list of (recipient, attempts_list)
                    data_fp = tempData.pop('data_fp', None)
                    data_file = tempData.pop('data_file', None)
                    data_size = tempData.pop('data_size', 0)
                    # 关闭临时文件句柄
                    try:
                        if data_fp:
                            data_fp.close()
                    except Exception:
                        pass

                    for rcpt in recipients:
                        try:
                            tempData['_suppress_error_mail'] = True
                            # 传入 data_file 路径以便 sendMail 可以流式读取
                            res = sendMail(tempData['MailFrom'], rcpt, data_file, tempData, user_group, suppressError=tempData.get('_suppress_error_mail', False))
                            if isinstance(res, tuple):
                                ok, attempts = res
                            else:
                                ok = bool(res)
                                attempts = []
                            all_attempts.append((rcpt, attempts))
                            if ok:
                                any_success = True
                                _log_conn(tempData, f"Delivered to recipient: {rcpt}")
                            else:
                                _log_conn(tempData, f"Delivery failed for recipient: {rcpt}")
                        except Exception as e:
                            _log_conn(tempData, f"Exception delivering to {rcpt}: {e}")
                            all_attempts.append((rcpt, [{'host': None, 'ip': None, 'port': None, 'ok': False, 'method': 'exception', 'error': str(e), 'ts': int(time.time())}]))

                    # 保存单个 DSN 给发件人，包含所有收件人的尝试明细
                    try:
                        sender_addr = tempData.get('MailFrom')
                        # 仅当发件人为本地用户时才保存 DSN（避免为外部发件人保存邮件）
                        if sender_addr and user_group.isIn(sender_addr):
                            # 读取原始头部做 Subject 解析，但为了安全 DSN 中插入的原文需要 HTML 转义
                            raw_original = ''
                            try:
                                if data_file and os.path.exists(data_file):
                                    with open(data_file, 'r', encoding='utf-8', errors='replace') as f:
                                        raw_original = f.read(8192)
                            except Exception:
                                raw_original = ''
                            sendDsnMail(sender_addr, raw_original, all_attempts, user_group)
                        else:
                            _log_conn(tempData, f"Sender {sender_addr} is external; skipping DSN save")
                    except Exception as e:
                        _log_conn(tempData, f"Failed to save DSN: {e}")

                    # 清理临时文件
                    _safe_unlink(data_file)

                    if any_success:
                        _log_conn(tempData, "SMTP Mail delivered for at least one recipient")
                        if not _safe_send(conn, "250 OK\r\n".encode()):
                            _log_conn(tempData, "Warning: failed to send 250 to client (socket may be closed)")
                    else:
                        _log_conn(tempData, "SMTP Mail delivery failed for all recipients")
                        if not _safe_send(conn, "550 All recipients failed\r\n".encode()):
                            _log_conn(tempData, "Warning: failed to send 550 to client (socket may be closed)")
                else:
                    # 写入 DATA 到临时文件，防止内存膨胀
                    try:
                        fp = tempData.get('data_fp')
                        if fp:
                            # data 已包含行尾\n
                            fp.write(data.encode() if isinstance(data, str) else data)
                            tempData['data_size'] = tempData.get('data_size', 0) + (len(data.encode()) if isinstance(data, str) else len(data))
                            # 检查最大消息大小
                            # maxMessageSize is in MB in config; convert to bytes
                            max_sz_mb = conf.get('SMTPServices', {}).get('settings', {}).get('maxMessageSize', 50)
                            try:
                                max_sz_bytes = int(max_sz_mb) * 1024 * 1024
                            except Exception:
                                max_sz_bytes = 50 * 1024 * 1024
                            if tempData['data_size'] > int(max_sz_bytes):
                                # 超出限制 -> 取消并通知并立即断开连接
                                _safe_close(fp)
                                _safe_unlink(tempData.get('data_file'))
                                _safe_send(conn, "552 Message size exceeds fixed maximum\r\n".encode())
                                # 关闭连接并退出处理函数以避免挂起
                                _safe_close(connfile)
                                _safe_close(conn)
                                return
                        else:
                            # 回退：如果没有文件句柄则累积（不推荐）
                            tempData['data'] = tempData.get('data', '') + data
                    except Exception as e:
                        _log_conn(tempData, f"Error writing DATA temp file: {e}")
                        _safe_send(conn, "451 Temporary storage error\r\n".encode())
                continue
            
            cmds = data.strip().split(" ")
            cmd = cmds[0].upper()
            commandCount += 1

            _log_conn(tempData, f"> {data.strip()}")

            if cmd in ('HELO', 'EHLO'):
                handle_helo(conn, cmds, tempData)
            elif cmd == 'STARTTLS':
                # Duplicate underlying socket FD before closing connfile.
                # Closing the file object returned by makefile() would otherwise
                # close the underlying socket FD. We dup() the FD, close the
                # file wrapper, and then create a new socket object from the duped FD.
                try:
                    conn = SocketUtils.safe_dup_socket(conn, connfile=connfile, log=loginfo)
                except Exception as e:
                    loginfo.write(f"[DBG][STARTTLS] safe_dup_socket failed: {e}")

                try:
                    conn = handle_starttls(conn, cmds, tempData, user_group)
                except Exception as e:
                    # Any exception during STARTTLS -> log and close connection
                    _log_conn(tempData, f"STARTTLS fatal: {e}")
                    _safe_send(conn, "421 Closing connection\r\n".encode())
                    _safe_close(connfile)
                    _safe_close(conn)
                    return
                if tempData.get('usingTLS'):
                    # After successful TLS handshake, just recreate the file wrapper
                    # Do NOT send any extra 220 here (handled before handshake).
                    connfile = SocketUtils.make_connfile(conn, mode='r', encoding='utf-8')
                    # preserve peer information across tempData reset
                    peer_saved = None
                    try:
                        peer_saved = tempData.get('peer')
                    except Exception:
                        peer_saved = None
                    tempData.clear()
                    if peer_saved is not None:
                        tempData['peer'] = peer_saved
                    tempData['log_port_label'] = padded
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
                _safe_send(conn, "221 Bye\r\n".encode())
                break
            elif cmd == 'RSET':
                peer_saved = tempData.get('peer')
                tempData.clear()
                if peer_saved is not None:
                    tempData['peer'] = peer_saved
                tempData['log_port_label'] = padded
                isReceivingData = False
                _safe_send(conn, "250 OK\r\n".encode())
            elif cmd == "NOOP":
                _safe_send(conn, "250 OK\r\n".encode())
            else:
                _log_conn(tempData, f"Unknown command: {cmd}")
                # 增加命令错误计数，超出阈值则临时封禁该 IP
                try:
                    cmd_errors += 1
                except Exception:
                    pass
                max_err = conf.get('wMailServerSettings', {}).get('maxCmdError', 5)
                if int(cmd_errors) >= int(max_err):
                    block_s = conf.get('wMailServerSettings', {}).get('cmdBlockSeconds', 60)
                    try:
                        AuthTracker.block_ip(tempData.get('peer'), int(block_s))
                    except Exception:
                        pass
                    _safe_send(conn, "421 Too many bad commands, closing connection\r\n".encode())
                    _safe_close(connfile)
                    _safe_close(conn)
                    return
                else:
                    _safe_send(conn, "500 Unknown command\r\n".encode())

        except Exception as e:
            _log_conn(tempData, f"Error: {str(e)}")
            # 增加命令错误计数，并在超过阈值时临时封禁
            try:
                cmd_errors += 1
            except Exception:
                pass
            max_err = conf.get('wMailServerSettings', {}).get('maxCmdError', 5)
            if int(cmd_errors) >= int(max_err):
                block_s = conf.get('wMailServerSettings', {}).get('cmdBlockSeconds', 60)
                try:
                    AuthTracker.block_ip(tempData.get('peer'), int(block_s))
                except Exception:
                    pass
                _safe_send(conn, "421 Too many bad commands, closing connection\r\n".encode())
                _safe_close(connfile)
                _safe_close(conn)
                return
            else:
                _safe_send(conn, "500 Something wrong so bye.\r\n".encode())
                break

    _log_conn(tempData, "Disconnected.")
    _safe_close(connfile)
    _safe_close(conn)

def sendMail(sender, recipient, data, tempData, userGroup, suppressError=False):
    # 检查当前会话是否已认证并获取用户名
    auth_user = None
    if tempData and tempData.get('user'):
        auth_user = tempData.get('user', {}).get('username')

    # Helper: check permission for auth_user
    def has_perm(u, perm):
        if not u:
            return False
        perms = userGroup.getUserPermissions(u)
        if not perms:
            return False
        return perm in perms

    # 目标是否为本地用户
    is_local = userGroup.isIn(recipient)

    # 如果目标本地，需 sendlocal（如果是已认证用户）；未认证客户仍按原行为允许投递
    if is_local:
        if auth_user:
            if not has_perm(auth_user, 'sendlocal'):
                loginfo.write(f"[{auth_user}][SMTP] Permission denied: sendlocal required to send to local user {recipient}")
                sendErrorMail(sender, recipient, data, userGroup, "Permission denied", "sendlocal permission required")
                return False
        # 本地投递（保存）
        path = userGroup.getUserPath(recipient)
        mail_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        mail_dir = os.path.join(path, mail_id)

        loginfo.write(f"[{sender}][SMTP] Saving mail {mail_id} from {sender} to {recipient}")

        os.makedirs(mail_dir, exist_ok=True)

        with open(os.path.join(mail_dir, 'content.txt'), 'w', encoding='utf-8') as f:
            # 如果 data 表示一个文件路径，则把文件内容移动/复制到 mailbox
            try:
                if isinstance(data, str) and os.path.exists(data):
                    # 直接 move 文件到目标位置以节省内存
                    f.close()
                    try:
                        os.replace(data, os.path.join(mail_dir, 'content.txt'))
                    except Exception:
                        # 回退到复制
                        with open(data, 'r', encoding='utf-8', errors='replace') as sf:
                            with open(os.path.join(mail_dir, 'content.txt'), 'w', encoding='utf-8') as df:
                                df.write(sf.read())
                else:
                    f.write(data)
            except Exception:
                try:
                    f.write(str(data))
                except Exception:
                    pass

        mail_info = {
            'sender': sender,
            'recipient': recipient,
            'timestamp': int(time.time()),
            'id': mail_id
        }
        with open(os.path.join(mail_dir, 'mail.json'), 'w', encoding='utf-8') as f:
            json.dump(mail_info, f, indent=2)
            loginfo.write(f"[{sender}][SMTP] Mail {mail_id} saved successfully")
            # Provide a synthetic attempt entry for local delivery so DSN aggregation
            # can count attempts and successes correctly.
            try:
                ts = int(time.time())
            except Exception:
                ts = None
            attempt = {'host': None, 'ip': None, 'port': None, 'ok': True, 'method': 'local', 'error': None, 'ts': ts}
            return True, [attempt]

    # 目标为外部地址：按配置中的 mailTry 顺序尝试发送方式（可配置为 ['relay','direct'] 或 ['direct','relay']）
    mail_services = conf.get('SMTPServices', {})
    mail_relay_enabled = mail_services.get('MailRelay', {}).get('enable', False)

    # If recipient domain is one of this userGroup's bindDomains but the specific user does not exist,
    # treat this as an immediate permanent failure (do not attempt direct MX or relay).
    try:
        rcpt_domain = recipient.split('@', 1)[1]
        if rcpt_domain in userGroup.getDomains() and not userGroup.isIn(recipient):
            loginfo.write(f"[{sender}][SMTP] Recipient domain {rcpt_domain} is local but user does not exist: {recipient}")
            if not suppressError:
                sendErrorMail(sender, recipient, data, userGroup, "Recipient unknown", f"The recipient {recipient} does not exist on this server.")
            return False, []
    except Exception:
        pass

    # 检查 nodirect 配置：如果 recipient 的域名匹配 nodirect 列表，则跳过 direct 直接投递
    skip_direct = False
    try:
        domain = recipient.split('@', 1)[1]
        nodirect_list = conf.get('nodirect') or []
        for nd in nodirect_list:
            if not nd:
                continue
            nd = nd.strip().lower()
            if domain.lower() == nd or domain.lower().endswith('.' + nd):
                skip_direct = True
                loginfo.write(f"[{sender}][SMTP] nodirect matched for domain {domain}, skipping direct delivery")
                break
    except Exception:
        domain = None

    # 获取尝试顺序，默认优先 relay 再 direct
    mail_try = conf.get('mailTry') or ['relay', 'direct']

    # 准备两个尝试函数（返回 True 表示成功，False 表示尝试失败/跳过）
    def try_relay():
        if not mail_relay_enabled:
            loginfo.write(f"[{sender}][SMTP] Relay disabled in config, skipping relay attempt")
            return False
        # Relay authorization policy:
        # - By default only authenticated users with 'sendrelay' permission may relay.
        # - Admin can enable anonymous relay via conf['SMTPSettings']['allowAnonymousRelay']=True
        #   combined with whitelist/blacklist modes under conf['SMTPSettings']['relayMode']:
        #     relayMode: 'whitelist'|'blacklist'|'off' (off means no extra list enforced)
        #   and lists in conf['SMTPSettings']['relayList'] (list of IPs or host identifiers)
        relay_allowed = False
        if auth_user and has_perm(auth_user, 'sendrelay'):
            relay_allowed = True
        else:
            anon_allowed = conf.get('SMTPSettings', {}).get('allowAnonymousRelay', False)
            if anon_allowed:
                # Support domain-based whitelist/blacklist patterns configured under SMTPServices.SMTPWhiteList
                smtp_wl = conf.get('SMTPServices', {}).get('SMTPWhiteList', {})
                whitelist = smtp_wl.get('whitelist', []) or []
                blacklist = smtp_wl.get('blacklist', []) or []
                # The matching target is the recipient domain (支持通配符，例如 *.himpqblog.cn)
                try:
                    rcpt_domain = recipient.split('@',1)[1].lower()
                except Exception:
                    rcpt_domain = ''

                allowed_by_whitelist = False
                if whitelist:
                    for pat in whitelist:
                        pat = pat.strip().lower()
                        if not pat:
                            continue
                        if fnmatch.fnmatch(rcpt_domain, pat) or fnmatch.fnmatch(recipient.lower(), pat):
                            allowed_by_whitelist = True
                            break

                blocked_by_blacklist = False
                if blacklist:
                    for pat in blacklist:
                        pat = pat.strip().lower()
                        if not pat:
                            continue
                        if fnmatch.fnmatch(rcpt_domain, pat) or fnmatch.fnmatch(recipient.lower(), pat):
                            blocked_by_blacklist = True
                            break

                # 根据 mode 字段决定行为：0=off(不额外基于名单限制)，1=whitelist, 2=blacklist
                mode = conf.get('SMTPServices', {}).get('SMTPWhiteList', {}).get('mode', 'disable')
                mode = str(mode).lower()

                if mode == 'whitelist':
                    # whitelist 模式：仅在 whitelist 匹配且不在 blacklist 的情形下允许
                    relay_allowed = allowed_by_whitelist and not blocked_by_blacklist
                elif mode == 'blacklist':
                    # blacklist 模式：除被 blacklist 匹配的域名之外均允许
                    relay_allowed = not blocked_by_blacklist
                else:
                    # mode == 'disable' 保持允许（由其它开关控制）
                    relay_allowed = True

                loginfo.write(f"[{sender}][SMTP] Anonymous relay decision for recipient domain {rcpt_domain}: mode={mode} allowed={relay_allowed} (whitelist_matches={allowed_by_whitelist}, blacklist_matches={blocked_by_blacklist})")

        if not relay_allowed:
            loginfo.write(f"[{auth_user or tempData.get('peer', 'unknown')}][SMTP] Permission denied: relay not allowed for this session")
            return False

        # authorized to relay
        loginfo.write(f"[{sender}][SMTP] Attempting relay for {sender} -> {recipient}")
        try:
            ok, relay_attempts = mailRelay(sender, recipient, data, userGroup, suppressError=suppressError)
            # attach relay_attempts to outer scope for DSN
            try_relay.attempts = relay_attempts
            if ok:
                return True
            else:
                loginfo.write(f"[{sender}][SMTP] Relay attempt failed for {recipient}")
                return False
        except Exception as e:
            loginfo.write(f"[{sender}][SMTP] Relay exception: {e}")
            return False

    def try_direct():
        # 直接外发需要已认证并具备 sendoutside 权限
        if skip_direct:
            loginfo.write(f"[{sender}][SMTP] Direct delivery skipped for {recipient} due to nodirect configuration")
            return False
        if auth_user and has_perm(auth_user, 'sendoutside'):
            loginfo.write(f"[{sender}][SMTP] Attempting direct delivery for {recipient}")
            direct_res = deliver_external(sender, recipient, data, userGroup, suppressError=suppressError)
            # deliver_external may return (ok, attempts) or False
            if isinstance(direct_res, tuple):
                ok, direct_attempts = direct_res
                try_direct.attempts = direct_attempts
                return ok
            else:
                return bool(direct_res)
        else:
            loginfo.write(f"[{sender}][SMTP] Permission denied: sendoutside required to send to external recipient {recipient}")
            return False

    # 按顺序尝试 mail_try 中的方式
    # collect attempts for DSN
    dsn_attempts = []

    for method in mail_try:
        m = method.lower()
        if m == 'relay':
            if try_relay():
                # successful via relay
                if hasattr(try_relay, 'attempts') and try_relay.attempts:
                    dsn_attempts.extend(try_relay.attempts)
                return True, dsn_attempts
            else:
                if hasattr(try_relay, 'attempts') and try_relay.attempts:
                    dsn_attempts.extend(try_relay.attempts)
        elif m == 'direct':
            if try_direct():
                # successful via direct
                if hasattr(try_direct, 'attempts') and try_direct.attempts:
                    dsn_attempts.extend(try_direct.attempts)
                return True, dsn_attempts
            else:
                if hasattr(try_direct, 'attempts') and try_direct.attempts:
                    dsn_attempts.extend(try_direct.attempts)
        else:
            loginfo.write(f"[{sender}][SMTP] Unknown mailTry method: {method}")

    # 如果按 mailTry 都失败，尝试发送错误通知或保存失败
    # 如果配置启用了中继并且用户有 sendrelay 权限，则在 deliver_external 失败后可尝试回退到中继（这仅在 mailTry 中未包含或已失败时）
    # 最后，告知用户失败
    # 保存 DSN 并返回失败 (DSN will be generated at DATA aggregation level)
    if not suppressError:
        sendErrorMail(sender, recipient, data, userGroup, "Permission denied or delivery failed", "All configured sending methods failed or were not permitted")
    return False, dsn_attempts
    
    


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


def sendDsnMail(sender, original, attempts, userGroup):
    """生成简洁的 DSN 报告：包含邮件 Subject（如果能解析）和收件人成功/失败列表，不附带原文。
    attempts: list of tuples (recipient, attempts_list)
      where attempts_list is list of {'host','ip','port','ok','method','error'}
    original: 原始邮件文本 (string) — 用来尝试提取 Subject，但不会把正文写入 DSN
    """
    try:
        # 如果发件人不是本地用户（external），不为其保存 DSN
        if not userGroup.isIn(sender):
            loginfo.write(f"[{sender}][SMTP] Sender is external; skipping DSN generation")
            return

        # 使用更健壮的 Subject 解析
        subj = parse_subject(original)

        overall_ok = any([any([a.get('ok') for a in atts]) for _, atts in attempts])
        title = 'Delivery report: succeeded' if overall_ok else 'Delivery report: failed'

        # 构建 DSN 表格 HTML
        table_rows = []
        for rcpt, atts in attempts:
            rcpt_ok = any([a.get('ok') for a in atts])
            status = 'Delivered' if rcpt_ok else 'Failed'

            total_attempts = len(atts)
            successful_attempts = sum(1 for a in atts if a.get('ok'))
            last_ts = None
            for a in reversed(atts):
                if a.get('ts'):
                    last_ts = a.get('ts')
                    break

            ts_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_ts)) if last_ts else ''

            # 简短错误汇总
            errors = []
            for a in atts:
                err = a.get('error')
                if err and err.strip():
                    short = err.strip().split('\n', 1)[0]
                    if len(short) > 140:
                        short = short[:137] + '...'
                    if short not in errors:
                        errors.append(short)
            error_summary = '; '.join(errors)

            status_color = '#2e7d32' if rcpt_ok else '#b71c1c'
            row_html = f"<tr><td style='padding:8px;border-bottom:1px solid #eee;'>{rcpt}</td>"
            row_html += f"<td style='padding:8px;border-bottom:1px solid #eee;color:{status_color};font-weight:600;'>{status}</td>"
            row_html += f"<td style='padding:8px;border-bottom:1px solid #eee;'>Attempts: {total_attempts}, Success: {successful_attempts}"
            if ts_text:
                row_html += f"; Last: {ts_text}"
            if error_summary:
                row_html += f"<div style='margin-top:6px;color:#666;font-size:12px;'>Errors: {error_summary}</div>"
            row_html += "</td></tr>"
            table_rows.append(row_html)

        dsn_table = "<table style='width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden;border:1px solid #eaeaea;'>"
        dsn_table += "<thead><tr style='background:#f5f5f5;'><th style='text-align:left;padding:10px;'>Recipient</th><th style='text-align:left;padding:10px;'>Status</th><th style='text-align:left;padding:10px;'>Summary</th></tr></thead>"
        dsn_table += "<tbody>" + ''.join(table_rows) + "</tbody></table>"

        # 读取模板并渲染
        template_path = conf.get("UserGroups", {}).get("default", {}).get("errorPath")
        template = None
        try:
            if template_path and os.path.exists(template_path):
                with open(template_path, 'r', encoding='utf-8') as f:
                    template = f.read()
        except Exception:
            template = None

        if not template:
            try:
                with open(os.path.join('sample', 'config', 'error.txt'), 'r', encoding='utf-8') as f:
                    template = f.read()
            except Exception:
                template = None

        used_template = bool(template)
        html = loadErrorMailContent(userGroup.getErrorMailFrom(), sender, original, title, 'See details below.', severity='info' if overall_ok else 'error', subject=subj or '', dsn_table=dsn_table)

        # 保存到发件人的本地 mailbox（若不存在则写入管理员 mailbox，最后退回到 dropped_dsn）
        path = userGroup.getUserPath(sender)
        note_recipient = sender
        if not path:
            admin_addr = userGroup.getErrorMailFrom()
            loginfo.write(f"[{sender}][SMTP] Sender not local, saving DSN to admin mailbox {admin_addr}")
            path = userGroup.getUserPath(admin_addr)
            note_recipient = admin_addr
            if not path:
                path = os.path.join('.', 'dropped_dsn')
                os.makedirs(path, exist_ok=True)

        note_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        note_dir = os.path.join(path, note_id)
        os.makedirs(note_dir, exist_ok=True)

        # 如果模板包含完整头部则直接写入；否则构建 MIME multipart
        if used_template and (html.lstrip().startswith('Date:') or 'MIME-Version:' in html or 'Content-Type:' in html or html.lstrip().startswith('From:')):
            with open(os.path.join(note_dir, 'content.txt'), 'w', encoding='utf-8') as f:
                f.write(html)
            with open(os.path.join(note_dir, 'mail.json'), 'w', encoding='utf-8') as f:
                json.dump({'sender': userGroup.getErrorMailFrom(), 'recipient': note_recipient, 'timestamp': int(time.time()), 'id': note_id}, f, indent=2)
        else:
            # 构建简易 MIME
            boundary = '====boundary_' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            date_str = time.strftime('%a, %d %b %Y %H:%M:%S %z')
            from_addr = userGroup.getErrorMailFrom()
            to_addr = sender
            subj_header = f"Delivery report: {'succeeded' if overall_ok else 'failed'}"

            # 纯文本摘要
            plain_lines = [subj_header]
            if subj:
                plain_lines.append(f"Subject: {subj}")
            plain_lines.append("")
            plain_lines.append("Recipients:")
            for rcpt, atts in attempts:
                rcpt_ok = any([a.get('ok') for a in atts])
                status = 'Delivered' if rcpt_ok else 'Failed'
                total_attempts = len(atts)
                successful_attempts = sum(1 for a in atts if a.get('ok'))
                last_ts = None
                for a in reversed(atts):
                    if a.get('ts'):
                        last_ts = a.get('ts')
                        break
                ts_text = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_ts)) if last_ts else ''
                errors = []
                for a in atts:
                    err = a.get('error')
                    if err and err.strip():
                        short = err.strip().split('\n',1)[0]
                        if len(short) > 120:
                            short = short[:117] + '...'
                        if short not in errors:
                            errors.append(short)
                error_summary = '; '.join(errors)
                extra = f" ({error_summary})" if error_summary else ''
                attempts_text = f"attempts: {total_attempts}, success: {successful_attempts}"
                if ts_text:
                    attempts_text += f"; last: {ts_text}"
                plain_lines.append(f"- {rcpt}: {status}{extra} -- {attempts_text}")

            plain_body = '\n'.join(plain_lines)

            mime_lines = []
            mime_lines.append(f"From: {from_addr}")
            mime_lines.append(f"To: {to_addr}")
            mime_lines.append(f"Subject: {subj_header}")
            mime_lines.append(f"Date: {date_str}")
            mime_lines.append("MIME-Version: 1.0")
            mime_lines.append(f"Content-Type: multipart/alternative; boundary=\"{boundary}\"")
            mime_lines.append("")
            mime_lines.append(f"--{boundary}")
            mime_lines.append("Content-Type: text/plain; charset=utf-8")
            mime_lines.append("Content-Transfer-Encoding: 8bit")
            mime_lines.append("")
            mime_lines.append(plain_body)
            mime_lines.append("")
            mime_lines.append(f"--{boundary}")
            mime_lines.append("Content-Type: text/html; charset=utf-8")
            mime_lines.append("Content-Transfer-Encoding: 8bit")
            mime_lines.append("")
            mime_lines.append(html)
            mime_lines.append("")
            mime_lines.append(f"--{boundary}--")

            mime_text = '\r\n'.join(mime_lines)
            with open(os.path.join(note_dir, 'content.txt'), 'w', encoding='utf-8') as f:
                f.write(mime_text)
            with open(os.path.join(note_dir, 'mail.json'), 'w', encoding='utf-8') as f:
                json.dump({'sender': from_addr, 'recipient': note_recipient, 'timestamp': int(time.time()), 'id': note_id}, f, indent=2)

        loginfo.write(f"[{sender}][SMTP] DSN saved as {note_id} for {len(attempts)} recipients")
    except Exception as e:
        loginfo.write(f"[{sender}][SMTP] Failed to save DSN for {sender}: {e}")

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
                # check IP block before creating handler thread
                peer_ip = None
                try:
                    peer_ip = addr[0] if isinstance(addr, (list, tuple)) and len(addr) > 0 else str(addr)
                except Exception:
                    try:
                        peer_ip = conn.getpeername()[0]
                    except Exception:
                        peer_ip = None

                try:
                    if peer_ip and AuthTracker.is_blocked(peer_ip):
                        try:
                            loginfo.write(f"[SMTP] Refusing connection from blocked IP {peer_ip}")
                        except Exception:
                            pass
                        try:
                            conn.send("421 Your IP is temporarily blocked, closing connection\r\n".encode())
                        except Exception:
                            pass
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                except Exception:
                    # if checking block fails for any reason, proceed with normal handling
                    pass

                self.threadpools.append(
                    threading.Thread(target=handle, args=(conn, addr, self.userGroup, self.port)))
                self.threadpools[-1].start()
                
            except Exception as e:
                loginfo.write(f"[SMTP] Error {self.port}: {str(e)}")


def get_mx_hosts(domain):
    """尝试获取域的 MX 记录，失败时回退到域的 A 记录"""
    # 优先检查本地缓存文件 ./config/localMX.json
    try:
        local_path = os.path.join('config', 'localMX.json')
        if os.path.exists(local_path):
            with open(local_path, 'r', encoding='utf-8') as f:
                local = json.load(f)
                # 支持 key 精确匹配或后缀匹配
                if domain in local:
                    entry = local[domain]
                    host = entry.get('smtp') or entry.get('mx')
                    if host:
                        loginfo.write(f"[SMTP] localMX.json override for {domain}: {host}")
                        return [host]
                else:
                    # 尝试后缀匹配（例如 user@sub.qq.com -> qq.com）
                    for k in local.keys():
                        if domain.endswith('.' + k) or domain == k:
                            entry = local.get(k)
                            host = entry.get('smtp') or entry.get('mx')
                            if host:
                                loginfo.write(f"[SMTP] localMX.json suffix override for {domain}: {host}")
                                return [host]
    except Exception as e:
        loginfo.write(f"[SMTP] Failed to read localMX.json: {e}")

    # 否则尝试 DNS MX
    try:
        dns_resolver = None
        try:
            dns_resolver = importlib.import_module('dns.resolver')
        except ModuleNotFoundError:
            dns_resolver = None
        except Exception:
            dns_resolver = None
        if dns_resolver:
            answers = dns_resolver.resolve(domain, 'MX')
            mxs = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])
            hosts = [h for _, h in mxs]
            loginfo.write(f"[SMTP] MX for {domain}: {hosts}")
            return hosts
        else:
            raise Exception('dnspython not installed')
    except Exception as e:
        loginfo.write(f"[SMTP] MX lookup failed for {domain}: {e} (falling back to A record)")
        try:
            # 回退：将域名作为主机名（会在连接时解析）
            return [domain]
        except Exception as e2:
            loginfo.write(f"[SMTP] A lookup fallback failed for {domain}: {e2}")
            return []


def deliver_external(sender, recipient, data, userGroup:UserManager.UserGroup, suppressError=False):
    """直接根据 MX/A 记录对目标服务器投递邮件。

    行为：
    - 使用 get_mx_hosts 获取 MX 列表
    - 对每个 MX，解析出所有地址（getaddrinfo），优先尝试 IPv4，再尝试 IPv6
    - 对每个地址使用全局 SEND_TIMEOUT（秒）进行连接尝试；超时/不可达则跳过下一个地址
    - 如果所有 MX 地址都失败且用户具有 sendrelay 权限并且 MailRelay 启用，则尝试通过 mailRelay 中继发送并向用户发送通知邮件
    """
    domain = recipient.split('@', 1)[1]
    hosts = get_mx_hosts(domain)
    attempts = []
    if not hosts:
        loginfo.write(f"[{sender}][SMTP] No MX/A records for {domain}")
        if not suppressError:
            sendErrorMail(sender, recipient, data, userGroup,
                          "No MX/A records", f"DNS lookup failed for domain {domain}")
        return False, attempts

    last_exc = None
    for host in hosts:
        try:
            loginfo.write(f"[{sender}][SMTP] Resolving addresses for {host}")
            # 支持在配置中指定要尝试的端口，例如 [25, 587, 465]
            direct_ports = conf.get('SMTPServices', {}).get('settings', {}).get('directPorts', [25])
            for port in direct_ports:
                try:
                    addrinfos = socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
                except Exception as e:
                    loginfo.write(f"[{sender}][SMTP] getaddrinfo failed for {host}:{port}: {e}")
                    last_exc = e
                    continue

                # 将地址按 family 排序：优先 AF_INET (IPv4)
                addrinfos_sorted = sorted(addrinfos, key=lambda x: 0 if x[0]==socket.AF_INET else 1)

                for fam, socktype, proto, canonname, sockaddr in addrinfos_sorted:
                    ip = sockaddr[0]
                    loginfo.write(f"[{sender}][SMTP] Trying deliver to {ip}:{port} (host {host}) with timeout {SEND_TIMEOUT}s")
                    conn = None
                    try:
                        conn = socket.create_connection((ip, int(port)), timeout=SEND_TIMEOUT)

                        # 如果是 SMTPS (465)，在读取 banner 之前进行 SSL-on-connect
                        if int(port) == 465:
                            try:
                                context = ssl_lib.create_default_context()
                                conn = context.wrap_socket(conn, server_hostname=host)
                                # 使用全局 SMTPSettings.ioTimeout 作为 I/O 超时
                                io_timeout = conf.get('SMTPSettings', {}).get('ioTimeout')
                                if io_timeout is not None:
                                    conn.settimeout(float(io_timeout))
                                else:
                                    conn.settimeout(None)
                            except Exception as e:
                                raise Exception(f'SSL wrap failed: {e}')

                        connfile = conn.makefile('r', encoding='utf-8')
                        banner = connfile.readline()
                        if not banner.startswith('220'):
                            raise Exception('Server not ready: '+ banner.strip())

                        ehlo_name = userGroup.getDomains()[0] if userGroup.getDomains() else domain
                        conn.send(f"EHLO {ehlo_name}\r\n".encode())
                        # 读取 EHLO 回复（多行）
                        supports_starttls = False
                        while True:
                            resp = connfile.readline()
                            if not resp:
                                raise Exception("No response during EHLO")
                            if resp.lower().find('starttls') != -1:
                                supports_starttls = True
                            if resp.startswith('250 '):
                                break
                            if not resp.startswith('250-'):
                                raise Exception('EHLO failed')

                        # 对 587/25，如果对端支持 STARTTLS 且配置允许，则尝试升级
                        starttls_allowed = conf.get('SMTPSettings', {}).get('starttlsEnable', True)
                        if int(port) in (25, 587) and supports_starttls and starttls_allowed:
                            try:
                                conn.send(b"STARTTLS\r\n")
                                resp = connfile.readline()
                                if resp.startswith('220'):
                                    context = ssl_lib.create_default_context()
                                    conn = context.wrap_socket(conn, server_hostname=host)
                                    io_timeout = conf.get('SMTPSettings', {}).get('ioTimeout')
                                    if io_timeout is not None:
                                        conn.settimeout(float(io_timeout))
                                    else:
                                        conn.settimeout(None)
                                    connfile = conn.makefile('r', encoding='utf-8')
                                    # 再次 EHLO
                                    conn.send(f"EHLO {ehlo_name}\r\n".encode())
                                    while True:
                                        resp = connfile.readline()
                                        if resp.startswith('250 '):
                                            break
                                else:
                                    loginfo.write(f"[{sender}][SMTP] STARTTLS rejected by {host}:{port}: {resp.strip()}")
                            except Exception as e:
                                loginfo.write(f"[{sender}][SMTP] STARTTLS error for {host}:{port}: {e}")

                        # MAIL FROM
                        conn.send(f"MAIL FROM:<{sender}>\r\n".encode())
                        resp = connfile.readline()
                        if not resp.startswith('250'):
                            raise Exception('Sender rejected: ' + resp.strip())

                        # RCPT TO
                        conn.send(f"RCPT TO:<{recipient}>\r\n".encode())
                        resp = connfile.readline()
                        if not (resp.startswith('250') or resp.startswith('251')):
                            raise Exception('Recipient rejected: ' + resp.strip())

                        # DATA
                        conn.send(b"DATA\r\n")
                        resp = connfile.readline()
                        if not resp.startswith('354'):
                            raise Exception('DATA command failed: ' + resp.strip())

                        # 发送邮件内容（支持文件路径的流式发送，确保以 CRLF . CRLF 结尾）
                        def send_message_from_source(conn_obj, source):
                            # source 可以是文件路径或字符串
                            try:
                                if isinstance(source, str) and os.path.exists(source):
                                    with open(source, 'rb') as sf:
                                        while True:
                                            chunk = sf.read(16*1024)
                                            if not chunk:
                                                break
                                            conn_obj.send(chunk)
                                else:
                                    txt = source if isinstance(source, str) else str(source)
                                    if not txt.endswith("\r\n"):
                                        txt = txt + "\r\n"
                                    conn_obj.send(txt.encode())
                                # end marker
                                conn_obj.send(b"\r\n.\r\n")
                                return True
                            except Exception as e:
                                raise

                        send_message_from_source(conn, data)
                        resp = connfile.readline()
                        if not resp.startswith('250'):
                            raise Exception('Mail delivery failed: ' + resp.strip())

                        conn.send(b"QUIT\r\n")
                        try:
                            connfile.close()
                        except Exception:
                            pass
                        try:
                            conn.close()
                        except Exception:
                            pass

                        loginfo.write(f"[{sender}][SMTP] Delivered to {ip}:{port} (host {host}) successfully")
                        attempts.append({'host': host, 'ip': ip, 'port': int(port), 'ok': True, 'method': 'direct', 'error': None, 'ts': int(time.time())})
                        return True, attempts

                    except Exception as e:
                        loginfo.write(f"[{sender}][SMTP] Delivery to {ip}:{port} (host {host}) failed: {e}")
                        last_exc = e
                        attempts.append({'host': host, 'ip': ip, 'port': int(port), 'ok': False, 'method': 'direct', 'error': str(e), 'ts': int(time.time())})
                        try:
                            if conn:
                                conn.close()
                        except Exception:
                            pass
                        # 尝试下一个地址/端口
                        continue

        except Exception as e:
            loginfo.write(f"[{sender}][SMTP] Resolution/attempt for host {host} failed: {e}")
            last_exc = e
            attempts.append({'host': host, 'ip': None, 'port': None, 'ok': False, 'method': 'direct', 'error': str(e), 'ts': int(time.time())})
            continue

    # 所有 MX 地址都尝试失败
    loginfo.write(f"[{sender}][SMTP] All delivery attempts to {domain} failed: {last_exc}")

    # 如果用户有 sendrelay 权限并且配置启用了 MailRelay，尝试使用中继发送并通知用户
    services = conf.get('SMTPServices', {})
    if userGroup and userGroup.getUserPermissions and userGroup.getUserPermissions(sender.split('@')[0]):
        perms = userGroup.getUserPermissions(sender.split('@')[0])
    else:
        perms = None

    mailrelay_enabled = services.get('MailRelay', {}).get('enable', False)
    if perms and 'sendrelay' in perms and mailrelay_enabled:
        loginfo.write(f"[{sender}][SMTP] Attempting fallback relay after MX failures for {recipient}")
        try:
            ok, relay_attempts = mailRelay(sender, recipient, data, userGroup, suppressError=suppressError)
            attempts.extend(relay_attempts or [])
            if ok:
                # 构造通知邮件内容（HTML样式），告知用户邮件通过中继成功发送
                # 仅在非 suppress 情况下保存通知（DATA 聚合时会由 DSN 统一生成）
                if not suppressError:
                    relay_subj = parse_subject(data) or "Delivered via relay"
                    notice = loadErrorMailContent(userGroup.getErrorMailFrom(), recipient, data, "Delivered via relay", "Your message was delivered using the configured mail relay after direct MX delivery failed.", severity='warning', subject=relay_subj, dsn_table='')
                    # save a notification mail to sender's mailbox if possible
                    path = userGroup.getUserPath(sender)
                    if path:
                        note_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                        note_dir = os.path.join(path, note_id)
                        os.makedirs(note_dir, exist_ok=True)
                        with open(os.path.join(note_dir, 'content.txt'), 'w', encoding='utf-8') as f:
                            f.write(notice)
                        with open(os.path.join(note_dir, 'mail.json'), 'w', encoding='utf-8') as f:
                            json.dump({'sender': services.get('MailRelay', {}).get('relayUsername', 'relay'), 'recipient': sender, 'timestamp': int(time.time()), 'id': note_id}, f, indent=2)
                        loginfo.write(f"[{sender}][SMTP] Mail delivered via relay and notification saved as {note_id}")
                    else:
                        # no local mailbox for sender — log and drop notification (avoid NoneType path)
                        loginfo.write(f"[{sender}][SMTP] Mail delivered via relay but no local mailbox for sender; notification dropped")
                return True, attempts
            else:
                loginfo.write(f"[{sender}][SMTP] Fallback relay attempt failed")
        except Exception as e:
            loginfo.write(f"[{sender}][SMTP] Fallback relay exception: {e}")

    # 最终失败，保存失败通知
    # 最终失败，保存失败通知
    if not suppressError:
        # 汇总 attempts 中的非空错误信息，优先展示远端服务器返回的文本（例如 '554 Reject by content spam ...'）
        error_texts = []
        for a in attempts:
            e = a.get('error')
            if e:
                txt = str(e).strip()
                if txt and txt not in error_texts:
                    error_texts.append(txt)
        detail_msg = f"Failed to deliver to any MX/A for {domain}"
        if error_texts:
            detail_msg += ": " + "; ".join(error_texts)
        else:
            detail_msg += f": {last_exc}"

        sendErrorMail(sender, recipient, data, userGroup,
                      "Remote delivery failed", detail_msg)
    return False, attempts


def mailRelay(sender, recipient, data, userGroup:UserManager.UserGroup, suppressError=False):
    """邮件中继功能：使用配置中的 MailRelay 设置，将邮件发送到上游中继服务器。"""
    attempts = []
    services = conf.get('SMTPServices', {})
    mr = services.get('MailRelay', {})
    relayHost = mr.get('relayHost')
    relayPort = int(mr.get('relayPort') or mr.get('port') or 25)
    relayUser = mr.get('relayUsername')
    relayPass = mr.get('relayPassword')
    use_ssl_on_connect = bool(mr.get('ssl', False) or mr.get('useSSL', False))
    use_relay_user_as_sender = bool(mr.get('useRelayUserAsSender', False))

    if not relayHost:
        loginfo.write(f"[{sender}][SMTP] No relayHost configured, cannot relay")
        return False, attempts

    # 解析 relayHost
    try:
        addrinfos = socket.getaddrinfo(relayHost, relayPort, proto=socket.IPPROTO_TCP)
    except Exception as e:
        loginfo.write(f"[{sender}][SMTP] getaddrinfo for relay {relayHost}:{relayPort} failed: {e}")
        attempts.append({'host': relayHost, 'ip': None, 'port': relayPort, 'ok': False, 'method': 'relay', 'error': str(e), 'ts': int(time.time())})
        if not suppressError:
            sendErrorMail(sender, recipient, data, userGroup, "Mail relay failed", f"DNS resolution failed for relay {relayHost}: {e}")
        return False, attempts

    addrinfos_sorted = sorted(addrinfos, key=lambda x: 0 if x[0]==socket.AF_INET else 1)

    conn = None
    connfile = None
    connected_addr = None
    last_connect_exc = None
    for fam, socktype, proto, canonname, sockaddr in addrinfos_sorted:
        ip = sockaddr[0]
        try:
            # 中继连接超时优先使用 MailRelay.timeout（专用），否则回退到全局 SEND_TIMEOUT
            relay_connect_timeout = mr.get('timeout') if isinstance(mr, dict) else None
            if relay_connect_timeout is None:
                relay_connect_timeout = SEND_TIMEOUT
            conn = socket.create_connection((ip, relayPort), timeout=float(relay_connect_timeout))
            connected_addr = ip
            break
        except Exception as e:
            loginfo.write(f"[{sender}][SMTP] Relay connect to {ip}:{relayPort} failed: {e}")
            last_connect_exc = e
            attempts.append({'host': relayHost, 'ip': ip, 'port': relayPort, 'ok': False, 'method': 'relay', 'error': str(e), 'ts': int(time.time())})
            continue

    if not conn:
        loginfo.write(f"[{sender}][SMTP] All relay connect attempts failed for {relayHost}:{relayPort}: {last_connect_exc}")
        if not suppressError:
            sendErrorMail(sender, recipient, data, userGroup, "Mail relay failed", f"Failed to connect to relay {relayHost}:{relayPort}: {last_connect_exc}")
        return False, attempts

    loginfo.write(f"[{sender}][SMTP] Connected to relay server {connected_addr}:{relayPort}")
    # 建立连接后使用全局的 SMTPSettings.ioTimeout 作为 I/O 超时
    io_timeout = conf.get('SMTPSettings', {}).get('ioTimeout')
    if io_timeout is not None:
        conn.settimeout(float(io_timeout))
    else:
        conn.settimeout(None)

    try:
        # SSL-on-connect
        if use_ssl_on_connect:
            try:
                context = ssl_lib.create_default_context()
                conn = context.wrap_socket(conn, server_hostname=relayHost)
                if io_timeout is not None:
                    conn.settimeout(float(io_timeout))
                else:
                    conn.settimeout(None)
            except Exception as e:
                raise Exception(f'SSL wrap failed: {e}')

        connfile = conn.makefile('r', encoding='utf-8')
        # read banner
        resp = connfile.readline()
        if not resp.startswith('220'):
            raise Exception('Server not ready: ' + resp.strip())

        ehlo_name = userGroup.getDomains()[0] if userGroup.getDomains() else recipient.split('@',1)[1]
        conn.send(f"EHLO {ehlo_name}\r\n".encode())
        supports_starttls = False
        while True:
            resp = connfile.readline()
            if not resp:
                raise Exception('No response during EHLO')
            if 'starttls' in resp.lower():
                supports_starttls = True
            if resp.startswith('250 '):
                break
            if not resp.startswith('250-'):
                raise Exception('EHLO failed')

        starttls_allowed = conf.get('SMTPSettings', {}).get('starttlsEnable', True)
        if supports_starttls and starttls_allowed and not use_ssl_on_connect:
            try:
                conn.send(b"STARTTLS\r\n")
                resp = connfile.readline()
                if resp.startswith('220'):
                    context = ssl_lib.create_default_context()
                    conn = context.wrap_socket(conn, server_hostname=relayHost)
                    if io_timeout is not None:
                        conn.settimeout(float(io_timeout))
                    else:
                        conn.settimeout(None)
                    connfile = SocketUtils.make_connfile(conn, mode='r', encoding='utf-8')
                    conn.send(f"EHLO {ehlo_name}\r\n".encode())
                    while True:
                        resp = connfile.readline()
                        if resp.startswith('250 '):
                            break
                else:
                    loginfo.write(f"[{sender}][SMTP] Relay STARTTLS rejected by {relayHost}: {resp.strip()}")
            except Exception as e:
                loginfo.write(f"[{sender}][SMTP] Relay STARTTLS error for {relayHost}: {e}")

        # AUTH if credentials provided
        if relayUser and relayPass:
            conn.send(b"AUTH LOGIN\r\n")
            resp = connfile.readline()
            if not resp.startswith('334'):
                raise Exception('AUTH failed')
            conn.send((base64.b64encode(relayUser.encode()).decode() + '\r\n').encode())
            resp = connfile.readline()
            if not resp.startswith('334'):
                raise Exception('Username rejected')
            conn.send((base64.b64encode(relayPass.encode()).decode() + '\r\n').encode())
            resp = connfile.readline()
            if not resp.startswith('235'):
                raise Exception('Authentication failed')

        envelope_sender = sender
        if use_relay_user_as_sender and relayUser:
            envelope_sender = relayUser

        conn.send(f"MAIL FROM:<{envelope_sender}>\r\n".encode())
        resp = connfile.readline()
        if not resp.startswith('250'):
            raise Exception('Sender rejected: ' + resp.strip())

        conn.send(f"RCPT TO:<{recipient}>\r\n".encode())
        resp = connfile.readline()
        if not (resp.startswith('250') or resp.startswith('251')):
            raise Exception('Recipient rejected: ' + resp.strip())

        conn.send(b"DATA\r\n")
        resp = connfile.readline()
        if not resp.startswith('354'):
            raise Exception('DATA command failed: ' + resp.strip())

        def send_message_from_source(conn_obj, source):
            try:
                if isinstance(source, str) and os.path.exists(source):
                    with open(source, 'rb') as sf:
                        while True:
                            chunk = sf.read(16*1024)
                            if not chunk:
                                break
                            conn_obj.send(chunk)
                else:
                    txt = source if isinstance(source, str) else str(source)
                    if not txt.endswith("\r\n"):
                        txt = txt + "\r\n"
                    conn_obj.send(txt.encode())
                conn_obj.send(b"\r\n.\r\n")
                return True
            except Exception:
                raise

        send_message_from_source(conn, data)
        resp = connfile.readline()
        if not resp.startswith('250'):
            raise Exception('Mail delivery failed: ' + resp.strip())

        conn.send(b"QUIT\r\n")
        attempts.append({'host': relayHost, 'ip': connected_addr, 'port': relayPort, 'ok': True, 'method': 'relay', 'error': None, 'ts': int(time.time())})
        return True, attempts

    except Exception as e:
        loginfo.write(f"[{sender}][SMTP] Relay error: {str(e)}")
        attempts.append({'host': relayHost, 'ip': connected_addr, 'port': relayPort if relayPort else None, 'ok': False, 'method': 'relay', 'error': str(e), 'ts': int(time.time())})
        if not suppressError:
            sendErrorMail(sender, recipient, data, userGroup, "Mail relay failed", f"Failed to relay email: {str(e)}")
        return False, attempts

    finally:
        try:
            if connfile:
                connfile.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass