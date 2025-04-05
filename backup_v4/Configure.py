import os
import json

config = None

def checkConf():
    """检查配置文件是否存在,不存在则创建默认配置"""
    if not os.path.exists("./config"):
        os.mkdir("./config")
        os.mkdir("./config/ssl")
    
    if not os.path.exists("./config/config.json"):
        defaultConfig = {
            "SMTPServices": {
                "settings": {
                    "capabilities": [
                        "PIPELINING",
                        "SIZE 73400320",  # 约70MB的最大邮件大小
                        "STARTTLS",
                        "AUTH LOGIN PLAIN",  # 支持的认证方式
                        "AUTH=LOGIN",
                        "SMTPUTF8",
                        "8BITMIME"
                    ],
                    # 全局 SMTP 行为设置（连接超时 / IO 超时 / 限制等）
                    "timeout": 5,
                    "ioTimeout": 60,
                    # 最大消息大小（单位：MB），50 默认（表示 50 MB）
                    "maxMessageSize": 50,
                    # 每封邮件最大收件人数
                    "maxRecipients": 5,
                    "directPorts": [25]
                },
                "services": {
                    "25": {
                        "bindIP": "0.0.0.0",
                        "ssl": False,
                        "userGroup": "default",
                    },
                    "465": {
                        "bindIP": "0.0.0.0", 
                        "ssl": True,
                        "userGroup": "default"
                    }
                },
                "MailRelay": {
                    "enable": False,
                    "relayHost": "",
                    "relayPort": 25,
                    "relayUsername": "",
                    "relayPassword": "",
                    "ssl": False,
                    "useRelayUsernameAsSender": True
                }
            ,
                "SMTPWhiteList": {
                    "mode": "disable",
                    "whitelist": [],
                    "blacklist": []
                }
            },
            "POP3Services": {
                "services": {
                    "110": {
                        "bindIP": "0.0.0.0",
                        "ssl": False,
                        "userGroup": "default"
                    },
                    "995": {
                        "bindIP": "0.0.0.0",
                        "ssl": True,
                        "userGroup": "default" 
                    }
                }
            },
            # 全局 SMTP 相关设置
            # 顶层 SMTPSettings 已迁移到 SMTPServices.settings（保持兼容字段旧值移除）
            "UserGroups": {
                "default": {
                    "errorPath": "./config/error.txt",
                    "sslCert": {
                        "cert": "./config/ssl/cert.pem",
                        "key": "./config/ssl/key.pem",
                        "ca": "./config/ssl/ca.pem"
                    }
                }
            }
        }
        
        with open("./config/config.json", "w", encoding="utf-8") as f:
            json.dump(defaultConfig, f, indent=4)

        with open("./config/error.txt", "w", encoding="utf-8") as f:
            f.write("""Date: $TIME
From: <$MAIL_FROM>
To: <$MAIL_TO>
Message-ID: <$ERROR_MAIL_ID@$USERGROUP_DOMAIN>
Subject: $TITLE
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;">
    <h2 style="color: #d32f2f; margin-bottom: 20px;">Mail Delivery Failed</h2>
    
    <div style="background: #fff; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
        <p style="color: #333; line-height: 1.5;">We were unable to deliver your message to:</p>
        <p style="color: #666; margin: 10px 0; padding: 10px; background: #f5f5f5; border-left: 4px solid #d32f2f;">
            <strong>$RECIPIENT</strong>
        </p>
    </div>

    <div style="color: #666; line-height: 1.6;">
        <p>The recipient's email address was not found on this server.</p>
        <p>Please check the recipient's email address and try again.</p>
    </div>

    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 12px;">
        This is an automatically generated message.
    </div>
</div>""")

    # Ensure localMX.json exists with default common providers
    local_mx_path = os.path.join("./config", "localMX.json")
    if not os.path.exists(local_mx_path):
        default_local_mx = {
            "163.com": {"smtp": "smtp.163.com", "ports": [25, 465]},
            "126.com": {"smtp": "smtp.126.com", "ports": [25]},
            "139.com": {"smtp": "smtp.139.com", "ports": [25]},
            "qq.com": {"smtp": "smtp.qq.com", "ports": [25, 465, 587]},
            "gmail.com": {"smtp": "smtp.gmail.com", "ports": [587, 465]},
            "sina.com": {"smtp": "smtp.sina.com", "ports": [25]},
            "sohu.com": {"smtp": "smtp.sohu.com", "ports": [25]},
            "yahoo.com": {"smtp": "smtp.mail.yahoo.cn", "ports": [25, 465]},
            "hotmail.com": {"smtp": "smtp.live.com", "ports": [25]},
            "263.net": {"smtp": "smtp.263.net", "ports": [25]}
        }
        try:
            with open(local_mx_path, 'w', encoding='utf-8') as f:
                json.dump(default_local_mx, f, indent=2)
        except Exception:
            pass
    # Ensure global temp path and wMailServerSettings
    try:
        cfg_dir = os.path.join('.', 'config')
        # default temp path under workspace
        default_temp = os.path.join('.', 'temp')
        # ensure top-level settings key
        # load config if exists to merge later
    except Exception:
        pass
            
def init():
    """初始化配置"""
    global config
    checkConf()
    with open("./config/config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    # Ensure some higher-level defaults for wMailServerSettings and POP3Settings
    defaults = {
        'wMailServerSettings': {
            'tempPath': os.path.join('.', 'temp'),
            'ipMaxPwdTry': 5,
            # ip block seconds for password failures
            'ipBlockSeconds': 3600,
            # max consecutive command errors before temporary block
            'maxCmdError': 5,
            'cmdBlockSeconds': 60
        },
        'POP3Services': {
            'settings': {
                'maxSpeed': 1
            }
        }
    }
    try:
        ensureDefaults(defaults)
    except Exception:
        pass

def get(key, default=None):
    """获取配置项"""
    global config
    if not config:
        init()
    return config.get(key, default)

def save():
    """保存配置"""
    global config
    if config:
        with open("./config/config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)


def ensureDefaults(defaults: dict):
    """递归地确保配置文件包含 defaults 指定的键和值；缺失时写入并保存。返回 True 如果有更新。"""
    global config
    if not config:
        init()

    def merge(dst, src):
        changed = False
        for k, v in src.items():
            if k not in dst:
                dst[k] = v
                changed = True
            else:
                if isinstance(v, dict) and isinstance(dst.get(k), dict):
                    sub_changed = merge(dst[k], v)
                    changed = changed or sub_changed
        return changed

    updated = merge(config, defaults)
    if updated:
        save()
    return updated