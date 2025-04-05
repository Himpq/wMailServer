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
                    ]
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
            
def init():
    """初始化配置"""
    global config
    checkConf()
    with open("./config/config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

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