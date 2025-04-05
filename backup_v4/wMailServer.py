import Configure, SMTPService, UserManager, DebugLog, POP3Service
import time, threading
import sys, traceback

def init_services():
    """Initialize all required modules and return success status"""
    Configure.checkConf()
    # Ensure new default configuration keys are present (camelCase keys)
    defaults = {
        "SMTPServices": {
            "MailRelay": {
                "timeout": 5
            }
        },
        "SMTPSettings": {
            "starttlsEnable": True,
            "disableSslPorts": False
        },
        "mailTry": ["relay", "direct"]
    }
    try:
        Configure.ensureDefaults(defaults)
    except Exception:
        pass
    # Ensure SMTPWhiteList config exists (whitelist/blacklist patterns)
    try:
        # Ensure nested keys exist and persist defaults using Configure.ensureDefaults
        Configure.ensureDefaults({'SMTPServices': {'SMTPWhiteList': {'mode': 'disable', 'whitelist': [], 'blacklist': []}}})
        smtp_services = Configure.get('SMTPServices', {})
        sw = smtp_services.get('SMTPWhiteList', {})
        # normalize placement of lists if specified at top-level keys
        wl = sw.get('whitelist') or smtp_services.get('whitelist') or []
        bl = sw.get('blacklist') or smtp_services.get('blacklist') or []
        mode = sw.get('mode') or smtp_services.get('mode') or 'disable'
        # write normalized structure back and save
        smtp_services['SMTPWhiteList'] = {'mode': mode, 'whitelist': wl, 'blacklist': bl}
        Configure.save()
        DebugLog.write(f"[wMailServer] SMTPWhiteList loaded/normalized: mode={mode} whitelist={len(wl)} patterns, blacklist={len(bl)} patterns")
    except Exception as e:
        DebugLog.write(f"[wMailServer] Error ensuring SMTPWhiteList in config: {e}")
    DebugLog.init()
    UserManager.initModule()
    SMTPService.initModule(DebugLog, Configure)
    POP3Service.initModule(DebugLog, Configure)
    DebugLog.write("All modules initialized successfully")
    return True

def start_smtp_services():
    """Start all configured SMTP services"""
    smtp_services = Configure.get("SMTPServices").get("services", {})
    # 将配置中的超时注入到 SMTPService 模块（如果存在）
    # 连接/IO 超时应由 SMTPServices.settings 中的 timeout / ioTimeout 控制。
    # 避免从 MailRelay 中读取 timeout 并覆盖全局设置，以免混淆。

    # 全局 SMTP 设置（例如是否强制禁用 ssl 端口）
    smtp_settings = Configure.get('SMTPSettings', {})
    
    for port, config in smtp_services.items():
        try:
            sslEnabled = config.get("ssl", False)
            # 如果全局配置要求禁用 ssl 端口，则强制关闭
            if smtp_settings.get('disable_ssl_ports'):
                sslEnabled = False
            userGroup  = config["userGroup"]
            
            DebugLog.write(f"[SMTP] port={port} ssl={sslEnabled} userGroup={userGroup}")

            # inform DebugLog of the mapping so it can render [SMTP] as [SMTP:PORT]
            try:
                # accumulate mapping (keep existing ones)
                existing = {}
                try:
                    existing = getattr(DebugLog, 'service_ports', {})
                except Exception:
                    existing = {}
                existing.update({"SMTP": str(port)})
                try:
                    DebugLog.set_service_ports(existing)
                except Exception:
                    pass
            except Exception:
                pass

            smtp = SMTPService.SMTPService("0.0.0.0", int(port), userGroup, sslEnabled)
            smtp_thread = threading.Thread(target=smtp.startListen, 
                                        name=f"SMTP-{port}")
            smtp_thread.daemon = True
            smtp_thread.start()
            
        except Exception as e:
            DebugLog.write(f"[SMTP] {port}: {traceback.format_exc()}")

def start_pop3_services():
    """Start all configured POP3 services"""
    pop3Services = Configure.get("POP3Services").get("services", {})
    
    for port, config in pop3Services.items():
        try:
            sslEnabled = config.get("ssl", False)
            userGroup  = config["userGroup"]
            
            DebugLog.write(f"[POP3] port={port} ssl={sslEnabled} userGroup={userGroup}")
            try:
                existing = {}
                try:
                    existing = getattr(DebugLog, 'service_ports', {})
                except Exception:
                    existing = {}
                existing.update({"POP3": str(port)})
                try:
                    DebugLog.set_service_ports(existing)
                except Exception:
                    pass
            except Exception:
                pass
            
            pop3 = POP3Service.POP3Service("0.0.0.0", int(port), userGroup, sslEnabled)
            pop3Thread = threading.Thread(target=pop3.startListen, name=f"POP3-{port}")
            pop3Thread.daemon = True
            pop3Thread.start()
            
            DebugLog.write(f"POP3 service successfully started on port {port}")
        except Exception as e:
            DebugLog.write(f"[POP3] {port}: {traceback.format_exc()}")

def main():

    DebugLog.write("==========================================================")
    DebugLog.write("Initializing wMailServer...")
    DebugLog.write("==========================================================")

    if not init_services():
        sys.exit(1)
    
    start_smtp_services()
    start_pop3_services()
    
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            DebugLog.write("Received shutdown signal. Stopping server...")
            break
        except Exception as e:
            DebugLog.write(f"Unexpected error in main loop: {str(e)}")
            break

if __name__ == "__main__":
    main()