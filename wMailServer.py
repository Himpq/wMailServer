import Configure, SMTPService, UserManager, DebugLog, POP3Service
import time, threading
import sys, traceback

def init_services():
    """Initialize all required modules and return success status"""
    Configure.checkConf()
    DebugLog.init()
    UserManager.initModule()
    SMTPService.initModule(DebugLog, Configure)
    POP3Service.initModule(DebugLog, Configure)
    DebugLog.write("All modules initialized successfully")
    return True

def start_smtp_services():
    """Start all configured SMTP services"""
    smtp_services = Configure.get("SMTPServices").get("services", {})
    
    for port, config in smtp_services.items():
        try:
            sslEnabled = config.get("ssl", False)
            userGroup  = config["userGroup"]
            
            DebugLog.write(f"[SMTP] port={port} ssl={sslEnabled} userGroup={userGroup}")
            
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