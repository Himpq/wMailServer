import socket

# Minimal IMAPService placeholder to prepare for future implementation.
# This file intentionally keeps a tiny, importable skeleton so other modules
# can reference IMAPService during transition without runtime import errors.

loginfo = None
conf = None


def initModule(log, cfg):
    global loginfo, conf
    loginfo = log
    conf = cfg
    try:
        loginfo.write('[IMAP] IMAPService placeholder initialized')
    except Exception:
        pass


class IMAPService:
    def __init__(self, bindIP, port, userGroup, ssl=False):
        self.bindIP = bindIP
        self.port = port
        self.userGroup = userGroup
        self.useSSL = ssl
        # Not implemented: this is a placeholder for future IMAP implementation.

    def startListen(self):
        raise NotImplementedError('IMAPService not implemented yet')
