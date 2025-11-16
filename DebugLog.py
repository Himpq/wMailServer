
import os
import time
import re
import threading

file = None
# mapping like {'SMTP': '25', 'POP3': '110'} (strings)
service_ports = {}
pad_char = '_'
_lock = threading.Lock()
isAutoCleanerRunning = False

def autoCleaner():
    global isAutoCleanerRunning
    isAutoCleanerRunning = True
    while 1:
        with _lock:
            size = os.path.getsize("./logs/wmailserver.log") if os.path.isfile("./logs/wmailserver.log") else 0
            size2 = os.path.getsize("./logs/output.log") if os.path.isfile ("./logs/output.log") else 0
            avr = (size+size2)/2

            

            if avr > 20000:
                try:

                    file.close()

                    os.remove("./logs/wmailserver.log")
                    os.remove("./logs/output.log")

                    init()

                    write("[DebugLog_] Autocleaner did its job.")
                except Exception as e:
                    print("[DebugLog_] Cannot clean logs:", str(e))

        time.sleep(60)



def getTime():
    return time.strftime("%m-%d %H:%M:%S", time.localtime())


def init():
    """Open the log file. Call once during startup. This is intentionally
    minimal: we create the logs directory and open the file for append. If
    opening the file fails we let the exception propagate so the caller can
    decide — no nested defensive checks here.
    """
    global file
    os.makedirs("./logs", exist_ok=True)
    file = open("./logs/wmailserver.log", 'a', encoding='utf-8')

    if not isAutoCleanerRunning:
        threading.Thread(target=autoCleaner).start()



def set_service_ports(mapping, padchar='_'):
    """Provide a mapping of service name -> port (strings or ints).

    Example: set_service_ports({'SMTP': 25, 'POP3': 110}, padchar='_')
    The padchar is used to left-pad shorter port strings when aligning.
    """
    global service_ports, pad_char
    pad_char = padchar
    service_ports = {str(k).upper(): str(v) for k, v in (mapping or {}).items()}


def _apply_prefixes(msg: str) -> str:
    if not service_ports:
        return msg
    try:
        max_len = max((len(v) for v in service_ports.values()))
    except Exception:
        return msg

    out = msg
    for svc, port in service_ports.items():
        padded = port.rjust(max_len, pad_char)
        # replace only occurrences of [SERVICE] that are not already like [SERVICE:...]
        pattern = r"\[" + re.escape(svc) + r"\](?!:)"
        out = re.sub(pattern, f"[{svc}:{padded}]", out)

    return out


def write(*args):
    """Simple, thread-safe logger.

    - Assumes `init()` was called once at startup. We keep the implementation
      compact: serialize writes with a lock, write to the file if available
      and flush. On IO error we fall back to printing to stdout. No nested
      try/except blocks or redundant checks.
    """
    raw = " ".join(list(args)) if args else ""
    out = _apply_prefixes(raw)
    ts = getTime()
    line = f"[{ts}] " + out + "\n"

    with _lock:
        if file:
            try:
                file.write(line)
                file.flush()
                # also print for live visibility
                print(out)
                return
            except Exception:
                # fallback to stdout if file write fails
                pass
    # If file isn't available or write failed, print to stdout
    print(out)


def save():
    """Compatibility: flush logfile if open."""
    with _lock:
        if file:
            file.flush()