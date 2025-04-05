import time
import threading
import datetime

# optional logger (set by services via AuthTracker.init(log))
loginfo = None

# 简单的内存追踪器：IP -> {'fails': int, 'blocked_until': ts}
_lock = threading.Lock()
_store = {}

# 配置驱动的阈值，默认值会由 Configure.init() 写入配置后读取
DEFAULT_MAX_TRIES = 5
DEFAULT_BLOCK_SECONDS = 3600


def _now():
    return int(time.time())


def record_failure(ip, max_tries=DEFAULT_MAX_TRIES, block_seconds=DEFAULT_BLOCK_SECONDS):
    if not ip:
        return
    with _lock:
        ent = _store.get(ip)
        if not ent:
            ent = {'fails': 0, 'blocked_until': 0, 'block_seconds': 0}
            _store[ip] = ent
        ent['fails'] += 1
        if ent['fails'] >= int(max_tries):
            ent['block_seconds'] = int(block_seconds)
            ent['blocked_until'] = _now() + int(block_seconds)
            # log detail if logger provided
            try:
                if loginfo:
                    ts = datetime.datetime.fromtimestamp(ent['blocked_until']).isoformat()
                    loginfo.write(f"[AuthTracker] IP {ip} blocked for {ent['block_seconds']}s until {ts} (fails={ent['fails']})")
            except Exception:
                pass


def record_success(ip):
    if not ip:
        return
    with _lock:
        if ip in _store:
            # reset failures on success
            _store.pop(ip, None)


def is_blocked(ip):
    if not ip:
        return False
    with _lock:
        ent = _store.get(ip)
        if not ent:
            return False
        if ent.get('blocked_until', 0) > _now():
            return True
        # expired -> clear
        if ent.get('blocked_until', 0) and ent.get('blocked_until', 0) <= _now():
            _store.pop(ip, None)
            return False
        return False


def get_info(ip):
    with _lock:
        ent = _store.get(ip, None)
        if not ent:
            return None
        # return a shallow copy to avoid external mutation
        return dict(ent)


def block_ip(ip, seconds=60):
    """Force-block an IP for given seconds."""
    if not ip:
        return
    with _lock:
        ent = _store.get(ip)
        if not ent:
            ent = {'fails': 0, 'blocked_until': 0, 'block_seconds': 0}
            _store[ip] = ent
        ent['block_seconds'] = int(seconds)
        ent['blocked_until'] = _now() + int(seconds)
        try:
            if loginfo:
                ts = datetime.datetime.fromtimestamp(ent['blocked_until']).isoformat()
                loginfo.write(f"[AuthTracker] IP {ip} force-blocked for {ent['block_seconds']}s until {ts}")
        except Exception:
            pass


def unblock_ip(ip):
    """Remove any block/failure record for a single IP."""
    if not ip:
        return
    with _lock:
        _store.pop(ip, None)


def clear_all():
    """Clear all tracked failures and blocks (admin/debug use)."""
    with _lock:
        _store.clear()


def list_blocks():
    """Return a snapshot dict of current tracked entries."""
    with _lock:
        # return copies
        return {k: dict(v) for k, v in _store.items()}


def init(log):
    """Initialize optional logger for AuthTracker. Pass the same log object used by services."""
    global loginfo
    loginfo = log
