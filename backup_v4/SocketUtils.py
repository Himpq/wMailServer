import socket
import os


def safe_dup_socket(conn, connfile=None, log=None):
    """Duplicate a socket's FD and return a new socket object.

    This implementation keeps error handling simple and logs relevant
    failures via the optional `log` object. On failure the original
    `conn` is returned. If `connfile` is provided it will be closed
    (best-effort) before creating the new socket from the duplicated FD.
    """
    # get original fileno
    try:
        orig_fd = conn.fileno()
    except Exception as e:
        if log:
            try:
                log.write(f"[DBG][SocketUtils] fileno() failed: {e}")
            except Exception:
                pass
        # ensure connfile closed if present
        if connfile is not None:
            try:
                connfile.close()
            except Exception:
                pass
        return conn

    if log:
        try:
            log.write(f"[DBG][SocketUtils] orig_fd={orig_fd} (about to dup)")
        except Exception:
            pass

    # duplicate FD
    try:
        new_fd = os.dup(orig_fd)
    except Exception as e:
        if log:
            try:
                log.write(f"[DBG][SocketUtils] os.dup failed: {e}")
            except Exception:
                pass
        if connfile is not None:
            try:
                connfile.close()
            except Exception:
                pass
        return conn

    if log:
        try:
            log.write(f"[DBG][SocketUtils] new_fd={new_fd} (dup created)")
        except Exception:
            pass

    # close the buffered file wrapper (may close orig_fd)
    if connfile is not None:
        try:
            connfile.close()
            if log:
                try:
                    log.write(f"[DBG][SocketUtils] connfile closed")
                except Exception:
                    pass
        except Exception as e:
            if log:
                try:
                    log.write(f"[DBG][SocketUtils] connfile.close() exception: {e}")
                except Exception:
                    pass

    # try to build new socket from duplicated fd
    try:
        new_conn = socket.socket(fileno=new_fd)
        if log:
            try:
                log.write(f"[DBG][SocketUtils] created new socket from new_fd fileno={new_conn.fileno()}")
            except Exception:
                pass
        return new_conn
    except Exception as e:
        if log:
            try:
                log.write(f"[DBG][SocketUtils] failed to create socket from new_fd={new_fd}: {e}")
            except Exception:
                pass
        # close duplicated fd to avoid leak
        try:
            os.close(new_fd)
        except Exception:
            pass
        return conn


def make_connfile(conn, mode='r', encoding='utf-8'):
    """Create a text-file wrapper for the socket. Centralized makefile calls."""
    try:
        return conn.makefile(mode, encoding=encoding)
    except Exception:
        return None
