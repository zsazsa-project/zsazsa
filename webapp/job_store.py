"""State of the background jobs the web app runs, kept in Redis.

Analyser runs, cache refreshes and bulk AI summaries are started on a worker
thread so the browser gets an answer straight away. Their state lives in Redis
rather than in the process, which means an analyst can leave the page, come
back, or open the app in another tab and still see what is running and how it
ended. Settings are the JOB_REDIS_* entries in config; when Redis is not
reachable the jobs are kept in memory instead, so the app still works, only
without the sharing. If Redis disappears while a job runs, that job's progress
stops being updated until it is back, which is a status display losing detail
rather than work being lost.

Every job is one field of a single Redis hash, holding the JSON below:

    id, action, label, status (queued|running|completed|failed), message,
    steps [{id, label, state}], log [{timestamp, message}], result, error,
    created_at, updated_at
"""

import copy
import json
import logging
import socket
import threading
import time
from contextlib import contextmanager
from uuid import uuid4

import config
from webapp.redis_client import RedisError, read_reply, send_command

logger = logging.getLogger(__name__)

# Jobs an instance keeps before the oldest are dropped, and how long the hash
# survives without a write.
_MAX_JOBS = 40
_TTL_SECONDS = 24 * 3600
# After a failed connection, wait before trying Redis again, so a host without
# it does not pay a connection timeout on every job update and every poll.
_RETRY_AFTER_SECONDS = 60

_memory: dict[str, dict] = {}
_memory_lock = threading.Lock()
_redis_down_until = 0.0


def _hash_key() -> str:
    return getattr(config, "JOB_REDIS_KEY", "zsazsa:jobs")


def _connect():
    """Socket to the job Redis, authenticated and on the right database."""
    host = getattr(config, "JOB_REDIS_HOST", "127.0.0.1")
    port = int(getattr(config, "JOB_REDIS_PORT", 6379) or 6379)
    db = getattr(config, "JOB_REDIS_DB", 0)
    username = getattr(config, "JOB_REDIS_USERNAME", "")
    password = getattr(config, "JOB_REDIS_PASSWORD", "")

    sock = socket.create_connection((host, port), timeout=2)
    try:
        if password:
            if username:
                send_command(sock, "AUTH", username, password)
            else:
                send_command(sock, "AUTH", password)
            read_reply(sock)
        if db:
            send_command(sock, "SELECT", db)
            read_reply(sock)
        return sock
    except (OSError, RedisError):
        sock.close()
        raise


def _command(*args):
    """Run one Redis command. Returns its reply, or None when Redis is down.

    A missing hash field also answers None, so callers treat "no such job" and
    "no Redis" the same way: look in memory, then give up.
    """
    global _redis_down_until
    if time.time() < _redis_down_until:
        return None
    try:
        sock = _connect()
    except (OSError, RedisError) as exc:
        if not _redis_down_until:
            logger.warning("Job Redis unavailable (%s); keeping jobs in memory", exc)
        _redis_down_until = time.time() + _RETRY_AFTER_SECONDS
        return None
    try:
        send_command(sock, *args)
        reply = read_reply(sock)
        _redis_down_until = 0.0
        return reply
    except (OSError, RedisError) as exc:
        logger.warning("Job Redis command %s failed: %s", args[0], exc)
        _redis_down_until = time.time() + _RETRY_AFTER_SECONDS
        return None
    finally:
        sock.close()


def _load(job_id: str) -> dict | None:
    raw = _command("HGET", _hash_key(), job_id)
    if raw is not None:
        try:
            return json.loads(raw)
        except ValueError:
            logger.warning("Job %s holds invalid JSON; dropping it", job_id[:8])
            _command("HDEL", _hash_key(), job_id)
            return None
    with _memory_lock:
        job = _memory.get(job_id)
        return copy.deepcopy(job) if job else None


def _save(job: dict) -> None:
    job["updated_at"] = time.time()
    key = _hash_key()
    if _command("HSET", key, job["id"], json.dumps(job)) is None:
        with _memory_lock:
            _memory[job["id"]] = job
        return
    # Redis holds the job now. Drop any copy left in memory by an earlier
    # outage, or the next outage would serve that stale version instead.
    with _memory_lock:
        _memory.pop(job["id"], None)
    _command("EXPIRE", key, _TTL_SECONDS)


def forget_job(job_id: str) -> None:
    """Drop a job, for work that turned out to have nothing to report."""
    with _memory_lock:
        _memory.pop(job_id, None)
    _command("HDEL", _hash_key(), job_id)


def create_job(action: str, label: str = "", steps: list[dict] | None = None) -> dict:
    """Register a queued job, drop the oldest ones, and return it."""
    now = time.time()
    job = {
        "id": uuid4().hex,
        "action": action,
        "label": label or action,
        "status": "queued",
        "message": "Queued",
        "steps": steps or [],
        "log": [{"timestamp": now, "message": "Job queued."}],
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
    }
    _save(job)
    for old in list_jobs()[_MAX_JOBS:]:
        forget_job(old["id"])
    return job


def get_job(job_id: str) -> dict | None:
    return _load(job_id)


def update_job(job_id: str, **fields) -> None:
    job = _load(job_id)
    if not job:
        return
    job.update(fields)
    _save(job)


def append_log(job_id: str, message: str) -> None:
    job = _load(job_id)
    if not job:
        return
    job.setdefault("log", []).append({"timestamp": time.time(), "message": message})
    job["log"] = job["log"][-50:]
    _save(job)
    logger.info("[job:%s] %s", job_id[:8], message)


def thread_name(job_id: str) -> str:
    """Name for the worker thread of a job, so it can be found again later.

    Whether such a thread is alive is the only trustworthy answer to "is this
    job still working or did its process die", so the name has to be derivable
    from the job id alone.
    """
    return f"job-{job_id[:8]}"


def worker_alive(job_id: str) -> bool:
    """True when this process still has a live worker for that job."""
    name = thread_name(job_id)
    return any(t.name == name and t.is_alive() for t in threading.enumerate())


@contextmanager
def heartbeat(job_id: str, message: str, every_s: int = 60):
    """Keep saying a job is alive while one long call blocks its thread.

    An LLM call returns nothing until it is done, and on a local model that can
    be many minutes. Without this the job's last write ages until the top bar
    calls it stalled, which is the opposite of what is happening. The message
    gains the elapsed time, so a slow job looks slow rather than dead.
    """
    started = time.time()
    done = threading.Event()

    def tick():
        while not done.wait(every_s):
            # Checked again on the way out of the wait: the call can have
            # finished and written its own last message in the meantime, and
            # overwriting that with "still running" would be a lie that sticks.
            if done.is_set():
                return
            minutes = int((time.time() - started) / 60)
            update_job(job_id, message=f"{message} (running {minutes}m)")

    ticker = threading.Thread(target=tick, daemon=True, name=f"heartbeat-{job_id[:8]}")
    ticker.start()
    try:
        yield
    finally:
        done.set()


def set_step(job_id: str, step: str, state: str, message: str = "") -> None:
    job = _load(job_id)
    if not job:
        return
    for row in job.get("steps", []):
        if row.get("id") == step:
            row["state"] = state
            break
    if message:
        job["message"] = message
        job.setdefault("log", []).append({"timestamp": time.time(), "message": message})
        job["log"] = job["log"][-50:]
    _save(job)
    if message:
        logger.info("[job:%s] %s: %s", job_id[:8], step, message)


def complete_open_steps(job_id: str) -> None:
    """Mark steps still in progress as done, for a job that has finished."""
    job = _load(job_id)
    if not job:
        return
    for row in job.get("steps", []):
        if row.get("state") == "in_progress":
            row["state"] = "completed"
    _save(job)


def list_jobs() -> list[dict]:
    """Every known job, newest first."""
    reply = _command("HGETALL", _hash_key())
    if reply is None:
        # No Redis. An empty hash answers with an empty list instead, which must
        # not fall back to memory or jobs already dropped would come back.
        with _memory_lock:
            jobs = copy.deepcopy(list(_memory.values()))
    else:
        # HGETALL answers as a flat [field, value, field, value, ...] list.
        jobs = []
        for raw in reply[1::2]:
            try:
                jobs.append(json.loads(raw))
            except ValueError:
                continue
    return sorted(jobs, key=lambda j: j.get("created_at", 0), reverse=True)


def forget_finished(statuses=("completed", "failed")) -> int:
    """Drop the entries for jobs in these states and return how many went.

    Only the record is dropped. A queued or running job keeps its entry
    whatever is asked for here, since there is no worker to call back.
    """
    gone = 0
    for job in list_jobs():
        if job.get("status") in statuses:
            forget_job(job["id"])
            gone += 1
    return gone


def forget_abandoned(older_than_s: float) -> int:
    """Drop queued or running entries untouched for that long, and count them.

    For a worker that died with its process: nothing will ever move those jobs
    off "running". The caller picks a wait long enough that work which is merely
    slow between two progress messages keeps its entry.
    """
    cutoff = time.time() - older_than_s
    gone = 0
    for job in list_jobs():
        if job.get("status") in ("queued", "running") and job.get("updated_at", 0) < cutoff:
            forget_job(job["id"])
            gone += 1
    return gone
