"""Container entry point: make the shared runs volume writable, then drop root.

The volume may have been created by the backend (read-only mount) before this
container first started, in which case it belongs to root. Fix ownership, then
run the service as the unprivileged `runner` user.
"""

import os
import pwd

WORK = os.environ.get("RUNNER_WORK_DIR", "/runs")
user = pwd.getpwnam("runner")
os.makedirs(os.path.join(WORK, "traces"), exist_ok=True)
for root, dirs, files in os.walk(WORK):
    for name in [root, *(os.path.join(root, d) for d in dirs), *(os.path.join(root, f) for f in files)]:
        os.chown(name, user.pw_uid, user.pw_gid)
os.setgroups([])
os.setgid(user.pw_gid)
os.setuid(user.pw_uid)
os.environ["HOME"] = user.pw_dir
os.execvp("uvicorn", ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1"])
