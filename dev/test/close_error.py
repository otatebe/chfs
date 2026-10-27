# usage: python3 close_error.py file ready_file go_file
#
# Writes data to a file in the CHFS mount point, creates ready_file, and
# waits for go_file, which is created after all CHFS servers are stopped.
# Then checks that close(2) reports the write-back error.
#
# No child process is created while the file is open, since closing the
# file descriptor in a child process also flushes the data.
import os
import sys
import time

path, ready, go = sys.argv[1:4]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"hello")
open(ready, "w").close()
for _ in range(600):
    if os.path.exists(go):
        break
    time.sleep(0.1)
else:
    print("timeout")
    sys.exit(2)
try:
    os.close(fd)
except OSError as e:
    print(f"close returns -1: {os.strerror(e.errno)}")
    print("OK")
    sys.exit(0)
print("close returns 0")
print("FAIL")
sys.exit(1)
