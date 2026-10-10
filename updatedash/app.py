#!/usr/bin/env python3
"""updatedash entry point.

  app.py                  run the dashboard
  app.py hash-password    read a password from stdin (or prompt) and print a hash for `password_hash`
  app.py check-config     validate the config and exit
"""
import getpass
import logging
import sys

from udash.auth import hash_password
from udash.config import ConfigError, load_config


def main(argv):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd == "hash-password":
        pw = sys.stdin.read().rstrip("\n") if not sys.stdin.isatty() else getpass.getpass("Password: ")
        if len(pw) < 10:
            sys.exit("password must be at least 10 characters")
        print(hash_password(pw))
        return 0
    try:
        cfg = load_config()
    except ConfigError as e:
        sys.exit(f"config error: {e}")
    if cmd == "check-config":
        print("config OK")
        return 0
    if cmd != "serve":
        sys.exit(__doc__)
    from udash.server import App, serve
    from udash.auth import AuthError
    try:
        app = App(cfg)
    except AuthError as e:
        sys.exit(f"config error: {e}")
    return serve(app)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
