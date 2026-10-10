#!/bin/sh
# Used by ssh (SSH_ASKPASS) to supply a stored password or key passphrase without a terminal.
printf '%s\n' "$UPDATEDASH_ASKPASS_VALUE"
