# Changelog

## 1.0.0
* Rebuilt as a package (`udash/`) with a test suite (52 tests incl. real sshd) and CI.
* Per-container direct SSH access (password or key) with a Test button; add non-Proxmox hosts by SSH. Credentials are
  encrypted at rest.
* Update logs stored on disk with a retention setting (per container) in the GUI; log history per container.
* "Update" only when relevant; version arrows and release links; release-notes preview.
* Sign-in page with signed sessions, hashed passwords, lockout, password change, audit log; HTTPS option.
* GUI management of the Proxmox allow list, protected-container list, queued/cancellable updates, graceful shutdown.
* Fixes: community-script updates run unattended (`PHS_SILENT=1`, `TERM=xterm`); port 0 was treated as 22; sessions
  survived restarts; same-second audit entries were reordered.
