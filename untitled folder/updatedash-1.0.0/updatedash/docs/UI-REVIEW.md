# UI review

Reviewed in dark and light mode, at desktop (800–1100 px) and phone (375 px) widths, by using the real screens
(sign-in, list, access dialog with a live SSH test, manage, logs, settings, update confirmation, toasts).
Findings that were fixed during the review are marked ✔; the rest are recommendations, most valuable first.

## Done in this version
* ✔ Real sign-in page and sign-out (replaces the browser's basic-auth popup); lockout and session messages in plain words.
* ✔ "Needs action first" sort, search (`/` focuses it), "needs action only" filter; choices are remembered.
* ✔ **Update** is offered only when there is something to update, or when the version can't be read; it is quiet (not
  primary) in that second case so real updates stand out. No more "Update anyway" on up-to-date apps.
* ✔ Version shown as `installed → new ↗` with a release-notes link; the confirmation shows the notes and whether a
  snapshot will be taken.
* ✔ Per-container **Access** dialog with Test connection (reports user, root/sudo, OS, host-key fingerprint, and a
  specific hint for the common failures).
* ✔ Log history per container, retention in Settings, **Copy log** that works over plain HTTP.
* ✔ Phone layout (cards instead of a wide table); status is always text, never colour alone; native `<dialog>` for focus
  trapping; labels on every control; visible focus; reduced-motion respected.
* ✔ Found while testing: `hidden` fields were showing in the Access dialog (CSS override), long versions broke
  mid-number, the "via Proxmox" label cluttered every row, and a restart signed everyone out. All fixed.

## Recommended next
1. **Update all available** with one confirmation and a visible queue (the engine already limits parallelism).
   Add row checkboxes for "update selected".
2. **Scheduling and policy**: maintenance windows, and per-container rules (auto-update Sonarr nightly, never auto-update
   Vaultwarden/Tailscale, always snapshot). Today everything is manual by design.
3. **Notifications** when updates are found or an update fails (ntfy, Gotify, Discord, email). Most useful if you don't
   open the page daily.
4. **One-click rollback**: list a container's `pre-update-*` snapshots and roll back from the UI. Needs one more gate
   command (`pct rollback`); I left it out because it is destructive, so make it opt-in like GUI management.
5. **Groups/tags** (Media, Infrastructure, Security) with collapsible sections and group-level actions; clickable chips
   (click "2 app updates" to filter).
6. **Live logs without polling**: stream with Server-Sent Events, and expand the log inside the row instead of one
   panel at the bottom of the page (it is easy to miss on a long list).
7. **Phone toolbar**: six controls wrap onto four rows. Collapse secondary ones (Settings, Sign out, Check all) into a
   menu, and make the table header sticky on desktop.
8. **First-run checklist**: "Proxmox gate reachable ✔ / allow list has N containers / password set / HTTPS in front".
   New users currently learn about the gate only from the docs.
9. **Update history view**: a timeline across containers (what was updated when, by whom, result) built from the
   existing logs and audit trail; show "last updated" in the row.
10. **Accessibility pass**: run an automated audit (axe) and a screen-reader walkthrough; add a skip link target for the
    dialogs; announce long-running job completion (the toast region is already `aria-live`).
11. **Density and theme**: compact/comfortable toggle and an explicit light/dark switch (it follows the OS today).
12. **Per-row notes and pinning**: "never update before the weekend", "pinned at 2.x because of X".
