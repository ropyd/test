(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);

  // ---------------------------------------------------------------- helpers
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids) if (kid != null && kid !== false) n.append(kid);
    return n;
  }
  const ext = (href, text) => el('a', { href, target: '_blank', rel: 'noopener noreferrer', text });

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { 'X-Requested-With': 'updatedash', 'Content-Type': 'application/json' },
    });
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    if (res.status === 401) { location.replace('/login'); throw new Error('Signed out'); }
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }
  const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });

  function toast(msg, kind) {
    const t = el('div', { class: 'toast' + (kind === 'bad' ? ' bad' : ''), text: msg });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), kind === 'bad' ? 8000 : 4500);
  }
  const fail = (e) => toast(e.message || String(e), 'bad');

  function ago(ts) {
    if (!ts) return 'never';
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }
  const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '–');
  const store = {
    get(k, d) { try { const v = localStorage.getItem('ud.' + k); return v === null ? d : v; } catch { return d; } },
    set(k, v) { try { localStorage.setItem('ud.' + k, v); } catch { /* storage blocked */ } },
  };

  function ask(title, body, okLabel, extra) {
    const dlg = $('#confirm');
    $('#confirmTitle').textContent = title;
    $('#confirmBody').textContent = body;
    $('#confirmOk').textContent = okLabel;
    $('#confirmExtra').replaceChildren(...(extra || []));
    return new Promise((resolve) => {
      dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), { once: true });
      dlg.returnValue = 'cancel';
      dlg.showModal();
    });
  }

  // ---------------------------------------------------------------- state
  let data = null;
  let busyPoll = false;
  let timer = null;
  const ui = {
    only: store.get('only', '0') === '1',
    sort: store.get('sort', 'action'),
    q: '',
  };
  $('#onlyAction').checked = ui.only;
  $('#sort').value = ui.sort;

  const STATUS = {
    update: ['Update available', 'update'],
    current: ['Up to date', 'current'],
    unknown: ['Version unknown', ''],
    error: ['Unreachable', 'error'],
    stopped: ['Stopped', 'stopped'],
    os: ['OS updates only', 'os'],
    nocheck: ['No app check', 'nocheck'],
  };
  const QUIET = new Set(['current', 'nocheck', 'stopped']);
  const PRIORITY = { update: 0, error: 1, os: 2, unknown: 3, current: 4, nocheck: 5, stopped: 6 };

  // ---------------------------------------------------------------- main table
  function visible(list) {
    let rows = list.filter((s) => {
      if (ui.only && QUIET.has(s.status) && !s.running) return false;
      if (ui.q) {
        const hay = `${s.name} ${s.ctid} ${(s.access && s.access.host) || ''}`.toLowerCase();
        if (!hay.includes(ui.q)) return false;
      }
      return true;
    });
    const by = {
      id: (a, b) => a.ctid - b.ctid,
      name: (a, b) => a.name.localeCompare(b.name),
      action: (a, b) => (a.running === b.running ? 0 : a.running ? -1 : 1) ||
        (PRIORITY[a.status] ?? 9) - (PRIORITY[b.status] ?? 9) || a.name.localeCompare(b.name),
    };
    return rows.sort(by[ui.sort] || by.id);
  }

  function accessBadge(s) {
    const a = s.access || {};
    if (a.mode !== 'ssh') return null;               // the default (through the Proxmox host) needs no label
    const mark = a.tested_ok === true ? ['✔', 'okc', 'login tested OK'] : a.tested_ok === false ? ['✖', 'badc', 'last login test failed'] : ['?', '', 'not tested'];
    return el('span', { class: 'sub' }, ` · SSH ${a.user}@${a.host}`,
      el('span', { class: 'access ' + mark[1], title: mark[2], 'aria-label': mark[2], text: mark[0] }));
  }

  function row(s) {
    const [label, cls] = STATUS[s.status] || STATUS.unknown;
    const stopped = s.status === 'stopped';
    const upd = s.status === 'update';

    const nameCell = el('td', { class: 'name', 'data-label': 'Container' },
      el('div', { class: 'svc', text: s.name }),
      el('div', { class: 'sub' }, s.custom ? 'SSH host' : `CT ${s.ctid}`,
        s.checked_at ? ` · checked ${ago(s.checked_at)}` : '', accessBadge(s),
        !s.latest && s.link ? el('span', {}, ' · ', ext(s.link, 'changelog ↗')) : null));

    const inst = s.installed
      ? el('td', { class: 'ver', 'data-label': 'Installed', text: s.installed })
      : el('td', { class: 'ver', 'data-label': 'Installed' }, stopped ? '–'
        : el('span', { class: 'hint', title: s.installed_hint || '', text: 'unknown' }));

    const avail = el('td', { class: 'ver', 'data-label': 'Available' }, el('span', {},
      s.latest && upd ? el('span', { class: 'arrow', 'aria-hidden': 'true', text: '→' }) : null,
      s.latest
        ? (s.link ? el('a', { class: upd ? 'newver' : '', href: s.link, target: '_blank', rel: 'noopener noreferrer',
          title: 'Release notes / changelog', text: s.latest + ' ↗' })
          : el('span', { class: upd ? 'newver' : '', text: s.latest }))
        : '–'));

    const status = el('td', { 'data-label': 'Status' },
      el('span', { class: 'badge ' + (s.running ? 'running' : cls), title: s.error || '',
        text: s.running ? (s.job_status === 'queued' ? 'Queued…' : 'Updating…') : s.checking ? 'Checking…' : label }),
      s.error ? el('div', { class: 'sub', text: s.error.slice(0, 140) }) : null);

    const os = el('td', { 'data-label': 'OS packages' },
      stopped || s.os_updates == null ? '–' : s.os_updates === 0 ? 'up to date' : `${s.os_updates} pending`);

    // "Update" only when there is something to update (or the version can't be read); never for up-to-date apps.
    const canApp = s.can_app_update && !stopped && !s.running && (upd || s.status === 'unknown');
    const acts = el('div', { class: 'acts' },
      canApp ? el('button', { class: 'btn small' + (upd ? ' primary' : ''), type: 'button', onclick: () => startUpdate(s, 'app'),
        title: upd ? '' : 'The installed version could not be read, so this runs the update anyway.',
        text: 'Update' }) : null,
      s.os_updates > 0 && !s.running && !stopped ? el('button', { class: 'btn small', type: 'button',
        onclick: () => startUpdate(s, 'os'), text: 'Upgrade OS' }) : null,
      s.running ? el('button', { class: 'btn small', type: 'button', text: 'Cancel',
        onclick: () => post('/api/cancel', { ctid: s.ctid }).then(refresh).catch(fail) }) : null,
      el('button', { class: 'btn small ghost', type: 'button', disabled: s.checking || s.running || stopped,
        onclick: () => post('/api/check', { ctid: s.ctid }).then(refresh).catch(fail), text: 'Check' }),
      el('button', { class: 'btn small ghost', type: 'button', onclick: () => openAccess(s), text: 'Access' }),
      s.job ? el('button', { class: 'btn small ghost', type: 'button', onclick: () => openHistory(s), text: 'Logs' }) : null);
    return el('tr', {}, nameCell, inst, avail, status, os, el('td', { class: 'actions' }, acts));
  }

  function chip(text, cls) { return el('span', { class: 'chip' + (cls ? ' ' + cls : ''), text }); }

  function render() {
    const d = data;
    const busy = d.services.some((s) => s.checking || s.running);
    $('#sub').textContent = d.last_sweep
      ? `${d.total} ${d.total === 1 ? 'container' : 'containers'} · last full check ${ago(d.last_sweep)} · auto-checks every ${d.interval} min`
      : 'Running first check…';
    $('#checkAll').disabled = busy;

    const upd = d.updates;
    $('#chips').replaceChildren(...[
      upd ? chip(`${upd} app update${upd > 1 ? 's' : ''} available`, 'warn')
        : d.errors ? chip('No app updates found', '') : chip('All apps up to date', 'ok'),
      d.os_pending ? chip(`${d.os_pending} with OS package updates`, '') : null,
      d.errors ? chip(`${d.errors} unreachable`, 'bad') : null,
      d.stopped ? chip(`${d.stopped} stopped`, '') : null,
    ].filter(Boolean));

    const banners = [];
    if (me && me.plaintext_password) banners.push('The config file still holds a plaintext password. Set a new one under Settings → Password.');
    if (d.inventory_error) banners.push(d.inventory_error);
    const bn = $('#banner');
    bn.hidden = !banners.length;
    bn.className = 'banner' + (d.inventory_error ? ' bad' : '');
    bn.textContent = banners.join(' ');

    const rows = visible(d.services);
    $('#rows').replaceChildren(...(rows.length ? rows.map(row) : [el('tr', {},
      el('td', { colspan: '6', class: 'empty', text: !d.services.length
        ? 'Nothing is managed yet. Use “Manage containers” (Proxmox) or “Add a host by SSH”.'
        : 'Nothing matches.' }))]));
    return busy;
  }

  async function refresh() {
    if (busyPoll) return;
    busyPoll = true;
    try {
      data = await api('/api/services');
      schedule(render() ? 2000 : 15000);
    } catch (e) {
      $('#sub').textContent = 'Cannot reach the server: ' + e.message;
      schedule(10000);
    } finally {
      busyPoll = false;
    }
  }
  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(() => { if (!document.hidden) refresh(); else schedule(ms); }, ms);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });

  // ---------------------------------------------------------------- updates and logs
  async function startUpdate(s, kind) {
    const os = kind === 'os';
    const extra = [];
    if (!os && (s.installed || s.latest)) {
      extra.push(el('p', { class: 'verline' },
        el('span', { class: 'ver', text: s.installed || 'unknown' }),
        el('span', { class: 'arrow', text: ' → ' }),
        el('span', { class: 'ver newver', text: s.latest || 'latest' }),
        s.link ? el('span', {}, ' · ', ext(s.link, 'release notes ↗')) : null));
      if (s.notes) extra.push(el('pre', { class: 'notes', text: s.notes }));
    }
    extra.push(el('p', { class: 'sub', text: s.snapshot ? 'A snapshot of the container is taken first.'
      : 'No snapshot will be taken for this one (it is not managed through the Proxmox host).' }));
    const ok = await ask(os ? `Upgrade OS packages in ${s.name}?` : `Update ${s.name}?`,
      os ? 'Runs apt upgrade inside the container.' : 'Runs the application update inside the container.',
      os ? 'Upgrade' : 'Update', extra);
    if (!ok) return;
    try {
      const { job } = await post('/api/update', { ctid: s.ctid, kind });
      watch(job, `${s.name} ${os ? 'OS packages' : 'update'}`);
      refresh();
    } catch (e) { fail(e); }
  }

  let watching = null;
  async function watch(jobId, title) {
    watching = jobId;
    $('#logpanel').hidden = false;
    $('#logtitle').textContent = title;
    $('#log').textContent = '';
    $('#logpanel').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    let since = 0;
    while (watching === jobId) {
      try {
        const j = await api(`/api/jobs/${jobId}?since=${since}`);
        if (j.lines.length) {
          const pre = $('#log');
          const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
          pre.textContent += j.lines.join('\n') + '\n';
          if (stick) pre.scrollTop = pre.scrollHeight;
        }
        since = j.next;
        $('#logstatus').textContent = j.status;
        $('#logstatus').className = 'badge ' + j.status;
        if (j.status !== 'running' && j.status !== 'queued') { refresh(); return; }
      } catch (e) {
        $('#logstatus').textContent = 'error';
        $('#logstatus').className = 'badge error';
        return;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  $('#logclose').addEventListener('click', () => { $('#logpanel').hidden = true; watching = null; });

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
    }
    const ta = el('textarea', { readonly: true, class: 'offscreen', 'aria-hidden': 'true' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
  $('#logcopy').addEventListener('click', async () => {
    const btn = $('#logcopy');
    const text = `${$('#logtitle').textContent} [${$('#logstatus').textContent}]\n\n${$('#log').textContent}`.trimEnd() + '\n';
    const ok = await copyText(text);
    if (!ok) {  // last resort: select the log so Ctrl/Cmd+C works
      const r = document.createRange();
      r.selectNodeContents($('#log'));
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
    }
    btn.textContent = ok ? 'Copied' : 'Press Ctrl/Cmd+C';
    setTimeout(() => { btn.textContent = 'Copy log'; }, 2000);
  });

  // ---------------------------------------------------------------- log history
  async function openHistory(s) {
    const dlg = $('#history');
    $('#historyTitle').textContent = `Logs · ${s.name}`;
    $('#historyNote').textContent = 'Loading…';
    $('#historyList').replaceChildren();
    dlg.showModal();
    try {
      const { logs, retention } = await api(`/api/logs?ctid=${s.ctid}`);
      $('#historyNote').textContent = `Keeping the latest ${retention} per container. Change this in Settings.`;
      $('#historyList').replaceChildren(...(logs.length ? logs.map((l) => el('li', {},
        el('div', { class: 'grow' },
          el('div', { class: 'nm', text: `${l.kind === 'os' ? 'OS packages' : 'Application'} · ${when(l.started)}` }),
          el('div', { class: 'sub', text: `${l.line_count} lines${l.by ? ' · by ' + l.by : ''}` })),
        el('span', { class: 'badge ' + l.status, text: l.status }),
        el('button', { class: 'btn small', type: 'button', text: 'View', onclick: () => {
          dlg.close();
          watch(l.id, `${s.name} · ${l.kind === 'os' ? 'OS packages' : 'update'} · ${when(l.started)}`);
        } }))) : [el('li', { class: 'muted', text: 'No logs yet.' })]));
    } catch (e) { $('#historyNote').textContent = e.message; }
  }
  $('#historyClose').addEventListener('click', () => $('#history').close());

  // ---------------------------------------------------------------- manage containers (Proxmox allow list)
  let inv = null;
  function renderManage() {
    const q = $('#manageFilter').value.trim().toLowerCase();
    const items = (inv ? inv.containers : []).filter((c) => !q || c.name.toLowerCase().includes(q) || String(c.ctid).includes(q));
    $('#manageList').replaceChildren(...items.map((c) => {
      const box = el('input', { type: 'checkbox', 'aria-label': `Manage ${c.name}`, disabled: c.locked });
      box.checked = c.managed;
      box.addEventListener('change', async () => {
        const want = box.checked;
        box.disabled = true;
        $('#manageMsg').className = 'muted';
        $('#manageMsg').textContent = `${want ? 'Adding' : 'Removing'} ${c.name}…`;
        try {
          await post('/api/allow', { ctid: c.ctid, action: want ? 'add' : 'remove' });
          c.managed = want;
          $('#manageMsg').textContent = `${c.name} ${want ? 'added' : 'removed'}.`;
          refresh();
        } catch (e) {
          box.checked = !want;
          $('#manageMsg').className = 'err';
          $('#manageMsg').textContent = e.message;
        } finally { box.disabled = !!c.locked; }
      });
      return el('li', {},
        el('div', { class: 'grow' }, el('div', { class: 'nm', text: c.name }), el('div', { class: 'sub', text: `CT ${c.ctid}` })),
        el('span', { class: 'badge ' + (c.status === 'running' ? 'current' : 'stopped'), text: c.status }),
        c.locked ? el('span', { class: 'badge stopped', title: 'Protected on the Proxmox host: edit /etc/updatedash-gate.allow by hand', text: 'Locked' }) : null,
        el('label', {}, box, 'Managed'));
    }));
  }
  async function openManage() {
    const dlg = $('#manage');
    $('#manageMsg').className = 'muted';
    $('#manageMsg').textContent = 'Loading containers…';
    $('#manageList').replaceChildren();
    $('#manageFilter').value = '';
    dlg.showModal();
    try {
      inv = await api('/api/inventory');
      if (!inv.manage) {
        $('#manageMsg').className = 'err';
        $('#manageMsg').textContent = 'Managing containers from here is not available: ' + inv.message +
          ' (Create /etc/updatedash-gate.manage on the Proxmox host, or edit /etc/updatedash-gate.allow by hand. You can still add hosts by SSH below.)';
        return;
      }
      $('#manageMsg').textContent = 'Tick a container to let the dashboard check and update it. Untick to stop managing it.';
      renderManage();
    } catch (e) { $('#manageMsg').className = 'err'; $('#manageMsg').textContent = e.message; }
  }
  $('#manageBtn').addEventListener('click', openManage);
  $('#manageClose').addEventListener('click', () => $('#manage').close());
  $('#manageFilter').addEventListener('input', renderManage);
  $('#addHostBtn').addEventListener('click', () => { $('#manage').close(); openAccess(null); });

  // ---------------------------------------------------------------- per-container access (SSH credentials)
  const F = {
    name: $('#aName'), host: $('#aHost'), port: $('#aPort'), user: $('#aUser'), auth: $('#aAuth'),
    pw: $('#aSecret'), key: $('#aKey'), pass: $('#aPass'), sudo: $('#aSudo'), forget: $('#aForget'),
  };
  let accessTarget = null;     // service object, or null when adding a new host
  let accessSaved = null;      // public fields of the saved credentials, if any

  function syncAuthRows() {
    const key = F.auth.value === 'key';
    $('#aKeyRow').hidden = !key;
    $('#aPwRow').hidden = key;
    const saved = accessSaved && accessSaved.has_secret && accessSaved.auth === F.auth.value;
    const note = $('#aSavedNote');
    note.hidden = !saved;
    note.textContent = saved ? `A ${key ? 'key' : 'password'} is saved. Leave the field empty to keep it, or enter a new one.` : '';
    F.pw.placeholder = saved ? '•••••••• (saved)' : '';
  }
  F.auth.addEventListener('change', syncAuthRows);
  $('#aKeyFile').addEventListener('change', (ev) => {
    const f = ev.target.files && ev.target.files[0];
    if (!f) return;
    if (f.size > 16384) { toast('That file is too large to be a private key.', 'bad'); return; }
    const r = new FileReader();
    r.onload = () => { F.key.value = String(r.result); };
    r.readAsText(f);
  });

  function accessBody() {
    const body = {
      host: F.host.value.trim(), port: Number(F.port.value) || 22, user: F.user.value.trim(), auth: F.auth.value,
      sudo: F.sudo.checked, forget_host_key: F.forget.checked,
    };
    const secret = F.auth.value === 'key' ? F.key.value : F.pw.value;
    if (secret) body.secret = secret;
    if (F.auth.value === 'key' && F.pass.value) body.passphrase = F.pass.value;
    if (accessTarget) body.ctid = accessTarget.ctid; else { body.custom = true; body.name = F.name.value.trim(); }
    return body;
  }

  function showResult(res, saved) {
    const box = $('#accessResult');
    box.hidden = false;
    box.className = 'result ' + (res.ok ? 'good' : 'bad');
    const lines = [el('div', { text: (res.ok ? '✔ ' : '✖ ') + res.message })];
    if (res.os) lines.push(el('div', { class: 'sub', text: `${res.hostname || ''} · ${res.os}` }));
    if (res.fingerprint) lines.push(el('div', { class: 'sub', text: `Host key ${res.fingerprint}` }));
    if (res.ok && res.root === false) lines.push(el('div', { class: 'sub', text: 'Not root.' }));
    if (saved) lines.push(el('div', { class: 'sub', text: 'Saved.' }));
    box.replaceChildren(...lines);
  }

  async function openAccess(s) {
    accessTarget = s;
    accessSaved = null;
    $('#accessResult').hidden = true;
    $('#accessForm').reset();
    F.port.value = 22; F.user.value = 'root'; F.auth.value = 'password';
    $('#accessTitle').textContent = s ? `Access · ${s.name}` : 'Add a host by SSH';
    $('#accessNameRow').hidden = !!s;
    $('#accessIntro').textContent = s
      ? (s.access && s.access.mode === 'ssh'
        ? 'This container is reached directly over SSH with the credentials below.'
        : 'Currently reached through the Proxmox host. Add SSH credentials to reach it directly instead (no snapshots in that case unless it is also managed through Proxmox).')
      : 'Reach any machine that runs sshd (a VM, a Raspberry Pi, a container) directly. No Proxmox access is needed.';
    $('#accessRemove').hidden = true;
    syncAuthRows();
    $('#access').showModal();
    if (s) {
      try {
        const { access } = await api(`/api/access?ctid=${s.ctid}`);
        if (access) {
          accessSaved = access;
          F.host.value = access.host || ''; F.port.value = access.port || 22; F.user.value = access.user || 'root';
          F.auth.value = access.auth || 'password'; F.sudo.checked = !!access.sudo;
          $('#accessRemove').hidden = false;
          $('#accessRemove').textContent = s.custom ? 'Remove this host' : 'Remove credentials';
          if (access.tested_at) showResult({ ok: !!access.tested_ok, message: `Last test ${ago(access.tested_at)}: ${access.tested_msg || ''}` }, false);
        }
      } catch (e) { fail(e); }
      syncAuthRows();
    }
  }

  $('#accessTest').addEventListener('click', async () => {
    const btn = $('#accessTest');
    btn.disabled = true; btn.textContent = 'Testing…';
    try { showResult(await post('/api/access/test', accessBody()), false); }
    catch (e) { showResult({ ok: false, message: e.message }, false); }
    finally { btn.disabled = false; btn.textContent = 'Test connection'; }
    refresh();
  });
  $('#accessForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('#accessSave');
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      const out = await post('/api/access/save', accessBody());
      showResult(out.test, true);
      toast(out.test.ok ? 'Saved. Login works.' : 'Saved, but the login test failed.', out.test.ok ? '' : 'bad');
      if (!accessTarget) { $('#access').close(); }
      else { accessSaved = out.access; $('#accessRemove').hidden = false; F.pw.value = ''; F.key.value = ''; F.pass.value = ''; syncAuthRows(); }
      refresh();
    } catch (e) { showResult({ ok: false, message: e.message }, false); }
    finally { btn.disabled = false; btn.textContent = 'Save'; }
  });
  $('#accessRemove').addEventListener('click', async () => {
    if (!accessTarget) return;
    const ok = await ask(accessTarget.custom ? `Remove ${accessTarget.name}?` : 'Remove saved credentials?',
      accessTarget.custom ? 'The host and its credentials are deleted from the dashboard.'
        : 'The container goes back to being reached through the Proxmox host (if it is managed there).', 'Remove');
    if (!ok) return;
    try { await post('/api/access/remove', { ctid: accessTarget.ctid }); toast('Removed.'); $('#access').close(); refresh(); }
    catch (e) { fail(e); }
  });
  $('#accessClose').addEventListener('click', () => $('#access').close());

  // ---------------------------------------------------------------- settings
  async function openSettings() {
    const dlg = $('#settings');
    $('#sRetentionMsg').textContent = '';
    $('#pwMsg').textContent = '';
    dlg.showModal();
    try {
      const s = await api('/api/settings');
      $('#sRetention').value = s.log_retention;
      $('#sRetention').min = s.limits.log_retention[0];
      $('#sRetention').max = s.limits.log_retention[1];
    } catch (e) { fail(e); }
    try {
      const { events } = await api('/api/audit?limit=30');
      $('#auditList').replaceChildren(...(events.length ? events.map((ev) => el('li', {},
        el('time', { text: when(ev.t) }), el('strong', { text: ev.action }),
        el('span', { class: 'muted', text: `${ev.user} · ${ev.ip || ''} ${ev.detail || ''}` }))) : [el('li', { class: 'muted', text: 'Nothing yet.' })]));
    } catch (e) { fail(e); }
    try {
      const a = await api('/api/about');
      $('#aboutText').textContent = `Update Dashboard ${a.version} · transport: ${a.transport} · ${a.tls ? 'TLS on' : 'plain HTTP (use a reverse proxy with HTTPS)'} · up ${Math.round(a.uptime / 60)} min`;
    } catch { /* optional */ }
  }
  $('#settingsBtn').addEventListener('click', openSettings);
  $('#settingsClose').addEventListener('click', () => $('#settings').close());
  $('#sRetentionSave').addEventListener('click', async () => {
    const msg = $('#sRetentionMsg');
    try {
      const v = Number($('#sRetention').value);
      const out = await post('/api/settings', { log_retention: v });
      msg.className = 'muted';
      msg.textContent = `Saved. Keeping ${out.log_retention} per container; older logs were removed.`;
      refresh();
    } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  });
  $('#pwForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const msg = $('#pwMsg');
    if ($('#pwNew').value !== $('#pwNew2').value) { msg.className = 'err'; msg.textContent = 'The new passwords do not match.'; return; }
    try {
      await post('/api/password', { current: $('#pwCur').value, new: $('#pwNew').value });
      msg.className = 'muted'; msg.textContent = 'Password changed. Other sessions were signed out.';
      $('#pwForm').reset();
      if (me) me.plaintext_password = false;
      if (data) render();
    } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  });

  // ---------------------------------------------------------------- toolbar wiring
  $('#checkAll').addEventListener('click', () => post('/api/check').then(() => setTimeout(refresh, 400)).catch(fail));
  $('#signOut').addEventListener('click', async () => { try { await post('/api/logout'); } finally { location.replace('/login'); } });
  $('#onlyAction').addEventListener('change', (e) => { ui.only = e.target.checked; store.set('only', ui.only ? '1' : '0'); if (data) render(); });
  $('#sort').addEventListener('change', (e) => { ui.sort = e.target.value; store.set('sort', ui.sort); if (data) render(); });
  $('#search').addEventListener('input', (e) => { ui.q = e.target.value.trim().toLowerCase(); if (data) render(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && !document.querySelector('dialog[open]')) {
      e.preventDefault();
      $('#search').focus();
    }
  });

  // ---------------------------------------------------------------- start
  let me = null;
  api('/api/me').then((m) => { me = m; if (data) render(); }).catch(() => {});
  refresh();
})();
