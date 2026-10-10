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
    host: '',
  };
  $('#onlyAction').checked = ui.only;
  $('#sort').value = ui.sort;

  const STATUS = {
    update: ['Update available', 'update'],
    current: ['Up to date', 'current'],
    unknown: ['Version unknown', ''],
    error: ['Unreachable', 'error'],
    stopped: ['Stopped', 'stopped'],
    os: ['System updates only', 'os'],
    nocheck: ['No app check', 'nocheck'],
  };
  const QUIET = new Set(['current', 'nocheck', 'stopped']);
  // security first, then app updates, then problems, then the rest
  function rank(s) {
    if (s.status === 'stopped') return 7;
    if ((s.os_security || 0) > 0) return 0;
    if (s.status === 'update') return 1;
    if (s.status === 'error') return 2;
    if ((s.os_updates || 0) > 0) return 3;
    if (s.status === 'unknown') return 4;
    if (s.status === 'current') return 5;
    return 6;
  }
  const expanded = new Set();
  const sysCache = new Map();

  function visible(list) {
    const rows = list.filter((s) => {
      if (ui.host !== '' && String(s.host_idx) !== ui.host) return false;
      if (ui.only && QUIET.has(s.status) && !s.running && !(s.os_updates > 0)) return false;
      if (ui.q) {
        const hay = `${s.name} ${s.real_ctid} ${s.host || ''} ${(s.access && s.access.host) || ''}`.toLowerCase();
        if (!hay.includes(ui.q)) return false;
      }
      return true;
    });
    const by = {
      id: (a, b) => (a.host_idx || 0) - (b.host_idx || 0) || a.real_ctid - b.real_ctid,
      name: (a, b) => a.name.localeCompare(b.name),
      action: (a, b) => (a.running === b.running ? 0 : a.running ? -1 : 1) || rank(a) - rank(b) || a.name.localeCompare(b.name),
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

  const multiHost = () => !!(data && data.hosts && data.hosts.length > 1);

  function appPane(s) {
    const [label, cls] = STATUS[s.status] || STATUS.unknown;
    const stopped = s.status === 'stopped';
    const upd = s.status === 'update';
    const kids = [];
    if (s.running) {
      kids.push(el('div', { class: 'line' }, el('span', { class: 'badge running', text: s.job_status === 'queued' ? 'Queued…' : 'Updating…' })));
    } else if (s.checking) {
      kids.push(el('div', { class: 'line' }, el('span', { class: 'badge running', text: 'Checking…' })));
    } else if (s.status === 'nocheck') {
      kids.push(el('div', { class: 'line' }, el('span', { class: 'badge nocheck', text: 'No app check' })));
    } else {
      const ver = [];
      if (s.installed) ver.push(el('span', { class: 'ver', text: s.installed }));
      else if (!stopped) ver.push(el('span', { class: 'ver hint', title: s.installed_hint || '', text: 'version unknown' }));
      if (upd && s.latest) {
        ver.push(el('span', { class: 'arrow', 'aria-hidden': 'true', text: '→' }));
        ver.push(s.link ? el('a', { class: 'ver newver', href: s.link, target: '_blank', rel: 'noopener noreferrer', title: 'Release notes', text: s.latest + ' ↗' })
          : el('span', { class: 'ver newver', text: s.latest }));
      }
      kids.push(el('div', { class: 'line' }, ...ver));
      kids.push(el('div', { class: 'line' }, el('span', { class: 'badge ' + cls, title: s.error || '', text: label }),
        !upd && s.latest && s.link ? ext(s.link, 'changelog ↗') : null));
    }
    if (s.error) kids.push(el('div', { class: 'sub', text: s.error.slice(0, 140) }));
    return el('td', { class: 'pane', 'data-label': 'Application' }, ...kids);
  }

  function sysPane(s) {
    const kids = [];
    const info = s.os_info;
    if (s.status === 'stopped') return el('td', { class: 'pane', 'data-label': 'System' }, '–');
    if (info && info.name) kids.push(el('div', { class: 'what', text: info.name }));
    if (info && info.apt === false) {
      kids.push(el('div', { class: 'sub', text: 'No apt here, so system updates are not checked.' }));
    } else if (s.os_updates == null) {
      kids.push(el('div', { class: 'sub', text: s.checking ? 'Checking…' : 'Not checked yet' }));
    } else if (s.os_updates === 0) {
      kids.push(el('div', { class: 'line' }, el('span', { class: 'badge current', text: 'Up to date' })));
    } else {
      const sec = s.os_security || 0;
      const other = s.os_updates - sec;
      if (s.os_point && s.os_point.length === 2 && s.os_point[0] !== s.os_point[1]) {
        kids.push(el('div', { class: 'line' }, el('span', { class: 'ver', text: s.os_point[0] }),
          el('span', { class: 'arrow', 'aria-hidden': 'true', text: '→' }), el('span', { class: 'ver newver', text: s.os_point[1] })));
      }
      const open = expanded.has(s.ctid);
      kids.push(el('div', { class: 'line' },
        sec ? el('span', { class: 'badge sec', text: `${sec} security` }) : null,
        s.auto_system ? el('span', { class: 'badge nocheck', title: 'Updated automatically when a security update is pending', text: 'auto' }) : null,
        other ? el('span', { class: 'badge pending', text: `${other} other` }) : null,
        el('button', { class: 'linkbtn', type: 'button', 'aria-expanded': open ? 'true' : 'false',
          onclick: () => toggleDetail(s), text: open ? 'Hide packages' : 'Show packages' })));
    }
    return el('td', { class: 'pane', 'data-label': 'System' }, ...kids);
  }

  function row(s) {
    const stopped = s.status === 'stopped';
    const upd = s.status === 'update';

    const nameCell = el('td', { class: 'name', 'data-label': 'Container' },
      el('div', { class: 'svc' }, s.name, multiHost() && s.host ? el('span', { class: 'hosttag', text: s.host }) : null),
      el('div', { class: 'sub' }, s.custom ? 'SSH host' : `CT ${s.real_ctid}`,
        s.checked_at ? ` · checked ${ago(s.checked_at)}` : '', accessBadge(s)));

    // "Update application" only when there is something to update (or the installed version can't be read).
    const canApp = s.can_app_update && !stopped && !s.running && (upd || s.status === 'unknown');
    const canSys = (s.os_updates || 0) > 0 && !s.running && !stopped;
    const acts = el('div', { class: 'acts' },
      canApp ? el('button', { class: 'btn small' + (upd ? ' primary' : ''), type: 'button', onclick: () => startUpdate(s, 'app'),
        title: upd ? '' : 'The installed version could not be read, so this runs the update anyway.', text: 'Update app' }) : null,
      canSys ? el('button', { class: 'btn small' + ((s.os_security || 0) > 0 ? ' primary' : ''), type: 'button',
        onclick: () => startUpdate(s, 'os'), text: 'Update system' }) : null,
      s.running ? el('button', { class: 'btn small', type: 'button', text: 'Cancel',
        onclick: () => post('/api/cancel', { ctid: s.ctid }).then(refresh).catch(fail) }) : null,
      el('button', { class: 'btn small ghost', type: 'button', disabled: s.checking || s.running || stopped,
        onclick: () => post('/api/check', { ctid: s.ctid }).then(refresh).catch(fail), text: 'Check' }),
      el('button', { class: 'btn small ghost', type: 'button', onclick: () => openAccess(s), text: 'Access' }),
      s.job ? el('button', { class: 'btn small ghost', type: 'button', onclick: () => openHistory(s), text: 'Logs' }) : null);
    const main = el('tr', {}, nameCell, appPane(s), sysPane(s), el('td', { class: 'actions' }, acts));
    if (!expanded.has(s.ctid)) return [main];
    return [main, detailRow(s)];
  }

  function detailRow(s) {
    const cell = el('td', { colspan: '4' });
    const cached = sysCache.get(s.ctid);
    if (!cached) {
      cell.append(el('span', { class: 'muted', text: 'Loading packages…' }));
      api(`/api/system?ctid=${s.ctid}`).then((v) => { sysCache.set(s.ctid, { v, at: Date.now() }); if (data) render(); })
        .catch((e) => { cell.replaceChildren(el('span', { class: 'err', text: e.message })); });
    } else {
      const v = cached.v;
      const pk = v.packages || [];
      const total = v.total || pk.length;
      cell.append(el('table', { class: 'pkgs' },
        el('thead', {}, el('tr', {}, el('th', { text: 'Package' }), el('th', { text: 'Installed' }), el('th', { text: 'Available' }), el('th', { text: 'Type' }))),
        el('tbody', {}, ...pk.map((p) => el('tr', { class: p.security ? 'secrow' : '' },
          el('td', { text: p.pkg }), el('td', { text: p.from || 'new' }), el('td', { text: p.to }),
          el('td', {}, el('span', { class: 'badge ' + (p.security ? 'sec' : 'pending'), text: p.security ? 'security' : 'update' })))))),
        ...(total > pk.length ? [el('p', { class: 'sub', text: `Showing the first ${pk.length} of ${total}; security updates are listed first.` })] : []));
      if (v.os_info && v.os_info.name) cell.prepend(el('p', { class: 'sub', text: v.os_info.name }));
    }
    return el('tr', { class: 'detail' }, cell);
  }

  function toggleDetail(s) {
    if (expanded.has(s.ctid)) expanded.delete(s.ctid);
    else { expanded.add(s.ctid); sysCache.delete(s.ctid); }
    if (data) render();
  }

  function chip(text, cls) { return el('span', { class: 'chip' + (cls ? ' ' + cls : ''), text }); }

  function syncHostFilter(d) {
    const hs = d.hosts || [];
    const sel = $('#hostFilter');
    const show = hs.length > 1;
    sel.hidden = !show;
    if (!show) { ui.host = ''; return; }
    const sig = hs.map((h) => h.idx + h.name).join('|');
    if (sel.dataset.sig !== sig) {
      sel.replaceChildren(el('option', { value: '', text: 'All hosts' }), ...hs.map((h) => el('option', { value: String(h.idx), text: h.name })));
      sel.dataset.sig = sig;
    }
    sel.value = ui.host;
  }

  function render() {
    const d = data;
    const busy = d.services.some((s) => s.checking || s.running);
    $('#sub').textContent = d.last_sweep
      ? `${d.total} ${d.total === 1 ? 'container' : 'containers'}${multiHost() ? ` on ${d.hosts.length} hosts` : ''} · last full check ${ago(d.last_sweep)} · auto-checks every ${d.interval} min`
      : 'Running first check…';
    $('#checkAll').disabled = busy;

    const upd = d.updates;
    $('#chips').replaceChildren(...[
      d.security ? chip(`${d.security} with security updates`, 'bad') : null,
      upd ? chip(`${upd} app update${upd > 1 ? 's' : ''} available`, 'warn')
        : d.errors ? chip('No app updates found', '') : chip('All apps up to date', 'ok'),
      d.os_pending ? chip(`${d.os_pending} with system updates`, 'warn') : null,
      d.errors ? chip(`${d.errors} unreachable`, 'bad') : null,
      d.stopped ? chip(`${d.stopped} stopped`, '') : null,
    ].filter(Boolean));
    syncHostFilter(d);

    const banners = [...((me && me.warnings) || [])];
    if (d.inventory_error) banners.push(d.inventory_error);
    const bn = $('#banner');
    bn.hidden = !banners.length;
    bn.className = 'banner' + (d.inventory_error ? ' bad' : '');
    if (banners.length > 1 && window.matchMedia('(max-width: 760px)').matches) {
      // phones: one tappable line instead of a wall of text (keep it open if the user opened it)
      const wasOpen = !!bn.querySelector('details[open]');
      const det = el('details', {}, el('summary', { text: `${banners.length} notices` }), ...banners.map((t) => el('p', { text: t })));
      if (wasOpen) det.open = true;
      bn.replaceChildren(det);
    } else bn.replaceChildren(...banners.map((t) => el('div', { text: t })));

    const rows = visible(d.services);
    $('#rows').replaceChildren(...(rows.length ? rows.flatMap(row) : [el('tr', {},
      el('td', { colspan: '4', class: 'empty', text: !d.services.length
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
    if (os) {
      const sec = s.os_security || 0;
      extra.push(el('p', { class: 'verline' },
        s.os_info && s.os_info.name ? `${s.os_info.name}` : 'System',
        s.os_point && s.os_point[0] !== s.os_point[1] ? el('span', {}, ' · ', el('span', { class: 'ver', text: s.os_point[0] }), ' → ', el('span', { class: 'ver newver', text: s.os_point[1] })) : null));
      extra.push(el('p', { text: `${s.os_updates} package${s.os_updates === 1 ? '' : 's'} will be upgraded${sec ? `, ${sec} of them security fixes` : ''}.` }));
      try {
        const v = await api(`/api/system?ctid=${s.ctid}`);
        const lines = (v.packages || []).slice(0, 60).map((p) => `${p.security ? '[security] ' : ''}${p.pkg}  ${p.from || 'new'} → ${p.to}`);
        if (lines.length) extra.push(el('pre', { class: 'notes', text: lines.join('\n') + ((v.total || 0) > lines.length ? `\n… and ${v.total - lines.length} more` : '') }));
      } catch { /* the list is a courtesy; the update itself does not depend on it */ }
    }
    extra.push(el('p', { class: 'sub', text: s.snapshot ? 'A snapshot of the container is taken first.'
      : 'No snapshot will be taken for this one (it is not managed through the Proxmox host).' }));
    const ok = await ask(os ? `Update the system in ${s.name}?` : `Update ${s.name}?`,
      os ? 'Runs apt upgrade inside the container.' : 'Runs the application update inside the container.',
      os ? 'Update system' : 'Update', extra);
    if (!ok) return;
    try {
      const { job } = await post('/api/update', { ctid: s.ctid, kind });
      watch(job, `${s.name} ${os ? 'system packages' : 'update'}`);
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
          el('div', { class: 'nm', text: `${l.kind === 'os' ? 'System' : 'Application'} · ${when(l.started)}` }),
          el('div', { class: 'sub', text: `${l.line_count} lines${l.by ? ' · by ' + l.by : ''}` })),
        el('span', { class: 'badge ' + l.status, text: l.status }),
        el('button', { class: 'btn small', type: 'button', text: 'View', onclick: () => {
          dlg.close();
          watch(l.id, `${s.name} · ${l.kind === 'os' ? 'system' : 'update'} · ${when(l.started)}`);
        } }))) : [el('li', { class: 'muted', text: 'No logs yet.' })]));
    } catch (e) { $('#historyNote').textContent = e.message; }
  }
  $('#historyClose').addEventListener('click', () => $('#history').close());

  // ---------------------------------------------------------------- manage containers (Proxmox allow list)
  let inv = null;
  let manageHost = 0;
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
          await post('/api/allow', { ctid: c.ctid, host: manageHost, action: want ? 'add' : 'remove' });
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
  async function loadManage() {
    $('#manageMsg').className = 'muted';
    $('#manageMsg').textContent = 'Loading containers…';
    $('#manageList').replaceChildren();
    try {
      inv = await api('/api/inventory?host=' + manageHost);
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
  async function openManage() {
    const dlg = $('#manage');
    $('#manageFilter').value = '';
    const hs = (data && data.hosts) || [];
    const sel = $('#manageHost');
    const many = hs.length > 1;
    sel.hidden = !many; $('#manageHostLabel').hidden = !many;
    sel.replaceChildren(...hs.map((h) => el('option', { value: String(h.idx), text: h.name })));
    manageHost = hs.length ? hs[0].idx : 0;
    sel.value = String(manageHost);
    dlg.showModal();
    loadManage();
  }
  $('#manageHost').addEventListener('change', (e) => { manageHost = Number(e.target.value); loadManage(); });
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
  let hostKey = { known: false, keys: [], checked: false, fp: '' };

  function resetHostKey() {
    hostKey = { known: false, keys: [], checked: false, fp: '' };
    $('#hostKeyList').replaceChildren();
    $('#hostKeyState').textContent = '';
    $('#hostKeyConfirmRow').hidden = true;
    $('#aTrust').checked = false;
  }
  async function checkHostKey() {
    const host = F.host.value.trim();
    if (!host) { $('#hostKeyState').textContent = 'Enter the host first.'; return; }
    const btn = $('#hostKeyBtn');
    btn.disabled = true;
    $('#hostKeyState').textContent = 'Asking the server…';
    try {
      const r = await post('/api/access/hostkey', { host, port: Number(F.port.value) || 22 });
      hostKey = { known: r.known, keys: r.keys, checked: true, fp: r.keys[0] ? r.keys[0].fingerprint : '' };
      $('#aTrust').checked = false;
      $('#hostKeyList').replaceChildren(...r.keys.map((k, i) => {
        const radio = el('input', { type: 'radio', name: 'hk', id: 'hk' + i, 'aria-label': k.type + ' ' + k.fingerprint });
        radio.checked = i === 0;
        radio.addEventListener('change', () => { hostKey.fp = k.fingerprint; $('#aTrust').checked = false; });
        return el('label', { class: 'fp', for: 'hk' + i }, radio, el('span', { text: `${k.type}  ${k.fingerprint}` }));
      }));
      if (r.known) {
        $('#hostKeyState').textContent = '✔ This host key is already trusted.';
        $('#hostKeyConfirmRow').hidden = true;
      } else if (!r.keys.length) {
        $('#hostKeyState').textContent = r.message || 'No host key was returned.';
        $('#hostKeyConfirmRow').hidden = true;
      } else {
        $('#hostKeyState').textContent = 'Not trusted yet. Compare a fingerprint below with the server, then confirm.';
        $('#hostKeyConfirmRow').hidden = false;
      }
    } catch (e) { $('#hostKeyState').textContent = e.message; }
    finally { btn.disabled = false; }
  }
  $('#hostKeyBtn').addEventListener('click', checkHostKey);
  [F.host, F.port].forEach((i) => i.addEventListener('input', resetHostKey));

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
    if (hostKey.checked && !hostKey.known && $('#aTrust').checked && hostKey.fp) body.trust_fingerprint = hostKey.fp;
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
    resetHostKey();
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
          checkHostKey();
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
      else { accessSaved = out.access; $('#accessRemove').hidden = false; F.pw.value = ''; F.key.value = ''; F.pass.value = ''; F.forget.checked = false; syncAuthRows(); checkHostKey(); }
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
  function showTfa(state) {
    $('#tfaOff').hidden = state !== 'off';
    $('#tfaSetup').hidden = state !== 'setup';
    $('#tfaCodes').hidden = state !== 'codes';
    $('#tfaOn').hidden = state !== 'on';
  }
  async function loadTfa() {
    try {
      const st = await api('/api/2fa');
      $('#tfaLeft').textContent = st.enabled ? `${st.recovery_left} recovery codes left` : '';
      if (!$('#tfaSetup').hidden || !$('#tfaCodes').hidden) return;   // don't interrupt a setup in progress
      showTfa(st.enabled ? 'on' : 'off');
    } catch (e) { fail(e); }
  }
  async function loadSessions() {
    try {
      const { sessions } = await api('/api/sessions');
      $('#sessionList').replaceChildren(...sessions.map((x) => el('li', {},
        el('div', { class: 'grow' },
          el('strong', { text: x.current ? 'This session' : (x.ip || 'unknown address') }),
          el('div', { class: 'sub', text: `${x.current ? (x.ip || '') + ' · ' : ''}last active ${ago(x.last)} · signed in ${when(x.created)}` }),
          el('div', { class: 'sub', text: (x.ua || '').slice(0, 80) })),
        x.current ? null : el('button', { class: 'btn small', type: 'button', text: 'Sign out',
          onclick: () => post('/api/sessions/revoke', { id: x.id }).then(loadSessions).catch(fail) }))));
    } catch (e) { fail(e); }
  }
  async function loadCommands() {
    try {
      const { commands } = await api('/api/custom-commands');
      $('#cmdList').textContent = commands.length ? commands.join('\n')
        : 'None. Everything this dashboard runs is on the built-in list.';
      $('#cmdCopy').hidden = !commands.length;
    } catch (e) { fail(e); }
  }
  async function openSettings() {
    const dlg = $('#settings');
    $('#sRetentionMsg').textContent = '';
    $('#pwMsg').textContent = '';
    ['#tfaMsg', '#tfaMsg2', '#tfaMsg3'].forEach((q) => { $(q).textContent = ''; });
    $('#tfaSetup').hidden = true; $('#tfaCodes').hidden = true;
    dlg.showModal();
    selectTab('general');
    loadTfa(); loadSessions(); loadCommands();
    try {
      const s = await api('/api/settings');
      $('#sRetention').value = s.log_retention;
      $('#sRetention').min = s.limits.log_retention[0];
      $('#sRetention').max = s.limits.log_retention[1];
    } catch (e) { fail(e); }
    try {
      const { events, chain_ok: chainOk, chain_broken_at: at } = await api('/api/audit?limit=30');
      $('#auditChain').textContent = chainOk ? '✔ The activity log is intact (each entry is chained to the one before it).'
        : `✖ The activity log was altered or has a gap near entry ${at}. Check the system journal, which has its own copy.`;
      $('#auditChain').className = chainOk ? 'muted' : 'err';
      $('#auditList').replaceChildren(...(events.length ? events.map((ev) => el('li', {},
        el('time', { text: when(ev.t) }), el('strong', { text: ev.action }),
        el('span', { class: 'muted', text: `${ev.user} · ${ev.ip || ''} ${ev.detail || ''}` }))) : [el('li', { class: 'muted', text: 'Nothing yet.' })]));
    } catch (e) { fail(e); }
    try {
      const a = await api('/api/about');
      $('#aboutText').textContent = `Update Dashboard ${a.version} · transport: ${a.transport} · ${a.tls ? 'HTTPS on' + (a.tls_fingerprint ? ' (self-signed, ' + a.tls_fingerprint + ')' : '') : 'plain HTTP (use TLS or an HTTPS reverse proxy)'} · up ${Math.round(a.uptime / 60)} min`;
    } catch { /* optional */ }
  }
  $('#settingsBtn').addEventListener('click', openSettings);
  $('#settingsClose').addEventListener('click', () => $('#settings').close());
  $('#sessionsRevokeAll').addEventListener('click', () => post('/api/sessions/revoke-all').then(() => { toast('Other sessions signed out.'); loadSessions(); }).catch(fail));
  $('#cmdCopy').addEventListener('click', async () => { toast(await copyText($('#cmdList').textContent + '\n') ? 'Copied.' : 'Select the text and copy it.'); });

  $('#tfaBeginForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const r = await post('/api/2fa/begin', { password: $('#tfaPw').value });
      $('#tfaPw').value = '';
      $('#tfaSecret').textContent = r.secret.match(/.{1,4}/g).join(' ');
      $('#tfaUri').textContent = r.uri;
      $('#tfaMsg').textContent = '';
      showTfa('setup');
      $('#tfaCode').focus();
    } catch (e) { $('#tfaMsg').className = 'err'; $('#tfaMsg').textContent = e.message; }
  });
  $('#tfaEnableForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const r = await post('/api/2fa/enable', { code: $('#tfaCode').value });
      $('#tfaCode').value = '';
      $('#tfaCodeList').textContent = r.recovery_codes.join('\n');
      showTfa('codes');
      refreshMe();
    } catch (e) { $('#tfaMsg2').textContent = e.message; }
  });
  $('#tfaCopy').addEventListener('click', async () => { toast(await copyText($('#tfaCodeList').textContent + '\n') ? 'Recovery codes copied.' : 'Select the codes and copy them.'); });
  $('#tfaDone').addEventListener('click', () => { $('#tfaCodeList').textContent = ''; showTfa('on'); loadTfa(); });
  $('#tfaDisableForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await post('/api/2fa/disable', { password: $('#tfaOffPw').value, code: $('#tfaOffCode').value });
      $('#tfaOffPw').value = ''; $('#tfaOffCode').value = '';
      $('#tfaMsg3').textContent = '';
      toast('Two-factor sign-in is off.');
      showTfa('off'); refreshMe();
    } catch (e) { $('#tfaMsg3').textContent = e.message; }
  });
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
      refreshMe();
    } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  });

  // ---------------------------------------------------------------- toolbar wiring
  $('#checkAll').addEventListener('click', () => post('/api/check').then(() => setTimeout(refresh, 400)).catch(fail));
  $('#signOut').addEventListener('click', async () => { try { await post('/api/logout'); } finally { location.replace('/login'); } });
  $('#onlyAction').addEventListener('change', (e) => { ui.only = e.target.checked; store.set('only', ui.only ? '1' : '0'); if (data) render(); });
  $('#sort').addEventListener('change', (e) => { ui.sort = e.target.value; store.set('sort', ui.sort); if (data) render(); });
  $('#hostFilter').addEventListener('change', (e) => { ui.host = e.target.value; if (data) render(); });
  $('#search').addEventListener('input', (e) => { ui.q = e.target.value.trim().toLowerCase(); if (data) render(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && !document.querySelector('dialog[open]')) {
      e.preventDefault();
      $('#search').focus();
    }
  });

  // ---------------------------------------------------------------- settings tabs
  const loaders = { appearance: () => loadTheme(), hosts: () => loadHosts(), integrations: () => loadTokens(), automation: () => loadAutomation() };
  function selectTab(name) {
    document.querySelectorAll('#settings .tab').forEach((t) => {
      const on = t.dataset.pane === name;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      $('#pane-' + t.dataset.pane).hidden = !on;
    });
    if (loaders[name]) loaders[name]();
  }
  document.querySelectorAll('#settings .tab').forEach((t) => {
    t.addEventListener('click', () => selectTab(t.dataset.pane));
    t.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const tabs = [...document.querySelectorAll('#settings .tab')];
      const next = tabs[(tabs.indexOf(t) + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      selectTab(next.dataset.pane);
      next.focus();
    });
  });

  // ---------------------------------------------------------------- appearance
  let themeSaved = null;       // what the server has
  let themeDraft = null;       // what the controls show
  let presets = {};
  const T = {
    mode: $('#thMode'), type: $('#thBgType'), c1: $('#thC1'), c2: $('#thC2'), c3: $('#thC3'), c3on: $('#thC3On'),
    angle: $('#thAngle'), accent: $('#thAccent'), accentOn: $('#thAccentOn'),
  };
  const clone = (x) => JSON.parse(JSON.stringify(x));

  function bgCss(bg) {
    const c = bg.colors;
    if (bg.type === 'solid') return ['none', c[0]];
    if (bg.type === 'linear') return [`linear-gradient(${bg.angle}deg, ${c.join(', ')})`, null];
    if (bg.type === 'radial') return [`radial-gradient(circle at ${50 + (bg.angle % 90)}% 0%, ${c.join(', ')})`, null];
    return ['none', null];
  }
  // Live preview: only validated values are set, as CSS variables (allowed by the CSP, unlike inline style attributes).
  function previewTheme(t) {
    const root = document.documentElement;
    if (t.mode === 'auto') root.removeAttribute('data-mode'); else root.setAttribute('data-mode', t.mode);
    const [img, col] = bgCss(t.background);
    root.style.setProperty('--page-bg-image', img);
    if (col) root.style.setProperty('--page-bg-color', col); else root.style.removeProperty('--page-bg-color');
    if (t.accent) {
      root.style.setProperty('--accent', t.accent);
      root.style.setProperty('--focus', t.accent);
      root.style.setProperty('--accent-text', lum(t.accent) > 0.4 ? '#0b0f17' : '#ffffff');
    } else ['--accent', '--focus', '--accent-text'].forEach((p) => root.style.removeProperty(p));
  }
  function lum(hex) {
    const ch = (i) => { const v = parseInt(hex.slice(i, i + 2), 16) / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * ch(1) + 0.7152 * ch(3) + 0.0722 * ch(5);
  }
  function readTheme() {
    const type = T.type.value;
    const n = { none: 0, solid: 1, linear: T.c3on.checked ? 3 : 2, radial: T.c3on.checked ? 3 : 2 }[type];
    const colors = [T.c1.value, T.c2.value, T.c3.value].slice(0, n);
    return { mode: T.mode.value, accent: T.accentOn.checked ? T.accent.value : '',
      background: { type, colors, angle: Number(T.angle.value) } };
  }
  function writeControls(t) {
    T.mode.value = t.mode;
    T.type.value = t.background.type;
    const c = t.background.colors;
    if (c[0]) T.c1.value = c[0];
    if (c[1]) T.c2.value = c[1];
    T.c3on.checked = !!c[2];
    if (c[2]) T.c3.value = c[2];
    T.angle.value = t.background.angle;
    T.accentOn.checked = !!t.accent;
    if (t.accent) T.accent.value = t.accent;
    syncThemeRows();
  }
  function syncThemeRows() {
    const type = T.type.value;
    $('#thColorsRow').hidden = type === 'none';
    $('#thC2Wrap').hidden = type === 'none' || type === 'solid';
    $('#thC3Wrap').hidden = type === 'none' || type === 'solid';
    $('#thAngleRow').hidden = type === 'none' || type === 'solid';
    $('#thAngleOut').textContent = T.angle.value + '°';
    T.accent.disabled = !T.accentOn.checked;
    T.c3.disabled = !T.c3on.checked;
  }
  function swatchCss(t) {
    const [img, col] = bgCss(t.background);
    return img !== 'none' ? img : col || 'var(--bg)';
  }
  function renderPresets() {
    $('#presetGrid').replaceChildren(...Object.entries(presets).map(([name, t]) => {
      const sw = el('span', { class: 'sw' });
      sw.style.background = swatchCss(t);      // CSSOM write; allowed by the CSP
      const on = JSON.stringify(readTheme()) === JSON.stringify(clean(t));
      return el('button', { class: 'preset', type: 'button', 'aria-pressed': on ? 'true' : 'false',
        onclick: () => { themeDraft = clean(t); writeControls(themeDraft); previewTheme(themeDraft); renderPresets(); },
      }, sw, el('span', { class: 'nm', text: name }));
    }));
  }
  const clean = (t) => ({ mode: t.mode, accent: t.accent || '', background: { type: t.background.type, colors: [...t.background.colors], angle: t.background.angle } });
  function onThemeInput() { syncThemeRows(); themeDraft = readTheme(); previewTheme(themeDraft); renderPresets(); $('#thMsg').textContent = ''; }
  Object.values(T).forEach((i) => i.addEventListener('input', onThemeInput));
  async function loadTheme() {
    try {
      const r = await api('/api/theme');
      presets = r.presets;
      themeSaved = clean(r.theme);
      themeDraft = clean(r.theme);
      writeControls(themeDraft);
      renderPresets();
    } catch (e) { fail(e); }
  }
  function reloadThemeCss() { $('#themeCss').setAttribute('href', '/theme.css?v=' + Date.now()); }
  function settle(t) {
    // The saved stylesheet now matches; drop the preview overrides so there is one source of truth.
    const root = document.documentElement;
    ['--page-bg-image', '--page-bg-color', '--accent', '--focus', '--accent-text'].forEach((p) => root.style.removeProperty(p));
    if (t.mode === 'auto') root.removeAttribute('data-mode'); else root.setAttribute('data-mode', t.mode);
    reloadThemeCss();
  }
  $('#thSave').addEventListener('click', async () => {
    try {
      const out = await post('/api/theme', { theme: readTheme() });
      themeSaved = clean(out.theme); themeDraft = clean(out.theme);
      settle(out.theme);
      $('#thMsg').className = 'muted'; $('#thMsg').textContent = 'Saved.';
    } catch (e) { $('#thMsg').className = 'err'; $('#thMsg').textContent = e.message; }
  });
  $('#thRevert').addEventListener('click', () => { if (themeSaved) { themeDraft = clean(themeSaved); writeControls(themeDraft); previewTheme(themeDraft); renderPresets(); } });
  $('#thReset').addEventListener('click', async () => {
    try {
      const out = await post('/api/theme/reset');
      themeSaved = clean(out.theme); themeDraft = clean(out.theme);
      writeControls(themeDraft); settle(out.theme); renderPresets();
      $('#thMsg').className = 'muted'; $('#thMsg').textContent = 'Back to the default look.';
    } catch (e) { fail(e); }
  });
  // leaving the dialog with unsaved changes drops the preview
  $('#settings').addEventListener('close', () => { if (themeSaved) settle(themeSaved); });

  // ---------------------------------------------------------------- Proxmox hosts
  const H = { name: $('#hName'), addr: $('#hAddr'), ips: $('#hIps'), allow: $('#hAllow') };
  let hKey = { keys: [], fp: '', known: false, checked: false };
  function resetHKey() {
    hKey = { keys: [], fp: '', known: false, checked: false };
    $('#hKeyList').replaceChildren(); $('#hKeyState').textContent = ''; $('#hKeyConfirmRow').hidden = true; $('#hTrust').checked = false;
  }
  async function loadHosts() {
    try {
      const { hosts } = await api('/api/hosts');
      $('#hostList').replaceChildren(...(hosts.length ? hosts.map((h) => el('li', {},
        el('div', { class: 'grow' }, el('strong', { text: h.name }), el('span', { class: 'sub', text: ` ${h.host || ''} · ${h.containers} managed` + (h.primary ? ' · from the config file' : '') }),
          h.error ? el('div', { class: 'err', text: h.error }) : null),
        h.primary ? null : el('button', { class: 'btn small danger', type: 'button', text: 'Remove', onclick: async () => {
          if (!await ask(`Remove ${h.name}?`, 'The dashboard stops managing its containers. Nothing on the node is changed; remove the dashboard key and the gate there yourself if you want.', 'Remove')) return;
          try { await post('/api/hosts/remove', { idx: h.idx }); toast('Host removed.'); loadHosts(); refresh(); } catch (e) { fail(e); }
        } }))) : [el('li', { class: 'muted', text: 'No Proxmox host is configured. Add one below.' })]));
    } catch (e) { fail(e); }
  }
  $('#hScript').addEventListener('click', async () => {
    const ips = H.ips.value.trim().split(/[\s,]+/).filter(Boolean).join(',');
    if (!ips) { $('#hScriptMsg').textContent = 'Enter this dashboard’s address first (as the node sees it).'; return; }
    const allow = H.allow.value.trim().split(/[\s,]+/).filter(Boolean).join(',');
    try {
      const r = await api(`/api/hosts/setup-script?ips=${encodeURIComponent(ips)}&allow=${encodeURIComponent(allow)}`);
      $('#hScriptText').textContent = r.script;
      $('#hScriptText').hidden = false; $('#hScriptCopy').hidden = false;
      $('#hScriptMsg').textContent = 'Read it, then run it as root in the node’s shell.';
    } catch (e) { $('#hScriptMsg').textContent = e.message; }
  });
  $('#hScriptCopy').addEventListener('click', async () => { toast(await copyText($('#hScriptText').textContent) ? 'Script copied.' : 'Select the text and copy it.'); });
  H.addr.addEventListener('input', resetHKey);
  H.addr.addEventListener('change', async () => {      // prefill "this dashboard's address" with the one that reaches the node
    if (H.ips.value.trim() || !H.addr.value.trim()) return;
    try { const r = await api('/api/hosts/my-ip?host=' + encodeURIComponent(H.addr.value.trim())); if (r.ip && !H.ips.value.trim()) H.ips.value = r.ip; } catch { /* optional */ }
  });
  $('#hKeyBtn').addEventListener('click', async () => {
    const host = H.addr.value.trim();
    if (!host) { $('#hKeyState').textContent = 'Enter the address first.'; return; }
    $('#hKeyState').textContent = 'Asking the node…';
    try {
      const r = await post('/api/hosts/hostkey', { host });
      hKey = { keys: r.keys, fp: r.keys[0] ? r.keys[0].fingerprint : '', known: r.known, checked: true };
      $('#hKeyList').replaceChildren(...r.keys.map((k, i) => {
        const radio = el('input', { type: 'radio', name: 'hhk', id: 'hhk' + i, 'aria-label': k.type + ' ' + k.fingerprint });
        radio.checked = i === 0;
        radio.addEventListener('change', () => { hKey.fp = k.fingerprint; $('#hTrust').checked = false; });
        return el('label', { class: 'fp', for: 'hhk' + i }, radio, el('span', { text: `${k.type}  ${k.fingerprint}` }));
      }));
      $('#hKeyConfirmRow').hidden = r.known || !r.keys.length;
      $('#hKeyState').textContent = r.known ? '✔ Already trusted.' : r.keys.length ? 'Compare with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the node.' : r.message;
    } catch (e) { $('#hKeyState').textContent = e.message; }
  });
  $('#hAdd').addEventListener('click', async () => {
    const msg = $('#hMsg');
    msg.className = 'err'; msg.textContent = '';
    const body = { name: H.name.value.trim(), host: H.addr.value.trim() };
    if (hKey.checked && !hKey.known && $('#hTrust').checked && hKey.fp) body.trust_fingerprint = hKey.fp;
    $('#hAdd').disabled = true;
    try {
      await post('/api/hosts/add', body);
      toast('Host added.');
      H.name.value = ''; H.addr.value = ''; resetHKey();
      $('#hScriptText').hidden = true; $('#hScriptCopy').hidden = true;
      loadHosts(); refresh();
    } catch (e) { msg.textContent = e.message; }
    finally { $('#hAdd').disabled = false; }
  });

  // ---------------------------------------------------------------- API tokens (Homarr)
  async function loadTokens() {
    $('#tokUrl').textContent = `${location.origin}/api/v1/summary`;
    try {
      const { tokens } = await api('/api/tokens');
      $('#tokList').replaceChildren(...(tokens.length ? tokens.map((t) => el('li', {},
        el('div', { class: 'grow' }, el('strong', { text: t.name }),
          el('div', { class: 'sub', text: `${t.detail ? 'with container names' : 'counts only'} · created ${when(t.created)} · ${t.last_used ? 'last used ' + ago(t.last_used) : 'never used'}` })),
        el('button', { class: 'btn small danger', type: 'button', text: 'Revoke', onclick: async () => {
          if (!await ask(`Revoke “${t.name}”?`, 'Anything using this token stops working.', 'Revoke')) return;
          try { await post('/api/tokens/revoke', { id: t.id }); loadTokens(); } catch (e) { fail(e); }
        } }))) : [el('li', { class: 'muted', text: 'No tokens yet.' })]));
      const prev = await api('/api/summary-preview');
      $('#summaryPreview').textContent = JSON.stringify(prev, null, 2);
    } catch (e) { fail(e); }
  }
  $('#tokForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('#tokMsg').textContent = '';
    try {
      const r = await post('/api/tokens/create', { name: $('#tokName').value.trim(), detail: $('#tokDetail').checked });
      $('#tokValue').textContent = r.token;
      $('#tokNew').hidden = false;
      $('#tokName').value = '';
      loadTokens();
    } catch (e) { $('#tokMsg').textContent = e.message; }
  });
  $('#tokCopy').addEventListener('click', async () => { toast(await copyText($('#tokValue').textContent) ? 'Token copied.' : 'Select the token and copy it.'); });

  // ---------------------------------------------------------------- install apps (plan only)
  const cart = [];             // [{slug, app, hostname, ctid, cpu, ram, disk, net, gateway}]
  const cat = { q: '', tag: '', offset: 0, total: 0, rows: [], timer: null, poll: null };
  const OPT_FIELDS = [['hostname', 'Hostname'], ['ctid', 'CT ID'], ['cpu', 'CPU cores'], ['ram', 'RAM (MB)'], ['disk', 'Disk (GB)'], ['net', 'IP (dhcp or a.b.c.d/24)'], ['gateway', 'Gateway']];

  function renderCart() {
    $('#cartEmpty').hidden = cart.length > 0;
    $('#cartCount').textContent = cart.length ? `(${cart.length})` : '';
    $('#cartList').replaceChildren(...cart.map((c, i) => {
      const inputs = OPT_FIELDS.map(([k, label]) => {
        const inp = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'default', 'aria-label': `${c.app} ${label}` });
        inp.value = c[k] || '';
        inp.addEventListener('input', () => { c[k] = inp.value; });
        return el('label', {}, label, inp);
      });
      const d = c.defaults || {};
      return el('li', {},
        el('div', { class: 'row1' }, el('strong', { class: 'grow', text: c.app }),
          el('span', { class: 'sub', text: d.cpu ? `default ${d.cpu} CPU · ${d.ram} MB · ${d.disk} GB` : '' }),
          el('button', { class: 'btn small ghost', type: 'button', text: 'Remove', onclick: () => { cart.splice(i, 1); renderCart(); renderCatalog(); } })),
        el('div', { class: 'opts' }, ...inputs));
    }));
  }
  function renderCatalog() {
    $('#catList').replaceChildren(...(cat.rows.length ? cat.rows.map((e) => {
      const inCart = cart.some((c) => c.slug === e.slug);
      return el('li', { class: 'stackli' },
        el('div', { class: 'row1' },
          el('div', { class: 'grow' }, el('div', { class: 'nm', text: e.app }), el('div', { class: 'sub', text: (e.tags || []).slice(0, 4).join(' · ') })),
          e.page ? ext(e.page, 'info ↗') : null,
          el('button', { class: 'btn small', type: 'button', text: inCart ? 'Add another' : 'Add', onclick: () => {
            cart.push({ slug: e.slug, app: e.app, defaults: { cpu: e.cpu, ram: e.ram, disk: e.disk } });
            renderCart(); renderCatalog();
          } })));
    }) : [el('li', { class: 'muted', text: 'No matches.' })]));
    $('#catMore').hidden = cat.rows.length >= cat.total;
  }
  async function loadCatalog(append) {
    if (!append) cat.offset = 0;
    try {
      const p = new URLSearchParams({ q: cat.q, tag: cat.tag, limit: '30', offset: String(cat.offset) });
      const r = await api('/api/catalog?' + p);
      cat.total = r.total;
      cat.rows = append ? cat.rows.concat(r.results) : r.results;
      const st = r.status;
      if (!$('#catTags').childElementCount && r.tags.length) renderTags(r.tags);
      $('#catStatus').textContent = st.loading ? `Loading the app library… ${st.progress ? st.progress.join(' / ') : ''}`
        : st.error && !st.count ? `Could not load the library: ${st.error}`
          : `${r.total} app${r.total === 1 ? '' : 's'}${st.commit ? ' · library version ' + st.commit.slice(0, 7) : ''}`;
      renderCatalog();
      clearTimeout(cat.poll);
      if (st.loading) cat.poll = setTimeout(() => { if ($('#install').open) loadCatalog(false); }, 2500);
    } catch (e) { $('#catStatus').textContent = e.message; }
  }
  function renderTags(tags) {
    $('#catTags').replaceChildren(...tags.map((t) => el('button', { class: 'tagbtn', type: 'button', 'aria-pressed': cat.tag === t ? 'true' : 'false', text: t, onclick: () => {
      cat.tag = cat.tag === t ? '' : t;
      [...$('#catTags').children].forEach((b) => b.setAttribute('aria-pressed', b.textContent === cat.tag ? 'true' : 'false'));
      loadCatalog(false);
    } })));
  }
  $('#catQ').addEventListener('input', (e) => { clearTimeout(cat.timer); cat.timer = setTimeout(() => { cat.q = e.target.value.trim(); loadCatalog(false); }, 250); });
  $('#catMore').addEventListener('click', () => { cat.offset = cat.rows.length; loadCatalog(true); });

  function openInstall() {
    $('#installPick').hidden = false; $('#installPlan').hidden = true; $('#planErr').textContent = '';
    const hs = (data && data.hosts) || [];
    $('#planHost').replaceChildren(...(hs.length ? hs : [{ idx: 0, name: 'Proxmox node' }]).map((h) => el('option', { value: String(h.idx), text: h.name })));
    renderCart();
    $('#install').showModal();
    loadCatalog(false);
    loadNodeInfo();
  }
  async function loadNodeInfo() {
    const fill = (id, items) => $(id).replaceChildren(...(items || []).map((v) => el('option', { value: v })));
    try {
      const n = await api('/api/node-info?host=' + (Number($('#planHost').value) || 0));
      fill('#dlBridge', n.bridges); fill('#dlRootdir', n.rootdir); fill('#dlVztmpl', n.vztmpl);
    } catch { /* suggestions are optional */ }
  }
  $('#planHost').addEventListener('change', loadNodeInfo);
  $('#installBtn').addEventListener('click', openInstall);
  $('#installClose').addEventListener('click', () => $('#install').close());
  $('#planBack').addEventListener('click', () => { $('#installPick').hidden = false; $('#installPlan').hidden = true; });
  $('#planBtn').addEventListener('click', async () => {
    $('#planErr').textContent = '';
    if (!cart.length) { $('#planErr').textContent = 'Add at least one app first.'; return; }
    const bridge = $('#planBridge').value.trim(), storage = $('#planStorage').value.trim(), tpl = $('#planTplStorage').value.trim();
    const apps = cart.map((c) => {
      const o = { slug: c.slug };
      OPT_FIELDS.forEach(([k]) => { if ((c[k] || '').trim()) o[k] = c[k].trim(); });
      if (bridge) o.bridge = bridge;
      if (storage) o.storage = storage;
      if (tpl) o.template_storage = tpl;
      return o;
    });
    $('#planBtn').disabled = true;
    try {
      const plan = await post('/api/install/plan', { apps, host: Number($('#planHost').value) || 0, opt_out_diagnostics: $('#planDiag').checked });
      $('#planNode').textContent = $('#planHost').selectedOptions[0] ? $('#planHost').selectedOptions[0].textContent : 'your Proxmox node';
      $('#planApps').replaceChildren(...plan.apps.map((a) => el('li', {},
        el('div', { class: 'row1' }, el('strong', { class: 'grow', text: a.app }), ext(a.review, 'read the script ↗'), a.page ? ext(a.page, 'info ↗') : null),
        el('div', { class: 'sub', text: `${a.lines} lines · sha256 ${a.sha256.slice(0, 16)}…` + (Object.keys(a.overrides).length ? ' · ' + Object.entries(a.overrides).map(([k, v]) => `${k.replace('var_', '')}=${v}`).join(' ') : ' · script defaults') }))));
      plan.warnings.forEach((w) => $('#planApps').append(el('li', { class: 'banner', text: w })));
      $('#planScript').textContent = plan.script;
      $('#planCopyMsg').textContent = '';
      $('#installPick').hidden = true; $('#installPlan').hidden = false;
    } catch (e) { $('#planErr').textContent = e.message; }
    finally { $('#planBtn').disabled = false; }
  });
  $('#planCopy').addEventListener('click', async () => { $('#planCopyMsg').textContent = await copyText($('#planScript').textContent) ? 'Copied. Paste it into the Proxmox shell.' : 'Select the text and copy it.'; });

  // ---------------------------------------------------------------- automation (notifications, automatic system updates)
  const AU = { kind: $('#nKind'), url: $('#nUrl'), on: $('#nOn'), hour: $('#aHour') };
  let autoSet = new Set();
  for (let h = 0; h < 24; h += 1) AU.hour.append(el('option', { value: String(h), text: String(h).padStart(2, '0') + ':00' }));
  function renderAuto() {
    const q = $('#autoFilter').value.trim().toLowerCase();
    const rows = ((data && data.services) || []).filter((s) => !q || s.name.toLowerCase().includes(q));
    $('#autoList').replaceChildren(...(rows.length ? rows.map((s) => {
      const box = el('input', { type: 'checkbox', 'aria-label': `Update ${s.name} automatically` });
      box.checked = autoSet.has(s.ctid);
      box.addEventListener('change', () => { if (box.checked) autoSet.add(s.ctid); else autoSet.delete(s.ctid); });
      return el('li', {}, el('div', { class: 'grow' }, el('div', { class: 'nm', text: s.name }),
        el('div', { class: 'sub', text: (s.custom ? 'SSH host' : `CT ${s.real_ctid}`) + (multiHost() && s.host ? ' · ' + s.host : '') + (s.snapshot ? ' · snapshot first' : ' · no snapshot') })),
        el('label', {}, box, 'Automatic'));
    }) : [el('li', { class: 'muted', text: 'No containers.' })]));
  }
  async function loadAutomation() {
    try {
      const a = await api('/api/automation');
      AU.kind.value = a.notify.kind; AU.url.value = a.notify.url; AU.on.checked = a.notify.enabled;
      AU.hour.value = String(a.auto.hour);
      autoSet = new Set(a.auto.uids);
      renderAuto();
    } catch (e) { fail(e); }
  }
  $('#autoFilter').addEventListener('input', renderAuto);
  $('#nSave').addEventListener('click', async () => {
    const m = $('#nMsg');
    try {
      await post('/api/automation/notify', { kind: AU.kind.value, url: AU.url.value.trim(), enabled: AU.on.checked });
      m.className = 'muted'; m.textContent = 'Saved.';
    } catch (e) { m.className = 'err'; m.textContent = e.message; }
  });
  $('#nTest').addEventListener('click', async () => {
    const m = $('#nMsg');
    m.className = 'muted'; m.textContent = 'Sending…';
    try {
      await post('/api/automation/notify', { kind: AU.kind.value, url: AU.url.value.trim(), enabled: AU.on.checked });
      const r = await post('/api/automation/notify/test');
      m.className = r.ok ? 'muted' : 'err'; m.textContent = r.ok ? 'Sent. Check your device.' : 'Failed: ' + r.message;
    } catch (e) { m.className = 'err'; m.textContent = e.message; }
  });
  $('#autoSave').addEventListener('click', async () => {
    const m = $('#autoMsg');
    try {
      const r = await post('/api/automation/auto', { uids: [...autoSet], hour: Number(AU.hour.value) });
      m.className = 'muted'; m.textContent = `Saved: ${r.auto.uids.length} container${r.auto.uids.length === 1 ? '' : 's'} after ${String(r.auto.hour).padStart(2, '0')}:00.`;
      refresh();
    } catch (e) { m.className = 'err'; m.textContent = e.message; }
  });

  // ---------------------------------------------------------------- start
  let me = null;
  function refreshMe() { return api('/api/me').then((m) => { me = m; if (data) render(); }).catch(() => {}); }
  refreshMe();
  refresh();
})();
