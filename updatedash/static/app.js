(() => {
  const $ = (s) => document.querySelector(s);
  const rows = $('#rows');
  const chips = $('#chips');
  const sub = $('#sub');
  const checkAllBtn = $('#checkAll');
  const onlyAction = $('#onlyAction');
  const logPanel = $('#logpanel');
  const logPre = $('#log');
  const logTitle = $('#logtitle');
  const logStatus = $('#logstatus');
  const dlg = $('#confirm');

  let watching = null;
  let busyPoll = false;
  let last = null;

  try { onlyAction.checked = localStorage.getItem('onlyAction') === '1'; } catch { /* storage blocked */ }

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids) if (kid != null) n.append(kid);
    return n;
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { 'X-Requested-With': 'updatedash', 'Content-Type': 'application/json' },
    });
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    if (!res.ok) throw new Error((data && data.error) || res.statusText);
    return data;
  }
  const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });

  function ago(ts) {
    if (!ts) return 'never';
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }

  const STATUS = {
    update: ['Update available', 'update'],
    current: ['Up to date', 'current'],
    unknown: ['Version unknown', ''],
    error: ['Unreachable', 'error'],
    stopped: ['Stopped', 'stopped'],
    os: ['OS updates only', 'os'],
    nocheck: ['No app check', 'nocheck'],
  };
  // rows hidden when "only needing action" is on
  const QUIET = new Set(['current', 'nocheck', 'stopped']);

  function ask(title, body, okLabel, extra) {
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

  async function startUpdate(svc, kind) {
    const os = kind === 'os';
    const extra = [];
    if (!os && (svc.installed || svc.latest)) {
      extra.push(el('p', { class: 'verline' },
        el('span', { class: 'ver', text: svc.installed || 'unknown' }),
        el('span', { class: 'arrow', text: '→' }),
        el('span', { class: 'ver newver', text: svc.latest || 'latest' }),
        svc.link ? el('span', {}, ' · ', ext(svc.link, 'release notes ↗')) : null));
      if (svc.notes) extra.push(el('pre', { class: 'notes', text: svc.notes }));
    }
    const ok = await ask(
      os ? `Upgrade OS packages in ${svc.name}?` : `Update ${svc.name}?`,
      (os ? 'Runs apt upgrade' : 'Runs the application update') +
        ` inside CT ${svc.ctid} (${svc.name}). A snapshot is taken first when snapshots are enabled.`,
      os ? 'Upgrade' : 'Update', extra);
    if (!ok) return;
    try {
      const { job } = await post('/api/update', { ctid: svc.ctid, kind });
      watch(job, `${svc.name} (CT ${svc.ctid}) ${os ? 'OS packages' : 'update'}`);
      refresh();
    } catch (e) {
      showError(e.message);
    }
  }

  function showError(msg) {
    logPanel.hidden = false;
    logTitle.textContent = 'Error';
    logStatus.textContent = 'failed';
    logStatus.className = 'badge failed';
    logPre.textContent = msg;
  }

  async function watch(jobId, title) {
    watching = jobId;
    logPanel.hidden = false;
    logTitle.textContent = title;
    logPre.textContent = '';
    let since = 0;
    while (watching === jobId) {
      try {
        const j = await api(`/api/jobs/${jobId}?since=${since}`);
        if (j.lines.length) {
          const stick = logPre.scrollTop + logPre.clientHeight >= logPre.scrollHeight - 30;
          logPre.textContent += j.lines.join('\n') + '\n';
          if (stick) logPre.scrollTop = logPre.scrollHeight;
        }
        since = j.next;
        logStatus.textContent = j.status;
        logStatus.className = 'badge ' + j.status;
        if (j.status !== 'running') { refresh(); return; }
      } catch (e) {
        logStatus.textContent = 'error';
        logStatus.className = 'badge error';
        return;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  function ext(href, text) {
    return el('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
  }

  function chip(text, cls) { return el('span', { class: 'chip' + (cls ? ' ' + cls : ''), text }); }

  function render(data) {
    last = data;
    const busy = data.services.some((s) => s.checking || s.running);
    sub.textContent = data.last_sweep
      ? `${data.total} containers · last full check ${ago(data.last_sweep)} · auto-checks every ${data.interval} min`
      : 'Running first check…';
    checkAllBtn.disabled = busy;

    const upd = data.updates;
    chips.replaceChildren(...[
      upd ? chip(`${upd} app update${upd > 1 ? 's' : ''} available`, 'warn')
        : data.errors ? chip('No app updates found', '') : chip('All apps up to date', 'ok'),
      data.os_pending ? chip(`${data.os_pending} with OS package updates`, '') : null,
      data.errors ? chip(`${data.errors} unreachable`, 'bad') : null,
      data.stopped ? chip(`${data.stopped} stopped`, '') : null,
      data.inventory_error ? chip(data.inventory_error, 'bad') : null,
    ].filter(Boolean));

    const shown = data.services.filter((s) => !onlyAction.checked || !QUIET.has(s.status) || s.running);
    if (!shown.length) {
      rows.replaceChildren(el('tr', {}, el('td', { colspan: '6', class: 'empty',
        text: data.services.length ? 'Nothing needs attention.' : 'No containers are managed yet. Click "Manage containers" to add some.' })));
      return busy;
    }
    rows.replaceChildren(...shown.map((s) => {
      const [label, cls] = STATUS[s.status] || STATUS.unknown;
      const statusCell = el('td', {},
        el('span', { class: 'badge ' + (s.running ? 'running' : cls),
          title: s.error || '', text: s.running ? 'Updating…' : s.checking ? 'Checking…' : label }),
        s.error ? el('div', { class: 'sub', text: s.error.slice(0, 120) }) : null);
      const stopped = s.status === 'stopped';
      const osCell = el('td', {}, stopped || s.os_updates == null ? '–' :
        s.os_updates === 0 ? 'up to date' : `${s.os_updates} pending`);
      const actions = el('td', { class: 'right' },
        el('button', { class: 'btn small ghost', disabled: s.checking || s.running || stopped,
          onclick: () => post('/api/check', { ctid: s.ctid }).then(refresh).catch((e) => showError(e.message)),
          text: 'Check' }),
        s.os_updates > 0 ? el('button', { class: 'btn small', disabled: s.running,
          onclick: () => startUpdate(s, 'os'), text: 'Upgrade OS' }) : null,
        s.can_app_update && !stopped ? el('button', {
          class: 'btn small ' + (s.status === 'update' ? 'primary' : ''),
          disabled: s.running || s.status === 'error',
          onclick: () => startUpdate(s, 'app'),
          text: s.status === 'update' ? 'Update' : 'Update anyway' }) : null,
        s.running ? el('button', { class: 'btn small',
          onclick: () => post('/api/cancel', { ctid: s.ctid }).then(refresh).catch((e) => showError(e.message)),
          text: 'Cancel' }) : null,
        s.job ? el('button', { class: 'btn small ghost',
          onclick: () => watch(s.job, `${s.name} (CT ${s.ctid}) last job`), text: 'Log' }) : null);
      const instCell = s.installed ? el('td', { class: 'ver', text: s.installed })
        : stopped ? el('td', { class: 'ver', text: '–' })
        : el('td', { class: 'ver' }, el('span', { class: 'hint', title: s.installed_hint || '', text: 'unknown' }));
      const upd = s.status === 'update';
      const latestCell = el('td', { class: 'ver' },
        s.latest ? (upd ? el('span', { class: 'arrow', text: '→ ' }) : null) : null,
        s.latest ? (s.link ? el('a', { class: upd ? 'newver' : '', href: s.link, target: '_blank',
          rel: 'noopener noreferrer', title: 'Release notes / changelog', text: s.latest + ' ↗' })
          : el('span', { class: upd ? 'newver' : '', text: s.latest })) : '–');
      return el('tr', {},
        el('td', {}, el('div', { class: 'svc', text: s.name }),
          el('div', { class: 'sub' }, `CT ${s.ctid}${s.checked_at ? ' · checked ' + ago(s.checked_at) : ''}`,
            !s.latest && s.link ? el('span', {}, ' · ', ext(s.link, 'changelog ↗')) : null)),
        instCell, latestCell, statusCell, osCell, actions);
    }));
    return busy;
  }

  async function refresh() {
    if (busyPoll) return;
    busyPoll = true;
    try {
      const busy = render(await api('/api/services'));
      schedule(busy ? 2000 : 15000);
    } catch (e) {
      sub.textContent = 'Cannot reach the server: ' + e.message;
      schedule(10000);
    } finally {
      busyPoll = false;
    }
  }

  let timer = null;
  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(refresh, ms);
  }

  // ---- manage containers
  const mdlg = $('#manage');
  const mlist = $('#manageList');
  const mmsg = $('#manageMsg');
  const mfilter = $('#manageFilter');
  let inv = null;

  function renderManage() {
    const q = mfilter.value.trim().toLowerCase();
    const items = (inv ? inv.containers : []).filter((c) => !q || c.name.toLowerCase().includes(q) || String(c.ctid).includes(q));
    mlist.replaceChildren(...items.map((c) => {
      const box = el('input', { type: 'checkbox', checked: c.managed, 'aria-label': `Manage ${c.name}`,
        disabled: c.locked });
      box.checked = c.managed;
      box.addEventListener('change', async () => {
        const want = box.checked;
        box.disabled = true;
        mmsg.className = 'muted';
        mmsg.textContent = `${want ? 'Adding' : 'Removing'} ${c.name}…`;
        try {
          await post('/api/allow', { ctid: c.ctid, action: want ? 'add' : 'remove' });
          c.managed = want;
          mmsg.textContent = `${c.name} ${want ? 'added' : 'removed'}.`;
          refresh();
        } catch (e) {
          box.checked = !want;
          mmsg.className = 'err';
          mmsg.textContent = e.message;
        } finally {
          box.disabled = false;
        }
      });
      return el('li', {},
        el('div', { class: 'grow' }, el('div', { class: 'nm', text: c.name }),
          el('div', { class: 'sub', text: `CT ${c.ctid}` })),
        el('span', { class: 'badge ' + (c.status === 'running' ? 'current' : 'stopped'), text: c.status }),
        c.locked ? el('span', { class: 'badge stopped', title: 'Protected on the Proxmox host: edit /etc/updatedash-gate.allow by hand',
          text: 'Locked' }) : null,
        el('label', {}, box, 'Managed'));
    }));
  }

  async function openManage() {
    mmsg.className = 'muted';
    mmsg.textContent = 'Loading containers…';
    mlist.replaceChildren();
    mfilter.value = '';
    mdlg.showModal();
    try {
      inv = await api('/api/inventory');
      if (!inv.manage) {
        mmsg.className = 'err';
        mmsg.textContent = 'Managing containers from here is switched off on the Proxmox host (' + inv.message +
          '). Create /etc/updatedash-gate.manage there, or edit /etc/updatedash-gate.allow by hand.';
        return;
      }
      mmsg.textContent = 'Tick a container to let the dashboard check and update it. Untick to stop managing it.';
      renderManage();
    } catch (e) {
      mmsg.className = 'err';
      mmsg.textContent = e.message;
    }
  }
  $('#manageBtn').addEventListener('click', openManage);
  $('#manageClose').addEventListener('click', () => mdlg.close());
  mfilter.addEventListener('input', renderManage);

  checkAllBtn.addEventListener('click', () => {
    post('/api/check').then(() => setTimeout(refresh, 400)).catch((e) => showError(e.message));
  });
  onlyAction.addEventListener('change', () => {
    try { localStorage.setItem('onlyAction', onlyAction.checked ? '1' : '0'); } catch { /* storage blocked */ }
    if (last) render(last);
  });
  $('#logclose').addEventListener('click', () => { logPanel.hidden = true; watching = null; });

  // Copy the log. navigator.clipboard only exists on HTTPS/localhost, so fall back to a hidden textarea
  // (this dashboard is often opened over plain http://ip:8099).
  const copyBtn = $('#logcopy');
  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
    }
    const ta = el('textarea', { readonly: true, 'aria-hidden': 'true', style: 'position:fixed;left:-9999px;top:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
  copyBtn.addEventListener('click', async () => {
    const title = logTitle.textContent;
    const text = `${title} [${logStatus.textContent}]\n\n${logPre.textContent}`.trimEnd() + '\n';
    const ok = await copyText(text);
    if (!ok) {  // last resort: select the log so Ctrl/Cmd+C works
      const r = document.createRange();
      r.selectNodeContents(logPre);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
    }
    copyBtn.textContent = ok ? 'Copied' : 'Press Ctrl/Cmd+C';
    setTimeout(() => { copyBtn.textContent = 'Copy log'; }, 2000);
  });

  refresh();
})();
