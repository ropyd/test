(() => {
  const $ = (s) => document.querySelector(s);
  const rows = $('#rows');
  const chips = $('#chips');
  const sub = $('#sub');
  const checkAllBtn = $('#checkAll');
  const logPanel = $('#logpanel');
  const logPre = $('#log');
  const logTitle = $('#logtitle');
  const logStatus = $('#logstatus');
  const dlg = $('#confirm');

  let watching = null;
  let busyPoll = false;

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
    unknown: ['Unknown', ''],
    error: ['Unreachable', 'error'],
  };

  function ask(title, body, okLabel) {
    $('#confirmTitle').textContent = title;
    $('#confirmBody').textContent = body;
    $('#confirmOk').textContent = okLabel;
    return new Promise((resolve) => {
      dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), { once: true });
      dlg.returnValue = 'cancel';
      dlg.showModal();
    });
  }

  async function startUpdate(svc, kind) {
    const os = kind === 'os';
    const ok = await ask(
      os ? `Upgrade OS packages in ${svc.name}?` : `Update ${svc.name}?`,
      (os ? 'Runs apt upgrade' : 'Runs the application update') +
        ` inside CT ${svc.ctid}. A snapshot is taken first when snapshots are enabled.`,
      os ? 'Upgrade' : 'Update');
    if (!ok) return;
    try {
      const { job } = await post('/api/update', { name: svc.name, kind });
      watch(job, `${svc.name} ${os ? 'OS packages' : 'update'}`);
      refresh();
    } catch (e) {
      alert_(e.message);
    }
  }

  function alert_(msg) {
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

  function render(data) {
    const busy = data.services.some((s) => s.checking || s.running);
    sub.textContent = data.last_sweep
      ? `Last full check ${ago(data.last_sweep)} · auto-checks every ${data.interval} min`
      : 'Running first check…';
    checkAllBtn.disabled = busy;

    const unreachable = data.services.filter((s) => s.status === 'error').length;
    chips.replaceChildren(...[
      el('span', { class: 'chip ' + (data.updates ? 'warn' : 'ok'),
        text: data.updates ? `${data.updates} update${data.updates > 1 ? 's' : ''} available` : 'Everything up to date' }),
      data.os_updates ? el('span', { class: 'chip', text: `${data.os_updates} with OS package updates` }) : null,
      unreachable ? el('span', { class: 'chip bad', text: `${unreachable} unreachable` }) : null,
    ].filter(Boolean));

    rows.replaceChildren(...data.services.map((s) => {
      const [label, cls] = STATUS[s.status] || STATUS.unknown;
      const statusCell = el('td', {},
        el('span', { class: 'badge ' + (s.running ? 'running' : cls),
          title: s.error || '', text: s.running ? 'Updating…' : s.checking ? 'Checking…' : label }),
        s.error ? el('div', { class: 'sub', text: s.error.slice(0, 120) }) : null);
      const osCell = el('td', {}, s.os_updates == null ? '–' :
        s.os_updates === 0 ? 'up to date' : `${s.os_updates} pending`);
      const actions = el('td', { class: 'right' },
        el('button', { class: 'btn small ghost', disabled: s.checking || s.running,
          onclick: () => post('/api/check', { name: s.name }).then(refresh).catch((e) => alert_(e.message)),
          text: 'Check' }),
        s.os_updates > 0 ? el('button', { class: 'btn small', disabled: s.running,
          onclick: () => startUpdate(s, 'os'), text: 'Upgrade OS' }) : null,
        el('button', { class: 'btn small ' + (s.status === 'update' ? 'primary' : ''),
          disabled: s.running || s.status === 'error',
          onclick: () => startUpdate(s, 'app'),
          text: s.status === 'update' ? 'Update' : 'Update anyway' }),
        s.job ? el('button', { class: 'btn small ghost',
          onclick: () => watch(s.job, `${s.name} last job`), text: 'Log' }) : null);
      return el('tr', {},
        el('td', {}, el('div', { class: 'svc', text: s.name }),
          el('div', { class: 'sub', text: `CT ${s.ctid} · checked ${ago(s.checked_at)}` })),
        el('td', { class: 'ver', text: s.installed || '–' }),
        el('td', { class: 'ver', text: s.latest || '–' }),
        statusCell, osCell, actions);
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

  checkAllBtn.addEventListener('click', () => {
    post('/api/check').then(() => setTimeout(refresh, 400)).catch((e) => alert_(e.message));
  });
  $('#logclose').addEventListener('click', () => { logPanel.hidden = true; watching = null; });

  refresh();
})();
