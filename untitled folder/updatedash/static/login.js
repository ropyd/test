(() => {
  const form = document.getElementById('loginForm');
  const err = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'updatedash' },
        body: JSON.stringify({ username: form.username.value, password: form.password.value }),
      });
      let data = {};
      try { data = await res.json(); } catch { /* not JSON */ }
      if (res.ok) { location.replace('/'); return; }
      err.textContent = data.error || 'Sign-in failed.';
      form.password.value = '';
      form.password.focus();
    } catch {
      err.textContent = 'Cannot reach the server.';
    } finally {
      btn.disabled = false;
    }
  });
})();
