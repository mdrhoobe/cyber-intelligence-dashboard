/* ── Theme ──────────────────────────────────────── */
function applyTheme(theme) {
  const isLight = theme === 'light';
  document.body.classList.toggle('light', isLight);
  const icon  = document.getElementById('themeIcon');
  const label = document.getElementById('themeLabel');
  if (icon)  icon.className = isLight ? 'fas fa-sun' : 'fas fa-moon';
  if (label) label.textContent = isLight ? 'LIGHT' : 'DARK';
}

function toggleTheme() {
  const next = document.body.classList.contains('light') ? 'dark' : 'light';
  localStorage.setItem('cid-theme', next);
  applyTheme(next);
}

// Apply on page load
applyTheme(localStorage.getItem('cid-theme') || 'dark');

/* ── Clock ──────────────────────────────────────── */
function updateClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const n = new Date();
  el.textContent = [n.getHours(), n.getMinutes(), n.getSeconds()]
    .map(v => String(v).padStart(2, '0')).join(':');
}
updateClock();
setInterval(updateClock, 1000);

/* ── Loading Overlay ────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const overlay = document.getElementById('loadingOverlay');

  document.querySelectorAll('[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const inp = form.querySelector('input[type=text], textarea');
      if (inp && !inp.value.trim()) return;
      const txt = document.getElementById('loadingTxt');
      if (txt) txt.textContent = form.dataset.loading || 'SCANNING...';
      if (overlay) overlay.classList.add('active');
    });
  });

  const toggle  = document.getElementById('navToggle');
  const sidebar = document.getElementById('sidebar');
  const sOver   = document.getElementById('sidebarOverlay');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (sOver) sOver.style.display =
        sidebar.classList.contains('open') ? 'block' : 'none';
    });
  }

  document.querySelectorAll('.platform-card').forEach(card => {
    card.addEventListener('click', () => {
      if (card.classList.contains('found') && card.dataset.url)
        window.open(card.dataset.url, '_blank', 'noopener,noreferrer');
    });
  });

  const clearBtn = document.getElementById('clearReports');
  if (clearBtn) {
    clearBtn.addEventListener('click', e => {
      if (!confirm('Clear all reports? This cannot be undone.'))
        e.preventDefault();
    });
  }

  if (overlay) overlay.classList.remove('active');
});
