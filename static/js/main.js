/* ================================================
   CYBER INTELLIGENCE DASHBOARD — main.js
   Author: Mohammed Saleh
================================================ */

/* ── Clock ─────────────────────────────────────── */
function updateClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const now = new Date();
  const hh  = String(now.getHours()).padStart(2, '0');
  const mm  = String(now.getMinutes()).padStart(2, '0');
  const ss  = String(now.getSeconds()).padStart(2, '0');
  el.textContent = `${hh}:${mm}:${ss}`;
}
updateClock();
setInterval(updateClock, 1000);

/* ── Loading Overlay ────────────────────────────── */
function showLoading(msg) {
  const overlay = document.getElementById('loadingOverlay');
  const txt     = document.getElementById('loadingTxt');
  if (!overlay) return;
  if (txt && msg) txt.textContent = msg;
  overlay.classList.add('active');
}

function hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.classList.remove('active');
}

/* Attach to search forms */
document.addEventListener('DOMContentLoaded', () => {

  /* Search forms trigger loading */
  const forms = document.querySelectorAll('[data-loading]');
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      const msg = form.dataset.loading || 'SCANNING...';
      const input = form.querySelector('input[type=text]');
      if (input && !input.value.trim()) return; // let HTML validation handle it
      showLoading(msg);
    });
  });

  /* Sidebar toggle (mobile) */
  const toggle  = document.getElementById('navToggle');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');

  if (toggle && sidebar) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('active');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
    });
  }

  /* Fade-in on results */
  const results = document.querySelectorAll('.fade-in');
  results.forEach((el, i) => {
    el.style.animationDelay = `${i * 0.04}s`;
    el.style.opacity = '0';
  });

  /* Platform card: open link on click */
  document.querySelectorAll('.platform-card').forEach(card => {
    card.addEventListener('click', () => {
      const url = card.dataset.url;
      if (url && card.classList.contains('found')) {
        window.open(url, '_blank', 'noopener,noreferrer');
      }
    });
  });

  /* Confirm before clearing reports */
  const clearBtn = document.getElementById('clearReports');
  if (clearBtn) {
    clearBtn.addEventListener('click', (e) => {
      if (!confirm('Clear all reports? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  /* Auto-hide loading if page loaded with results (back button etc.) */
  hideLoading();
});
