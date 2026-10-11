/**
 * ProofChain Palette Theme & Session Controller
 * Exclusively toggles between Midnight Indigo (Deep Canvas) and Vanilla (Warm Canvas)
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'proofchain_theme_mode';
  const savedTheme = localStorage.getItem(STORAGE_KEY) || 'vanilla-light';

  document.documentElement.setAttribute('data-theme', savedTheme);

  window.addEventListener('DOMContentLoaded', () => {
    const navLinks = document.querySelector('.nav-links');
    if (!navLinks) return;

    // Check session
    const rawSession = localStorage.getItem('proofchain_session');
    let session = null;
    if (rawSession) {
      try { session = JSON.parse(rawSession); } catch(e){}
    }

    // 1. Session badge / action
    const sessionLi = document.createElement('li');
    if (session && session.operator) {
      const logoutBtn = document.createElement('button');
      logoutBtn.className = 'theme-switch-btn';
      logoutBtn.style.borderColor = 'var(--vanilla-border)';
      logoutBtn.textContent = 'Operator: ' + session.operator + ' (Exit)';
      logoutBtn.title = 'Click to terminate session and return to Login';
      logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('proofchain_session');
        window.location.href = 'login.html';
      });
      sessionLi.appendChild(logoutBtn);
    } else {
      const loginA = document.createElement('a');
      loginA.href = 'login.html';
      loginA.className = 'mono';
      loginA.style.fontSize = '0.78rem';
      loginA.textContent = 'Sign In';
      sessionLi.appendChild(loginA);
    }
    navLinks.appendChild(sessionLi);

    // 2. Theme switcher button
    if (!document.getElementById('themeToggleBtn')) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.id = 'themeToggleBtn';
      btn.className = 'theme-switch-btn';
      btn.textContent = savedTheme === 'indigo-dark' ? 'Theme: Midnight Indigo' : 'Theme: Vanilla';

      btn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'vanilla-light';
        const next = current === 'indigo-dark' ? 'vanilla-light' : 'indigo-dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem(STORAGE_KEY, next);
        btn.textContent = next === 'indigo-dark' ? 'Theme: Midnight Indigo' : 'Theme: Vanilla';
      });

      li.appendChild(btn);
      navLinks.appendChild(li);
    }
  });
})();
