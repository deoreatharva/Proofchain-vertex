/**
 * ProofChain Palette Theme Controller
 * Exclusively toggles between Midnight Indigo (Deep Canvas) and Vanilla (Warm Canvas)
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'proofchain_theme_mode';
  const savedTheme = localStorage.getItem(STORAGE_KEY) || 'indigo-dark';

  document.documentElement.setAttribute('data-theme', savedTheme);

  window.addEventListener('DOMContentLoaded', () => {
    const navLinks = document.querySelector('.nav-links');
    if (!navLinks) return;

    // Check if toggle button already exists
    if (document.getElementById('themeToggleBtn')) return;

    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.id = 'themeToggleBtn';
    btn.className = 'theme-switch-btn';
    btn.textContent = savedTheme === 'indigo-dark' ? 'Theme: Midnight Indigo' : 'Theme: Vanilla';

    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'indigo-dark';
      const next = current === 'indigo-dark' ? 'vanilla-light' : 'indigo-dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem(STORAGE_KEY, next);
      btn.textContent = next === 'indigo-dark' ? 'Theme: Midnight Indigo' : 'Theme: Vanilla';
    });

    li.appendChild(btn);
    navLinks.appendChild(li);
  });
})();
