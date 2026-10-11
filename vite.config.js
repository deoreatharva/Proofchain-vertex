import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  root: '.',
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, 'index.html'),
        uiHome: resolve(import.meta.dirname, 'ui/index.html'),
        register: resolve(import.meta.dirname, 'ui/register.html'),
        batches: resolve(import.meta.dirname, 'ui/batches.html'),
        verify: resolve(import.meta.dirname, 'ui/verify.html'),
        audit: resolve(import.meta.dirname, 'ui/audit.html')
      }
    }
  },
  server: {
    port: 3000,
    open: '/ui/index.html'
  }
});
