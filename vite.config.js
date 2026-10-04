import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Use localhost so the proxy follows the same loopback address family as
  // the local API process (macOS commonly binds it on IPv6 ::1).
  server: { proxy: { '/api': 'http://localhost:5174' } },
  preview: { proxy: { '/api': 'http://localhost:5174' } },
});
