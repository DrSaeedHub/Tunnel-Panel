import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// The panel is served under a secret web path that is only known at install
// time, so assets must be requested relatively and resolved against the <base>
// tag the backend injects. An absolute base would hardcode a prefix here and
// break every installation that chose a different one.
export default defineConfig({
  base: './',
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    // Up one level: the built bundle lives at web/dist, where web/embed.go
    // embeds it. The npm project sits under web/_app because the Go tool
    // ignores directories whose names begin with an underscore, which keeps
    // node_modules -- and the stray Go files some npm packages ship -- out of
    // `go build ./...`.
    outDir: '../dist',
    emptyOutDir: true,
    // Never inline an asset as a base64 data URI. Vite would do that below 4kB
    // by default, which costs a third more bytes than the file it replaces --
    // and those bytes land in the entry chunk every session pays for, to spare
    // a request that only the one page needing the asset would have made. The
    // bundle ships inside the Go binary, so that trade is the wrong way round
    // here. It also kept one empty-state illustration inlined while its dark
    // twin stayed a file, purely because they landed either side of the limit.
    assetsInlineLimit: 0,
    // The bundle ships inside the Go binary, so size is deployment weight.
    // Charts and the QR encoder are split out because most sessions never
    // open a view that needs them.
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('recharts') || id.includes('d3-')) return 'charts'
          if (id.includes('qrcode')) return 'qrcode'
          if (id.includes('i18next')) return 'i18n'
          if (id.includes('react-router')) return 'router'
          if (id.includes('@radix-ui')) return 'radix'
          // React itself stays in the common vendor chunk: splitting it out
          // makes the graph circular, because vendor packages import it.
          return 'vendor'
        },
      },
    },
    chunkSizeWarningLimit: 700,
  },
  server: {
    proxy: {
      // Development convenience only: the real deployment serves both from the
      // same origin under the same prefix.
      '/api': { target: 'http://127.0.0.1:18791', changeOrigin: true },
    },
  },
})
