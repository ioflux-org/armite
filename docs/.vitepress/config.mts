import { defineConfig } from 'vitepress'

// Served as a GitHub "project" site, so every URL lives under /armite/.
// Moving to its own domain later (say armite.ioflux.org)? Change base to '/'
// and update `site`.
const base = '/armite/'
const site = 'https://ioflux-org.github.io/armite/'
const repo = 'https://github.com/ioflux-org/armite'

export default defineConfig({
  base,
  lang: 'en-US',
  title: 'Armite',
  description: 'A local Azure emulator with a real identity plane and real RBAC.',
  cleanUrls: true,
  lastUpdated: true,
  sitemap: { hostname: site },

  // `head` is not base-aware, so these paths spell out /armite/.
  head: [
    ['link', { rel: 'icon', href: `${base}favicon.ico`, sizes: '48x48' }],
    ['link', { rel: 'icon', href: `${base}favicon.svg`, type: 'image/svg+xml' }],
    ['link', { rel: 'apple-touch-icon', href: `${base}apple-touch-icon.png` }],
    ['meta', { name: 'theme-color', content: '#0B1026' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Armite' }],
    ['meta', { property: 'og:image', content: `${site}social-preview.png` }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
  ],

  themeConfig: {
    logo: { light: '/armite-logo.svg', dark: '/armite-logo-dark.svg', alt: 'Armite' },
    siteTitle: false,

    nav: [{ text: 'Docs', link: '/getting-started' }],

    sidebar: [
      {
        text: 'Start here',
        items: [
          { text: 'Getting started', link: '/getting-started' },
          { text: 'Client setup', link: '/clients' },
          { text: 'Hostnames', link: '/dns' },
          { text: 'Running in Docker', link: '/docker' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/config' },
          { text: 'Storage accounts and blobs', link: '/storage' },
          { text: 'Data persistence', link: '/persistence' },
          { text: 'Where Armite differs from Azure', link: '/divergences' },
        ],
      },
    ],

    socialLinks: [{ icon: 'github', link: repo }],
    search: { provider: 'local' },
    outline: [2, 3],
    editLink: { pattern: `${repo}/edit/main/docs/:path`, text: 'Edit this page on GitHub' },

    footer: {
      message:
        'Released under the Apache License 2.0. Azure, Entra and Key Vault are Microsoft trademarks; Armite is not affiliated with or endorsed by Microsoft.',
    },
  },
})
