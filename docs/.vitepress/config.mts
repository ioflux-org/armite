import { defineConfig, type HeadConfig } from 'vitepress'

// Served on its own domain (docs/public/CNAME), so URLs live at the root.
// Back on the GitHub project URL (ioflux-org.github.io/armite) they would
// need base '/armite/' and the site URL to match.
const base = '/'
const site = 'https://armite.cloud/'
const repo = 'https://github.com/ioflux-org/armite'
const version = process.env.ARMITE_VERSION ?? 'dev'

// Microsoft Clarity (usage analytics) is injected only when the build
// has a project id - the Docs workflow passes the repository variable
// CLARITY_PROJECT_ID - so local builds and forks carry no tracking.
const clarity = process.env.CLARITY_PROJECT_ID
const analytics: HeadConfig[] = clarity
  ? [
    [
      'script',
      {},
      `(function(c,l,a,r,i,t,y){c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};` +
      `t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;` +
      `y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);})` +
      `(window,document,"clarity","script","${clarity}");`,
    ],
  ]
  : []

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
    ...analytics,
  ],

  themeConfig: {
    logo: { light: '/armite-logo.svg', dark: '/armite-logo-dark.svg', alt: 'Armite' },
    siteTitle: false,

    nav: [
      { text: 'Docs', link: '/getting-started' },
      { text: version, link: version.startsWith('v') ? `${repo}/releases/tag/${version}` : `${repo}/releases` },
    ],

    sidebar: [
      {
        text: 'Start here',
        items: [
          { text: 'Install', link: '/install' },
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
