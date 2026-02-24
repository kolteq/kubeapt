// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'KubeAPT',
  tagline: 'Kubernetes Admission Policy Toolkit',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://kubeapt.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'KolTEQ', // Usually your GitHub org/user name.
  projectName: 'KubeAPT', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'throw',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
	mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      // image: 'img/docusaurus-social-card.jpg',
      navbar: {
        hideOnScroll: false,
        // title: '',
        logo: {
          alt: 'KubeAPT Logo',
          src: 'img/kubeapt-logo.svg',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            href: 'https://github.com/kolteq/KubeAPT',
            label: 'GitHub',
            position: 'right',
          },
          {
            type: 'docsVersionDropdown',
            position: 'right',
          },
          {
            to: 'https://kolteq.com/policies',
            label: 'Policy Bundles',
            position: 'right',
            className: 'button button--secondary button--l'
          },
        ],
      },
      colorMode: {
        defaultMode: 'light',
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },
      footer: {
        style: 'light',
        logo: {
          alt: 'KolTEQ Logo',
          src: 'img/kolteq-logo.svg',
          href: 'https://www.kolteq.com',
          width: 160,
        },
        copyright: `<a href="https://kolteq.com/imprint">Imprint</a>
    <a href="https://kolteq.com/privacy">Privacy</a><br>Copyright © ${new Date().getFullYear()} KolTEQ GmbH`,
      },
      prism: {
        theme: require('prism-react-renderer/themes/oceanicNext'),
      },
    }),
  plugins: [
    '@easyops-cn/docusaurus-search-local',
  ]
};

module.exports = config;
