// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator'
import starlightThemeObsidian from 'starlight-theme-obsidian'

// https://astro.build/config
export default defineConfig({
	site: "https://acnhmodding.github.io",
	integrations: [
		starlight({
			title: 'ACNH Modding Wiki',
			customCss: ['./src/styles/custom.css'],
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/acnhmodding/wiki' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.gg/4cBd8dD6XS' },
				{ icon: 'reddit', label: 'Reddit', href: 'https://www.reddit.com/r/acnhmodding/' },
			],
			editLink: {
				baseUrl: "https://github.com/acnhmodding/wiki/edit/main/"
			},
			expressiveCode: {
				themes: ['dracula', 'one-light'],
			},
			plugins: [
				starlightLinksValidator(),
				starlightThemeObsidian({
					debug: false,
					sitemapConfig: {},
					graphConfig: {},
					backlinksConfig: {},
					graph: false,
					backlinks: false
				}),
			],
			sidebar: [
				{
					label: 'Getting Started',
					autogenerate: { directory: "getting-started" },
				},
				{
					label: 'Tools',
					autogenerate: { directory: 'tools' },
				},
				{
					label: 'Guides',
					autogenerate: { directory: "guides" },
				},
				{
					label: 'Documentation',
					autogenerate: { directory: 'documentation' },
				},
			],
		}),
	],
});
