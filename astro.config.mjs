// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightSidebarTopics from 'starlight-sidebar-topics';
import sitemap from '@astrojs/sitemap';

const NETLIFY_PREVIEW_SITE = process.env.CONTEXT !== 'production' && process.env.DEPLOY_PRIME_URL;

const site = NETLIFY_PREVIEW_SITE || 'https://acnhmodding.github.io/';
const ogUrl = new URL('banner.png?v=1', site).href;
const ogImageAlt = 'Your place for everything about Animal Crossing: New Horizons modding!';

// https://astro.build/config
export default defineConfig({
	site: "https://acnhmodding.github.io",
	integrations: [
		starlight({
			title: 'ACNH Modding Wiki',
			lastUpdated: true,
			components: {
				SocialIcons: './src/overrides/SocialIcons.astro',
			},
			customCss: [
				'./src/styles/custom.css',
				'./src/fonts/acnh-font.css',
			],
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/acnhmodding/acnhmodding.github.io' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.gg/4cBd8dD6XS' },
				{ icon: 'heart', label: 'Fluxer', href: 'https://fluxer.gg/Guyh2coW' },
				{ icon: 'reddit', label: 'Reddit', href: 'https://www.reddit.com/r/acnhmodding/' },
				{ icon: 'heart', label: 'GameBanana', href: 'https://gamebanana.com/games/7923' },
			],
			head: [
				{
					tag: 'meta',
					attrs: { property: 'og:image', content: ogUrl },
				},
				{
					tag: 'meta',
					attrs: { property: 'og:image:alt', content: ogImageAlt },
				},
				{
					tag: 'meta',
					attrs: { name: 'theme-color', content: '#67c464' },
				}
			],
			editLink: {
				baseUrl: "https://github.com/acnhmodding/acnhmodding.github.io/edit/master/"
			},
			expressiveCode: {
				themes: ['dracula', 'one-light'],
			},
			plugins: [
				starlightSidebarTopics([
					{
						label: 'Wiki',
						link: '/getting-started/overview',
						icon: 'open-book',
						items: [
							{
								label: 'Getting Started',
								items: [{ autogenerate: { directory: "getting-started" } }]
							},
							{
								label: 'Using Mods',
								items: [{ autogenerate: { directory: "using-mods" } }]
							},
							{
								label: 'Creating Mods',
								items: [{ autogenerate: { directory: "creating-mods" } }]
							},
							{
								label: 'Tools',
								items: [{ autogenerate: { directory: 'tools' } }]
							},
							{
								label: 'Guides',
								items: [{ autogenerate: { directory: "guides" } }]
							},
						]
					},
					{
						label: 'Documentation',
						link: '/documentation',
						icon: 'laptop',
						items: [{
							label: 'Documentation',
							items:[{
								label: 'Getting Started',
								link: '/documentation',
							}, {
								label: 'Particle Effects',
								link: '/documentation/effects',
							}, {
								label: 'Audio and SLink',
								link: '/documentation/audio',
							}, {
								label: 'EventFlow Functions',
								link: '/documentation/eventflow-functions',
							}, {
								label: 'UI Screens and IDs',
								link: '/documentation/ui',
							}]
						},
					 	{
								label: 'File Formats',
								items: [{ autogenerate: { directory: 'documentation/file-formats' } }],
						}]
					},

				])
			]
		}),
		sitemap(),
	],
});
