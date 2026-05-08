// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightSidebarTopics from 'starlight-sidebar-topics';

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
			components: {
				Sidebar: './src/overrides/Sidebar.astro',
				PageFrame: 'starlight-theme-obsidian/overrides/PageFrame.astro',
				Pagination: 'starlight-theme-obsidian/overrides/Pagination.astro',
				ThemeSelect: 'starlight-theme-obsidian/overrides/ThemeSelect.astro',
				SocialIcons: './src/overrides/SocialIcons.astro',
			},
			customCss: [
				'starlight-theme-obsidian/styles/layers.css',
				'starlight-theme-obsidian/styles/theme.css',
				'starlight-theme-obsidian/styles/centered-reading.css',
				'starlight-theme-obsidian/styles/common.css',
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
								autogenerate: { directory: "getting-started" }
							},
							{
								label: 'Using Mods',
								autogenerate: { directory: "using-mods" }
							},
							{
								label: 'Creating Mods',
								autogenerate: { directory: "creating-mods" }
							},
							{
								label: 'Tools',
								autogenerate: { directory: 'tools' }
							},
							{
								label: 'Guides',
								autogenerate: { directory: "guides" }
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
							}]
						},
					 	{
								label: 'File Formats',
								autogenerate: { directory: 'documentation/file-formats' },
						}]
					},

				])
			]
		}),
	],
});
