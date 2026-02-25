// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightSidebarTopics from 'starlight-sidebar-topics'
import starlightThemeObsidian from 'starlight-theme-obsidian'

// https://astro.build/config
export default defineConfig({
	site: "https://acnhmodding.github.io",
	integrations: [
		starlight({
			title: 'ACNH Modding Wiki',
			components: {
				Sidebar: './src/overrides/Sidebar.astro',
			},
			customCss: [
				'./src/styles/custom.css',
				'./src/fonts/acnh-font.css',
			],
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/acnhmodding/acnhmodding.github.io' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.gg/4cBd8dD6XS' },
				{ icon: 'reddit', label: 'Reddit', href: 'https://www.reddit.com/r/acnhmodding/' },
			],
			editLink: {
				baseUrl: "https://github.com/acnhmodding/acnhmodding.github.io/edit/master/"
			},
			expressiveCode: {
				themes: ['dracula', 'one-light'],
			},
			plugins: [
				starlightThemeObsidian({
					debug: false,
					sitemapConfig: {},
					graphConfig: {},
					backlinksConfig: {},
					graph: false,
					backlinks: true,
				}),
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
