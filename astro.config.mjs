// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightSidebarTopics from 'starlight-sidebar-topics'

// https://astro.build/config
export default defineConfig({
	site: "https://acnhmodding.github.io",
	integrations: [
		starlight({
			title: 'ACNH Modding Wiki',
			components: {
				Pagination: './src/overrides/Pagination.astro',
			},
			customCss: ['./src/styles/custom.css', './src/styles/obsidian.css'],
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
