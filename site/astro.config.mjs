// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

const GITHUB = 'https://github.com/ivangsm/jay';

export default defineConfig({
	site: 'https://ivangsm.github.io',
	base: '/jay',
	// Astro's HTML compressor strips the whitespace between text and inline tags,
	// which glues prose to <code> and <a> ("MinIO'smc", "does.The full table").
	compressHTML: false,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Jay',
			description:
				'An embedded object store in Go. S3-compatible HTTP API and a binary protocol on one server, one metadata file and one static binary.',
			social: [{ icon: 'github', label: 'GitHub', href: GITHUB }],
			editLink: { baseUrl: `${GITHUB}/edit/main/site/` },
			lastUpdated: true,
			favicon: '/favicon.svg',
			customCss: [
				'@fontsource/ibm-plex-sans/latin-400.css',
				'@fontsource/ibm-plex-sans/latin-600.css',
				'@fontsource/ibm-plex-mono/latin-400.css',
				'@fontsource/ibm-plex-mono/latin-500.css',
				'./src/styles/theme.css',
			],
			plugins: [starlightLinksValidator({ errorOnRelativeLinks: false })],
			sidebar: [
				{
					label: 'Start here',
					items: [
						{ label: 'What Jay is', slug: 'what-jay-is' },
						{ label: 'Quickstart', slug: 'quickstart' },
						{ label: 'Install', slug: 'install' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'The S3 API', slug: 'guides/s3-api' },
						{ label: 'The native protocol', slug: 'guides/native-protocol' },
						{ label: 'Embedding Jay in Go', slug: 'guides/embedded' },
						{ label: 'Command-line client', slug: 'guides/cli' },
						{ label: 'Deploying Jay', slug: 'guides/deployment' },
						{ label: 'Backup and restore', slug: 'guides/backup-and-restore' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Configuration', slug: 'reference/configuration' },
						{ label: 'Seed token', slug: 'reference/seed-token' },
						{ label: 'Authentication', slug: 'reference/authentication' },
						{ label: 'S3 compatibility', slug: 'reference/s3-compatibility' },
						{ label: 'Native protocol', slug: 'reference/native-protocol' },
						{ label: 'Admin API', slug: 'reference/admin-api' },
						{ label: 'Observability', slug: 'reference/observability' },
					],
				},
				{
					label: 'Under the hood',
					items: [
						{ label: 'Performance', slug: 'internals/performance' },
						{ label: 'Architecture', slug: 'internals/architecture' },
						{ label: 'Limits', slug: 'internals/limits' },
					],
				},
			],
		}),
	],
});
