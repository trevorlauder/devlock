// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	site: "https://trevorlauder.github.io",
	base: "/devlock",
	integrations: [
		starlight({
			title: 'devlock',
			description: 'A Linux sandbox for running untrusted coding agents.',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/trevorlauder/devlock',
				},
			],
			sidebar: [
				{ label: 'Overview', slug: '' },
				{
					label: 'Getting started',
					items: [
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Quickstart', slug: 'getting-started/quickstart' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'How devlock works', slug: 'guides/architecture' },
						{ label: 'Running an agent', slug: 'guides/running' },
						{ label: 'Shell mode', slug: 'guides/shell' },
						{ label: 'Inspect mode', slug: 'guides/inspect' },
						{ label: 'Writing a custom agent', slug: 'guides/custom-agents' },
						{ label: 'Writing a custom profile', slug: 'guides/custom-profiles' },
						{ label: 'User policy overrides', slug: 'guides/overrides' },
						{ label: 'Logs and post mortems', slug: 'guides/logs' },
						{ label: 'Troubleshooting', slug: 'guides/troubleshooting' },
						{
							label: 'Built-in agents',
							items: [
								{ label: 'claude', slug: 'guides/agents/claude' },
							],
						},
						{
							label: 'Built-in profiles',
							items: [
								{ label: 'base', slug: 'guides/profiles/base' },
								{ label: 'default', slug: 'guides/profiles/default' },
								{ label: 'security-probe', slug: 'guides/profiles/security-probe' },
							],
						},
						{
							label: 'Agent guides',
							items: [
								{ label: 'Claude Code', slug: 'guides/claude' },
							],
						},
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI flags', slug: 'reference/cli' },
						{ label: 'Agent YAML schema', slug: 'reference/agent-schema' },
						{ label: 'Profile YAML schema', slug: 'reference/profile-schema' },
						{ label: 'Path access buckets', slug: 'reference/path-buckets' },
						{ label: 'Variables', slug: 'reference/variables' },
						{ label: 'Environment variables', slug: 'reference/environment' },
						{ label: 'Security model', slug: 'reference/security-model' },
						{ label: 'Proxy', slug: 'reference/proxy' },
					],
				},
			],
		}),
	],
});
