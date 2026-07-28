import sitemap from "@astrojs/sitemap";
import svelte from "@astrojs/svelte";
import { unified } from "@astrojs/markdown-remark";
import swup from "@swup/astro";
import icon from "astro-icon";
import { defineConfig } from "astro/config";
import x86asm from "highlight.js/lib/languages/x86asm";
import { common } from "lowlight";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeComponents from "rehype-components"; /* Render the custom directive content */
import rehypeHighlight from "rehype-highlight";
import rehypeKatex from "rehype-katex";
import rehypeSlug from "rehype-slug";
import remarkDirective from "remark-directive"; /* Handle directives */
import remarkGithubAdmonitionsToDirectives from "remark-github-admonitions-to-directives";
import remarkMath from "remark-math";
import remarkSectionize from "remark-sectionize";
import { AdmonitionComponent } from "./src/plugins/rehype-component-admonition.mjs";
import { GithubCardComponent } from "./src/plugins/rehype-component-github-card.mjs";
import { parseDirectiveNode } from "./src/plugins/remark-directive-rehype.js";
import { remarkExcerpt } from "./src/plugins/remark-excerpt.js";
import { remarkReadingTime } from "./src/plugins/remark-reading-time.mjs";

// https://astro.build/config
export default defineConfig({
	site: "https://n4sm.github.io/",
	trailingSlash: "always",
	integrations: [
		swup({
			theme: false,
			animationClass: "transition-swup-", // see https://swup.js.org/options/#animationselector
			// the default value `transition-` cause transition delay
			// when the Tailwind class `transition-all` is used
			containers: ["main", "#toc"],
			smoothScrolling: true,
			cache: true,
			preload: true,
			accessibility: true,
			updateHead: true,
			updateBodyClass: false,
			globalInstance: true,
		}),
		icon({
			include: {
				"preprocess: vitePreprocess(),": ["*"],
				"fa6-brands": ["*"],
				"fa6-regular": ["*"],
				"fa6-solid": ["*"],
			},
		}),
        svelte(),
		sitemap(),
	],
	markdown: {
		syntaxHighlight: false,
		processor: unified({
			remarkPlugins: [
				remarkMath,
				remarkReadingTime,
				remarkExcerpt,
				remarkGithubAdmonitionsToDirectives,
				remarkDirective,
				remarkSectionize,
				parseDirectiveNode,
			],
			rehypePlugins: [
				rehypeKatex,
				rehypeSlug,
				[
					rehypeHighlight,
					{
						languages: { ...common, x86asm },
						aliases: {
							bash: ["shellsession", "Shell"],
							x86asm: ["nasm"],
						},
						plainText: ["txt", "text", "nnn"],
					},
				],
				[
					rehypeComponents,
					{
						components: {
							github: GithubCardComponent,
							note: (x, y) => AdmonitionComponent(x, y, "note"),
							tip: (x, y) => AdmonitionComponent(x, y, "tip"),
							important: (x, y) => AdmonitionComponent(x, y, "important"),
							caution: (x, y) => AdmonitionComponent(x, y, "caution"),
							warning: (x, y) => AdmonitionComponent(x, y, "warning"),
						},
					},
				],
				[
					rehypeAutolinkHeadings,
					{
						behavior: "append",
						properties: {
							className: ["anchor"],
						},
						content: {
							type: "element",
							tagName: "span",
							properties: {
								className: ["anchor-icon"],
								"data-pagefind-ignore": true,
							},
							children: [
								{
									type: "text",
									value: "#",
								},
							],
						},
					},
				],
			],
		}),
	},
	vite: {
		build: {
			cssMinify: "esbuild",
			rollupOptions: {
				//external: ['fsevents'],
				onwarn(warning, warn) {
					// temporarily suppress this warning
					if (
						warning.message.includes("is dynamically imported by") &&
						warning.message.includes("but also statically imported by")
					) {
						return;
					}
					warn(warning);
				},
			},
		},
	},
});
