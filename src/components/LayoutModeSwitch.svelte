<script lang="ts">
	import Icon from "@iconify/svelte";
	import { onMount } from "svelte";

	const STORAGE_KEY = "layout-mode";
	const MINIMAL_MODE = "minimal";

	let isMinimal = false;

	function applyLayout(minimal: boolean) {
		isMinimal = minimal;
		document.documentElement.classList.toggle("layout-minimal", minimal);
		localStorage.setItem(STORAGE_KEY, minimal ? MINIMAL_MODE : "default");
	}

	onMount(() => {
		isMinimal =
			document.documentElement.classList.contains("layout-minimal") ||
			localStorage.getItem(STORAGE_KEY) === MINIMAL_MODE;
		document.documentElement.classList.toggle("layout-minimal", isMinimal);
	});
</script>

<button
	type="button"
	class="relative btn-plain scale-animation rounded-lg h-11 w-11 active:scale-90"
	class:current-theme-btn={isMinimal}
	aria-label={isMinimal ? "Use standard layout" : "Use minimal wide layout"}
	aria-pressed={isMinimal}
	title={isMinimal ? "Standard layout" : "Minimal wide layout"}
	onclick={() => applyLayout(!isMinimal)}
>
	<div class="absolute transition" class:opacity-0={isMinimal}>
		<Icon
			icon="material-symbols:view-sidebar-outline-rounded"
			class="text-[1.25rem]"
		/>
	</div>
	<div class="absolute transition" class:opacity-0={!isMinimal}>
		<Icon
			icon="material-symbols:density-small-rounded"
			class="text-[1.25rem]"
		/>
	</div>
</button>
