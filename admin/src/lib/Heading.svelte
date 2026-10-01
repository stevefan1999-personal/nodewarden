<script lang="ts">
  let { title }: { title: string } = $props();
</script>

<svelte:head><title>{title} · CloudWarden</title></svelte:head>
<h1>{title}</h1>
