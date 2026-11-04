<script lang="ts">
  import { tick } from 'svelte';

  export type MenuItem = { label: string; action: () => void; danger?: boolean; disabled?: boolean };

  let { items, label = 'Действия', icon = '⋯' }: { items: MenuItem[]; label?: string; icon?: string } = $props();
  let open = $state(false);
  let root: HTMLDivElement | undefined = $state();
  let trigger: HTMLButtonElement | undefined = $state();
  let popup: HTMLDivElement | undefined = $state();
  // The popup is fixed to the viewport so scrollable lists and cards
  // around the trigger cannot clip it.
  let position = $state({ top: 0, right: 0 });

  const gap = 4;
  const margin = 8;

  async function toggle() {
    open = !open;
    if (!open) return;
    await tick();
    place();
  }

  function place() {
    if (!trigger || !popup) return;
    const rect = trigger.getBoundingClientRect();
    const height = popup.offsetHeight;
    const below = rect.bottom + gap;
    const fitsBelow = below + height <= window.innerHeight - margin;
    const top = fitsBelow ? below : Math.max(margin, rect.top - gap - height);
    position = { top, right: Math.max(margin, window.innerWidth - rect.right) };
  }

  function onWindowClick(event: MouseEvent) {
    if (open && root && !root.contains(event.target as Node)) open = false;
  }

  function close() {
    open = false;
  }
</script>

<svelte:window
  onclick={onWindowClick}
  onkeydown={(e) => e.key === 'Escape' && close()}
  onresize={close}
  onscrollcapture={(e) => open && popup && !popup.contains(e.target as Node) && close()}
/>

<div class="menu" bind:this={root}>
  <button class="ghost trigger" aria-label={label} aria-expanded={open} bind:this={trigger} onclick={toggle}>{icon}</button>
  {#if open}
    <div class="popup card" role="menu" bind:this={popup} style:top="{position.top}px" style:right="{position.right}px">
      {#each items as item (item.label)}
        <button
          role="menuitem"
          class="ghost"
          class:danger={item.danger}
          disabled={item.disabled}
          onclick={() => {
            open = false;
            item.action();
          }}>{item.label}</button
        >
      {/each}
    </div>
  {/if}
</div>

<style>
  .menu { position: relative; }
  .trigger { padding: 2px 10px; font-size: 18px; line-height: 1; }
  .popup {
    position: fixed;
    z-index: 100;
    padding: 4px;
    min-width: 180px;
    display: flex;
    flex-direction: column;
    box-shadow: 0 8px 24px rgb(0 0 0 / 0.35);
  }
  .popup button { text-align: left; padding: 7px 10px; }
</style>
