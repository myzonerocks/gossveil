<script setup lang="ts">
withDefaults(defineProps<{ size?: number }>(), { size: 26 })
</script>

<template>
  <!-- A shield whose face is a closing aperture: what the library does to a
       message. The blades take the text colour, so the mark belongs to
       whatever it sits on. -->
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 32 32"
    fill="none"
    class="shrink-0"
    aria-hidden="true"
  >
    <path
      d="M16 2.6 5.4 6.4v8.9c0 6.6 4.3 11.6 10.6 14.1 6.3-2.5 10.6-7.5 10.6-14.1V6.4Z"
      stroke="currentColor"
      stroke-width="2.1"
      stroke-linejoin="round"
      opacity="0.9"
    />
    <path
      d="M16 10.1 21.1 13v5.8L16 21.7 10.9 18.8V13Z"
      fill="var(--color-seal)"
    />
    <path d="M16 15.9 21.1 13M16 15.9v5.8M16 15.9 10.9 13" stroke="var(--color-ground)" stroke-width="1.5" />
  </svg>
</template>
