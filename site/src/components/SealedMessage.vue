<script setup lang="ts">
import { usePreferredReducedMotion } from '@vueuse/core'
import { computed } from 'vue'

const motion = usePreferredReducedMotion()
const still = computed(() => motion.value === 'reduce')
</script>

<template>
  <!-- What a message looks like on the wire: a header a server can route and a
       body only the recipient can open. -->
  <figure class="sealed" :class="still ? 'sealed--still' : ''">
    <figcaption class="flex items-center gap-2 border-b border-edge px-4 py-2.5">
      <span class="size-1.5 rounded-full bg-seal" aria-hidden="true" />
      <span class="font-mono text-[14px] tracking-wider text-ink-faint">on the wire</span>
    </figcaption>

    <div class="space-y-3 p-4 font-mono text-[14px] leading-relaxed">
      <div>
        <p class="text-ink-faint">what the server sees</p>
        <div class="mt-1.5 rounded-lg border border-edge bg-surface p-3">
          <p class="text-ink-muted">kind <span class="text-seal-bright">whisper</span></p>
          <p class="text-ink-muted">to <span class="text-ink">a sealed envelope</span></p>
          <p class="sealed__cipher text-ink-faint">8f2a c401 77de 9b10 3e5c a8f6 2b74 e019</p>
        </div>
      </div>

      <p class="text-center text-ink-faint" aria-hidden="true">|</p>

      <div>
        <p class="text-ink-faint">what the recipient opens</p>
        <div class="mt-1.5 rounded-lg border border-seal/40 bg-seal/8 p-3">
          <p class="text-ink">"see you at six"</p>
          <p class="mt-1 text-ink-faint">sender verified, ratchet advanced</p>
        </div>
      </div>
    </div>
  </figure>
</template>

<style scoped>
.sealed {
  overflow: hidden;
  border: 1px solid var(--color-edge);
  border-radius: calc(var(--radius-card) + 2px);
  background: linear-gradient(180deg, var(--lit-from), var(--lit-to));
  box-shadow: var(--lit-shadow);
}

/* The ciphertext is different every time anyone looks at it. */
.sealed__cipher {
  animation: churn 5s steps(1) infinite;
}

@keyframes churn {
  0% {
    content: "";
  }
  25% {
    opacity: 0.55;
  }
  50% {
    opacity: 0.85;
  }
  75% {
    opacity: 0.4;
  }
  100% {
    opacity: 0.7;
  }
}

.sealed--still .sealed__cipher {
  animation: none;
}
</style>
