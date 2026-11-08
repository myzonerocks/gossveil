<script setup lang="ts">
import CodeTabs from '@/components/CodeTabs.vue'
import SealedMessage from '@/components/SealedMessage.vue'

const sdks = [
  {
    name: 'Swift',
    path: '/docs/sdk/swift',
    line: 'iOS and macOS, through a checksummed XCFramework in the package.',
  },
  {
    name: 'Kotlin',
    path: '/docs/sdk/kotlin',
    line: 'Android, through an AAR carrying the core for every ABI.',
  },
  {
    name: 'TypeScript',
    path: '/docs/sdk/typescript',
    line: 'Browser and Node, through the same core built to wasm.',
  },
  { name: 'C', path: '/docs/sdk/c', line: 'The ABI itself, for any language with a C FFI.' },
]

const guarantees = [
  {
    head: 'One core, three packages',
    line: 'The protocol lives in Zig and the SDKs wrap one C ABI, so a session started on a phone carries on in a browser without touching the wire.',
  },
  {
    head: 'Post-quantum from the start',
    line: "There's a post-quantum key in every published bundle and a sparse post-quantum ratchet inside every session.",
  },
  {
    head: 'Your storage stays yours',
    line: 'You implement the stores, in your language, against your database. We never open a connection or a file.',
  },
]

const pieces = [
  {
    title: 'Sessions',
    line: 'Key bundles, the handshake, and a ratchet that recovers skipped keys.',
    to: '/docs/concepts/sessions',
  },
  {
    title: 'Circles',
    line: 'Sender keys for groups, with out-of-order delivery.',
    to: '/docs/concepts/circles',
  },
  {
    title: 'Envelopes',
    line: 'Sealed sender, so the server routes what it cannot read.',
    to: '/docs/concepts/envelopes',
  },
  {
    title: 'Safety numbers',
    line: 'A fingerprint two people compare out loud or scan.',
    to: '/docs/concepts/safety',
  },
]
</script>

<template>
  <section class="relative overflow-hidden border-b border-edge">
    <div class="home-glow" aria-hidden="true" />
    <div class="relative mx-auto max-w-6xl px-6 pb-16 pt-16 lg:pt-20">
      <div class="mx-auto max-w-3xl text-center">
        <h1
          class="text-balance text-[2.1rem] font-bold leading-[1.07] tracking-tight sm:text-[2.9rem] lg:text-[3.4rem]"
        >
          End-to-end encryption for messaging apps
        </h1>
        <p
          class="mx-auto mt-5 max-w-2xl text-balance text-[1.0625rem] leading-relaxed text-ink-muted sm:text-[1.1875rem]"
        >
          Forward-secret sessions with a post-quantum handshake, group messaging, sealed envelopes
          and safety numbers. One core in Zig, thin packages for Swift, Kotlin and TypeScript, and
          your keys stay in your own storage.
        </p>

        <div class="mt-9 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
          <RouterLink to="/docs/start/quickstart" class="btn btn-primary">Get started</RouterLink>
          <RouterLink to="/docs/install/sdks" class="btn btn-quiet">Add an SDK</RouterLink>
        </div>
      </div>

      <div class="mt-14 grid items-start gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <CodeTabs />
        <SealedMessage />
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto grid max-w-7xl gap-px bg-edge px-0 sm:grid-cols-3">
      <div v-for="item in guarantees" :key="item.head" class="bg-ground px-6 py-8 lg:px-8 lg:py-10">
        <h2 class="text-[1.0625rem] font-semibold">{{ item.head }}</h2>
        <p class="mt-2 text-[0.9375rem] leading-relaxed text-ink-muted">{{ item.line }}</p>
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto max-w-7xl px-6 py-14 lg:py-20">
      <p class="font-mono text-[12px] uppercase tracking-[0.2em] text-ink-faint">The protocol</p>
      <div class="mt-8 grid gap-px bg-edge sm:grid-cols-2 lg:grid-cols-4">
        <RouterLink
          v-for="piece in pieces"
          :key="piece.title"
          :to="piece.to"
          class="group bg-ground p-6 transition-colors hover:bg-surface"
        >
          <span class="flex items-center justify-between text-[1.0625rem] font-semibold">
            {{ piece.title }}
            <span
              class="text-ink-faint transition-transform group-hover:translate-x-0.5 group-hover:text-seal"
              aria-hidden="true"
            >
              &rarr;
            </span>
          </span>
          <span class="mt-2 block text-[0.9375rem] leading-relaxed text-ink-muted">
            {{ piece.line }}
          </span>
        </RouterLink>
      </div>
    </div>
  </section>

  <section class="border-b border-edge">
    <div class="mx-auto max-w-7xl px-6 py-14 lg:py-20">
      <p class="font-mono text-[12px] uppercase tracking-[0.2em] text-ink-faint">SDKs</p>
      <h2 class="mt-3 max-w-2xl text-[1.75rem] font-bold leading-tight tracking-tight sm:text-3xl">
        Swift, Kotlin, TypeScript, C
      </h2>
      <div class="mt-8 grid gap-px bg-edge sm:grid-cols-2 lg:grid-cols-4">
        <RouterLink
          v-for="sdk in sdks"
          :key="sdk.name"
          :to="sdk.path"
          class="group bg-ground p-6 transition-colors hover:bg-surface"
        >
          <span class="flex items-center justify-between text-[1.0625rem] font-semibold">
            {{ sdk.name }}
            <span
              class="text-ink-faint transition-transform group-hover:translate-x-0.5 group-hover:text-seal"
              aria-hidden="true"
            >
              &rarr;
            </span>
          </span>
          <span class="mt-2 block text-[0.9375rem] leading-relaxed text-ink-muted">
            {{ sdk.line }}
          </span>
        </RouterLink>
      </div>
    </div>
  </section>

  <section>
    <div class="mx-auto max-w-7xl px-6 py-16 lg:py-20">
      <div class="lit flex flex-col gap-6 rounded-card p-8 lg:flex-row lg:items-center lg:p-10">
        <div class="max-w-xl">
          <h2 class="text-[1.5rem] font-bold tracking-tight">Where gossveil stops</h2>
          <p class="mt-3 text-[1.0625rem] leading-relaxed text-ink-muted">
            Registration, contact discovery, key backup enclaves, key transparency and credential
            issuance need a server with opinions, and those are yours. We do the cryptography and
            the wire format.
          </p>
        </div>
        <RouterLink to="/docs/about" class="btn btn-quiet shrink-0 lg:ml-auto">
          What it's for
        </RouterLink>
      </div>
    </div>
  </section>
</template>

<style scoped>
/* One light above the hero, strongest at the top edge and gone by the fold. */
.home-glow {
  position: absolute;
  inset: -40% 0 auto 0;
  height: 620px;
  background: radial-gradient(
    60% 50% at 50% 50%,
    color-mix(in oklab, var(--color-seal) calc(var(--glow) * 100%), transparent),
    transparent 70%
  );
  pointer-events: none;
}
</style>
