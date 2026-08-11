<script setup lang="ts">
import { ref } from 'vue'
import { useDomainsStore } from '../stores/domains'
import ActionList from './ActionList.vue'

const store = useDomainsStore()
const expanded = ref<string | null>(null)

function toggle(domain: string) {
  expanded.value = expanded.value === domain ? null : domain
}
</script>

<template>
  <p v-if="store.domains.length === 0" class="hint">No domains configured.</p>

  <ul v-else class="domain-list">
    <li v-for="domain in store.domains" :key="domain.name" class="domain-row">
      <button type="button" class="domain-toggle" @click="toggle(domain.name)">
        <span :class="['status-dot', store.isConverged(domain.name) ? 'converged' : 'pending']" aria-hidden="true" />
        <span class="name">{{ domain.name }}</span>
        <!-- Zone usually equals the domain name; showing it again unqualified
             reads as a rendering bug, so only surface it when it differs. -->
        <span v-if="domain.zone !== domain.name" class="zone">(zone: {{ domain.zone }})</span>
        <span class="providers">— {{ domain.providers.join(', ') || 'no providers' }}</span>
      </button>
      <ActionList v-if="expanded === domain.name" :domain="domain.name" />
    </li>
  </ul>
</template>

<style scoped>
.domain-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.domain-row {
  display: flex;
  flex-direction: column;
}

.domain-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  text-align: left;
  background: var(--zc-surface);
  border: 1px solid var(--zc-border);
  border-radius: var(--zc-radius);
  padding: 0.7rem 0.9rem;
}

/* The row used to render "example.com— purelymail": adjacent inline spans
   with no whitespace text node between them in the compiled template. The
   flex gap above already separates every span; this stops the providers
   span from crowding the one before it when the gap alone reads too tight. */
.domain-toggle > .providers {
  margin-left: 0.15rem;
}

.status-dot {
  flex: none;
  width: 0.6rem;
  height: 0.6rem;
  border-radius: 50%;
  background: var(--zc-text-faint);
}

.status-dot.converged {
  background: var(--zc-accent);
}

.status-dot.pending {
  background: var(--zc-amber);
}

.name {
  color: var(--zc-text-strong);
  font-weight: 600;
}

.zone {
  color: var(--zc-text-faint);
  font-size: 0.9em;
}

.providers {
  color: var(--zc-text-muted);
}
</style>
