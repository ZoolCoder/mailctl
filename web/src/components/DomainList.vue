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
        <span :class="['status-dot', store.isConverged(domain.name) ? 'converged' : 'pending']" />
        <span class="name">{{ domain.name }}</span>
        <span class="zone">{{ domain.zone }}</span>
        <span class="providers">{{ domain.providers.join(', ') }}</span>
      </button>
      <ActionList v-if="expanded === domain.name" :domain="domain.name" />
    </li>
  </ul>
</template>
