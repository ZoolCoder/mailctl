<script setup lang="ts">
import { useDomainsStore } from '../stores/domains'

const props = defineProps<{ domain: string }>()
const store = useDomainsStore()
</script>

<template>
  <div class="action-list">
    <p v-if="store.actions.length === 0 && store.reports.length === 0" class="hint">
      Run Plan or Audit to see details for this domain.
    </p>

    <ul v-if="store.actionsFor(props.domain).length" class="actions">
      <li v-for="action in store.actionsFor(props.domain)" :key="action.id" :class="{ manual: action.manual }">
        <strong>{{ action.op }}</strong> {{ action.resource }} — {{ action.detail }}
        <span v-if="action.manual" class="tag">manual</span>
      </li>
    </ul>

    <div v-if="store.reportFor(props.domain)" class="report">
      <p v-if="store.reportFor(props.domain)?.error" class="error">
        {{ store.reportFor(props.domain)?.error }}
      </p>
      <ul v-else class="checks">
        <li
          v-for="check in store.reportFor(props.domain)?.checks"
          :key="check.name"
          :class="{ ok: check.ok, fail: !check.ok }"
        >
          {{ check.name }}: want {{ check.want }}, got {{ check.got }}
        </li>
      </ul>
      <ul v-if="store.reportFor(props.domain)?.notes.length" class="notes">
        <li v-for="(note, i) in store.reportFor(props.domain)?.notes" :key="i">{{ note }}</li>
      </ul>
    </div>
  </div>
</template>
