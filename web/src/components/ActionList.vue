<script setup lang="ts">
import { useDomainsStore } from '../stores/domains'

const props = defineProps<{ domain: string }>()
const store = useDomainsStore()
</script>

<template>
  <div class="action-list">
    <section class="plan-panel">
      <p v-if="!store.hasPlanned" class="hint">Run Plan to see pending actions.</p>
      <p v-else-if="store.actionsFor(props.domain).length === 0" class="up-to-date">
        Up to date — nothing to do.
      </p>
      <ul v-else class="actions">
        <li v-for="action in store.actionsFor(props.domain)" :key="action.id" :class="{ manual: action.manual }">
          <strong>{{ action.op }}</strong> {{ action.resource }} — {{ action.detail }}
          <span v-if="action.manual" class="tag">manual</span>
        </li>
      </ul>
    </section>

    <section class="audit-panel">
      <p v-if="!store.hasAudited" class="hint">Run Audit to see check results.</p>
      <template v-else-if="store.reportFor(props.domain)">
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
      </template>
      <p v-else class="hint">No audit report for this domain.</p>
    </section>
  </div>
</template>
