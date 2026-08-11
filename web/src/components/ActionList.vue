<script setup lang="ts">
import { useDomainsStore } from '../stores/domains'
import type { Action } from '../api'

const props = defineProps<{ domain: string }>()
const store = useDomainsStore()

// CREATE and DELETE must be distinguishable at a glance, not just by reading
// the word — this is read under time pressure.
function opClass(op: Action['op']) {
  return `op-${op.toLowerCase()}`
}
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
          <strong :class="opClass(action.op)">{{ action.op }}</strong> {{ action.resource }} — {{ action.detail }}
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

<style scoped>
.action-list {
  margin-top: 0.4rem;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.plan-panel,
.audit-panel {
  background: var(--zc-surface-2);
  border: 1px solid var(--zc-border);
  border-radius: var(--zc-radius);
  padding: 0.7rem 0.9rem;
}

.up-to-date {
  color: var(--zc-accent);
}

.actions,
.checks,
.notes {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.actions li + li,
.checks li + li {
  border-top: 1px solid var(--zc-border);
  padding-top: 0.4rem;
}

/* CREATE/UPDATE/DELETE must read apart at a glance, not just by the word. */
.op-create {
  color: var(--zc-accent);
}

.op-update {
  color: var(--zc-amber);
}

.op-delete {
  color: var(--zc-red);
}

.tag {
  display: inline-block;
  margin-left: 0.4rem;
  font-size: var(--zc-fs-label);
  font-weight: 600;
  color: var(--zc-bg);
  background: var(--zc-amber);
  border-radius: var(--zc-radius-sm);
  padding: 0.05rem 0.4rem;
}

.checks li.ok {
  color: var(--zc-text-muted);
}

/* A failing check must be obvious without reading it: colour plus weight
   plus a border, not colour alone. */
.checks li.fail {
  color: var(--zc-red);
  font-weight: 600;
  border-left: 3px solid var(--zc-red);
  padding-left: 0.5rem;
  margin-left: -0.5rem;
}

.notes li {
  color: var(--zc-text-muted);
  font-size: 0.9em;
}
</style>
