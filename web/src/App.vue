<script setup lang="ts">
import { onMounted } from 'vue'
import './styles/tokens.css'
import { useDomainsStore } from './stores/domains'
import DomainList from './components/DomainList.vue'

const store = useDomainsStore()

// The domain list reaches no provider, so loading it on mount is safe.
// Plan and Audit call live provider APIs and must stay behind explicit
// buttons — never fire them automatically.
onMounted(() => {
  store.loadDomains()
})
</script>

<template>
  <main>
    <h1>mailctl</h1>

    <div class="toolbar">
      <button type="button" :disabled="store.planning" @click="store.runPlan()">
        {{ store.planning ? 'Planning…' : 'Plan' }}
      </button>
      <button type="button" :disabled="store.auditing" @click="store.runAudit()">
        {{ store.auditing ? 'Auditing…' : 'Audit' }}
      </button>
    </div>

    <p v-if="store.error" class="error" role="alert">{{ store.error }}</p>

    <DomainList />
  </main>
</template>

<style>
/* Global: html/body need to reach outside this component's root, and .hint
   is shared with DomainList/ActionList, so this block is intentionally
   unscoped rather than <style scoped>. */
* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  background: var(--zc-bg);
}

body {
  color: var(--zc-text);
  font-family: var(--zc-font-ui);
  font-size: var(--zc-fs-body);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

::selection {
  background: var(--zc-accent);
  color: var(--zc-accent-contrast);
}

:focus-visible {
  outline: 2px solid var(--zc-accent-strong);
  outline-offset: 2px;
  border-radius: var(--zc-radius-sm);
}

main {
  max-width: 40rem;
  margin: 0 auto;
  padding: 2rem 1.25rem 4rem;
}

h1 {
  font-family: var(--zc-font-display);
  color: var(--zc-text-strong);
  font-size: 1.75rem;
  margin: 0 0 1.5rem;
}

.toolbar {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}

button {
  font: inherit;
  color: var(--zc-text);
  background: var(--zc-surface);
  border: 1px solid var(--zc-border);
  border-radius: var(--zc-radius-sm);
  padding: 0.5rem 0.9rem;
  cursor: pointer;
  transition: border-color var(--zc-dur) var(--zc-ease), background-color var(--zc-dur) var(--zc-ease);
}

button:hover:not(:disabled) {
  border-color: var(--zc-border-strong);
  background: var(--zc-surface-2);
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.error {
  background: var(--zc-surface-2);
  border: 1px solid var(--zc-border);
  border-left: 3px solid var(--zc-red);
  color: var(--zc-red);
  border-radius: var(--zc-radius-sm);
  padding: 0.65rem 0.9rem;
  margin-bottom: 1.5rem;
}

.hint {
  color: var(--zc-text-muted);
}
</style>
