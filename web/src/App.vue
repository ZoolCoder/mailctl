<script setup lang="ts">
import { onMounted } from 'vue'
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
