<script setup lang="ts">
import { useStatusStore } from './stores/status'

// Placeholder shell. The real viewer (domains, mailboxes, plan diff) is
// built in a later task.
const status = useStatusStore()
</script>

<template>
  <main>
    <h1>mailctl</h1>
    <p v-if="status.ready">UI scaffold ready.</p>
  </main>
</template>
