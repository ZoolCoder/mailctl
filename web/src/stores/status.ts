import { defineStore } from 'pinia'

// Placeholder store wiring Pinia into the app shell. The actual viewer
// state (domains, mailboxes, plan diff, etc.) lands in a later task.
export const useStatusStore = defineStore('status', {
  state: () => ({
    ready: true,
  }),
})
