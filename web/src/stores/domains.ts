import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, type Action, type Domain, type Report } from '../api'

export const useDomainsStore = defineStore('domains', () => {
  const domains = ref<Domain[]>([])
  const actions = ref<Action[]>([])
  const reports = ref<Report[]>([])
  const error = ref('')
  const planning = ref(false)
  const auditing = ref(false)

  // Loads the domain list only. This must never trigger a plan or audit call:
  // those reach live provider APIs and cost latency and rate limit, so they
  // are gated behind explicit user action.
  async function loadDomains() {
    try {
      domains.value = (await api.domains()).domains
      error.value = ''
    } catch (e) {
      // Keep whatever already loaded: a failed refresh should not blank the view.
      error.value = (e as Error).message
    }
  }

  async function runPlan() {
    planning.value = true
    error.value = ''
    try {
      actions.value = (await api.plan()).actions
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      planning.value = false
    }
  }

  async function runAudit() {
    auditing.value = true
    error.value = ''
    try {
      reports.value = (await api.audit()).reports
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      auditing.value = false
    }
  }

  const actionsFor = (domain: string) => actions.value.filter((a) => a.domain === domain)

  // A manual action renders but is never executed, so it does not make a
  // domain unconverged — otherwise a domain with DKIM taken from config would
  // look permanently pending. A domain with no actions at all (no plan run
  // yet, or nothing to do) also counts as converged.
  const isConverged = (domain: string) => actionsFor(domain).every((a) => a.manual)

  const reportFor = (domain: string) => reports.value.find((r) => r.domain === domain)

  return {
    domains,
    actions,
    reports,
    error,
    planning,
    auditing,
    loadDomains,
    runPlan,
    runAudit,
    actionsFor,
    isConverged,
    reportFor,
  }
})
