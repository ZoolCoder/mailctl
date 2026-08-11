import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it } from 'vitest'

import ActionList from './ActionList.vue'
import { useDomainsStore } from '../stores/domains'

describe('ActionList', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('shows a hint before any plan has run', () => {
    const wrapper = mount(ActionList, { props: { domain: 'a.example' } })

    expect(wrapper.text()).toContain('Run Plan')
  })

  // Regression: with a multi-domain plan where one domain has actions and
  // another has none, the panel for the converged domain used to check the
  // GLOBAL actions array for its empty state and rendered nothing at all.
  it('shows "up to date" for a converged domain after a plan ran, not a blank panel', () => {
    const store = useDomainsStore()
    store.hasPlanned = true
    store.actions = [
      { id: '0', op: 'CREATE', resource: 'dns', domain: 'a.example', detail: 'MX', manual: false },
    ]

    const wrapper = mount(ActionList, { props: { domain: 'b.example' } })

    expect(wrapper.text()).toContain('Up to date')
    expect(wrapper.text()).not.toContain('Run Plan')
  })

  it('lists actions for the current domain once a plan has run', () => {
    const store = useDomainsStore()
    store.hasPlanned = true
    store.actions = [
      { id: '0', op: 'CREATE', resource: 'dns', domain: 'a.example', detail: 'MX', manual: false },
    ]

    const wrapper = mount(ActionList, { props: { domain: 'a.example' } })

    expect(wrapper.text()).toContain('CREATE')
    expect(wrapper.text()).not.toContain('Up to date')
  })
})
