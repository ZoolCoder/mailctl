import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it } from 'vitest'

import DomainList from './DomainList.vue'
import { useDomainsStore } from '../stores/domains'

describe('DomainList', () => {
  beforeEach(() => setActivePinia(createPinia()))

  // Regression: a row used to render as one run-on string, e.g.
  // "example.comexample.compurelymail", with no markup a stylesheet could
  // target to separate the fields.
  it('renders the name and providers as distinct, separated elements', () => {
    const store = useDomainsStore()
    store.domains = [{ name: 'example.com', zone: 'example.com', providers: ['purelymail'] }]

    const wrapper = mount(DomainList)

    expect(wrapper.find('.name').text()).toBe('example.com')
    expect(wrapper.find('.providers').text()).toContain('purelymail')
    // The zone repeats the name in the common case; showing it again
    // unqualified reads as a rendering bug, so it must not appear twice.
    expect(wrapper.find('.zone').exists()).toBe(false)
  })

  it('shows the zone only when it differs from the domain name', () => {
    const store = useDomainsStore()
    store.domains = [{ name: 'example.com', zone: 'other-zone.example', providers: ['purelymail'] }]

    const wrapper = mount(DomainList)

    expect(wrapper.find('.zone').text()).toContain('other-zone.example')
  })
})
