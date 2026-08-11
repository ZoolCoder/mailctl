import { createPinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'

import App from './App.vue'

function stubFetch() {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ domains: [{ name: 'example.com', zone: 'example.com', providers: ['purelymail'] }] }),
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('App', () => {
  it('loads the domain list on mount and renders it', async () => {
    stubFetch()

    const wrapper = mount(App, {
      global: { plugins: [createPinia()] },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('mailctl')
    expect(wrapper.text()).toContain('example.com')
  })

  it('never calls plan or audit on mount', async () => {
    const fetchMock = stubFetch()

    mount(App, {
      global: { plugins: [createPinia()] },
    })
    await flushPromises()

    // Only /api/domains may fire without user action.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toContain('/api/domains')
  })

  it('triggers a plan call only when the Plan button is clicked', async () => {
    const fetchMock = stubFetch()

    const wrapper = mount(App, {
      global: { plugins: [createPinia()] },
    })
    await flushPromises()

    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ schemaVersion: 1, actions: [] }),
    })

    await wrapper.find('button').trigger('click')
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[1][0]).toContain('/api/plan')
  })
})
