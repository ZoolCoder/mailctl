import { createPinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import App from '../App.vue'

describe('App', () => {
  it('mounts the placeholder shell', () => {
    const wrapper = mount(App, {
      global: { plugins: [createPinia()] },
    })

    expect(wrapper.text()).toContain('mailctl')
  })
})
