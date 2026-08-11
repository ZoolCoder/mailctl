import { describe, expect, it, vi } from 'vitest'
import { api } from './api'

describe('api error handling', () => {
  it('reports a plain-text 403 as an actionable session message, not a JSON parse error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        // The auth guard uses http.Error, which writes plain text, never JSON.
        text: async () => 'forbidden\n',
        json: async () => {
          throw new SyntaxError('Unexpected token \'o\', "forbidden\n" is not valid JSON')
        },
      }),
    )

    await expect(api.domains()).rejects.toThrow(/session token/i)
  })

  it('still surfaces a structured provider error from a 500 body', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: async () =>
          JSON.stringify({ error: 'domain example.com: Purelymail GET /domains: invalidToken' }),
      }),
    )

    await expect(api.domains()).rejects.toThrow('domain example.com: Purelymail GET /domains: invalidToken')
  })

  it('gives a 403 and a 500 distinguishable messages', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 403, text: async () => 'forbidden\n' }),
    )
    let authMessage = ''
    try {
      await api.domains()
    } catch (e) {
      authMessage = (e as Error).message
    }

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: async () =>
          JSON.stringify({ error: 'domain example.com: Purelymail GET /domains: invalidToken' }),
      }),
    )
    let providerMessage = ''
    try {
      await api.domains()
    } catch (e) {
      providerMessage = (e as Error).message
    }

    // One is "reopen your browser tab", the other is "fix your credentials" —
    // conflating them into the same generic text would send an operator to
    // the wrong fix.
    expect(authMessage).not.toBe(providerMessage)
    expect(authMessage).toMatch(/session token/i)
    expect(providerMessage).toContain('invalidToken')
    expect(providerMessage).not.toMatch(/session token/i)
  })
})
