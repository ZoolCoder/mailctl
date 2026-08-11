import { setActivePinia, createPinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useDomainsStore } from './domains'

describe('domains store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('loads domains without requesting a plan', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        domains: [{ name: 'example.com', zone: 'example.com', providers: ['purelymail'] }],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const store = useDomainsStore()
    await store.loadDomains()

    expect(store.domains).toHaveLength(1)
    // Provider calls cost latency and rate limit, so nothing may plan on load.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toContain('/api/domains')
  })

  it('sends the token as a header, never as a query parameter', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ domains: [] }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const store = useDomainsStore()
    await store.loadDomains()

    const [url, options] = fetchMock.mock.calls[0]
    // The server only honours ?token= on GET/HEAD requests that accept HTML —
    // the launch navigation. Every API call must carry the header instead, or
    // a POST relying on the query form gets refused with 403.
    expect(String(url)).not.toContain('token=')
    expect((options?.headers as Record<string, string>)?.['X-Mailctl-Token']).toBeDefined()
  })

  it('does not report a domain as converged before any plan has run', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ domains: [{ name: 'a.example', zone: 'a.example', providers: [] }] }),
      }),
    )

    const store = useDomainsStore()
    await store.loadDomains()

    // No plan has run, so this must not be vacuously "converged" — that would
    // render a fresh, unchecked page as if everything were already verified.
    expect(store.isConverged('a.example')).toBe(false)
  })

  it('treats a domain with zero actions after a plan as converged', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          schemaVersion: 1,
          actions: [{ id: '0', op: 'CREATE', resource: 'dns', domain: 'other.example', detail: 'MX', manual: false }],
        }),
      }),
    )

    const store = useDomainsStore()
    await store.runPlan()

    // 'a.example' has no actions in this plan at all — it converged, it did
    // not simply go unchecked.
    expect(store.isConverged('a.example')).toBe(true)
  })

  it('groups plan actions by domain', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          schemaVersion: 1,
          actions: [
            { id: '0', op: 'CREATE', resource: 'dns', domain: 'a.example', detail: 'MX', manual: false },
            { id: '1', op: 'CREATE', resource: 'dns', domain: 'b.example', detail: 'MX', manual: false },
            { id: '2', op: 'MANUAL', resource: 'dkim', domain: 'a.example', detail: 'read the portal', manual: true },
          ],
        }),
      }),
    )

    const store = useDomainsStore()
    await store.runPlan()

    expect(store.actionsFor('a.example')).toHaveLength(2)
    expect(store.actionsFor('b.example')).toHaveLength(1)
  })

  it('treats a domain with only manual actions as converged', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          schemaVersion: 1,
          actions: [
            { id: '0', op: 'MANUAL', resource: 'dkim', domain: 'a.example', detail: 'read the portal', manual: true },
          ],
        }),
      }),
    )

    const store = useDomainsStore()
    await store.runPlan()

    // A manual action renders but is never executed, so a plan containing only
    // manual actions has converged as far as mailctl is concerned.
    expect(store.isConverged('a.example')).toBe(true)
  })

  it('treats a domain with a non-manual action as not converged', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          schemaVersion: 1,
          actions: [{ id: '0', op: 'CREATE', resource: 'dns', domain: 'a.example', detail: 'MX', manual: false }],
        }),
      }),
    )

    const store = useDomainsStore()
    await store.runPlan()

    expect(store.isConverged('a.example')).toBe(false)
  })

  it('surfaces an error without discarding what loaded', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          domains: [{ name: 'a.example', zone: 'a.example', providers: ['purelymail'] }],
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Cloudflare GET /zones: 403' }),
      })
    vi.stubGlobal('fetch', fetchMock)

    const store = useDomainsStore()
    await store.loadDomains()
    await store.runPlan()

    expect(store.error).toContain('403')
    // A failed refresh must not blank the view.
    expect(store.domains).toHaveLength(1)
  })

  it('surfaces an audit error without discarding loaded domains', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          domains: [{ name: 'a.example', zone: 'a.example', providers: ['purelymail'] }],
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Purelymail GET /domains: 500' }),
      })
    vi.stubGlobal('fetch', fetchMock)

    const store = useDomainsStore()
    await store.loadDomains()
    await store.runAudit()

    expect(store.error).toContain('500')
    expect(store.domains).toHaveLength(1)
  })
})
