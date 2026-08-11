// The token arrives in the launch URL and is kept in memory only. It is not put
// in localStorage or sessionStorage: it dies with the server process, so
// persisting it would only leave a stale value behind.
const params = new URLSearchParams(window.location.search)
const token = params.get('token') ?? ''

// Strip the token from the visible URL so it does not sit in the address bar
// or leak via Referer on a later subresource request.
if (params.has('token')) {
  params.delete('token')
  const query = params.toString()
  const url = window.location.pathname + (query ? `?${query}` : '') + window.location.hash
  window.history.replaceState(window.history.state, '', url)
}

async function request<T>(path: string, method: 'GET' | 'POST'): Promise<T> {
  // The token travels in a header, never in ?token= — the server only honours
  // the query param on GET/HEAD requests that accept HTML (the launch
  // navigation). A POST relying on it is refused with 403.
  const response = await fetch(path, {
    method,
    headers: { 'X-Mailctl-Token': token },
  })
  const body = await response.json()
  if (!response.ok) {
    throw new Error(body?.error ?? `${method} ${path} failed with ${response.status}`)
  }
  return body as T
}

export interface Domain {
  name: string
  zone: string
  providers: string[]
}

export interface Action {
  id: string
  op: 'CREATE' | 'UPDATE' | 'DELETE' | 'MANUAL'
  resource: string
  domain: string
  provider?: string
  detail: string
  manual: boolean
}

export interface Check {
  name: string
  want: string
  got: string
  ok: boolean
}

export interface Report {
  domain: string
  ok: boolean
  checks: Check[]
  notes: string[]
  error?: string
}

export const api = {
  domains: () => request<{ domains: Domain[] }>('/api/domains', 'GET'),
  plan: () => request<{ schemaVersion: number; actions: Action[] }>('/api/plan', 'POST'),
  audit: () => request<{ reports: Report[] }>('/api/audit', 'POST'),
}
