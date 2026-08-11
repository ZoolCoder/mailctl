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

  // The status must be checked before any attempt to parse the body: the
  // auth guard's failure response is plain text ("forbidden\n"), never JSON,
  // so calling response.json() first turns every 401/403 into a confusing
  // "Unexpected token" parse error instead of anything about authentication.
  if (!response.ok) {
    throw new Error(await describeFailure(response))
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error(`${method} ${path} returned a response that was not JSON`)
  }
}

// A 401/403 here is almost always the session token going stale — a plain
// browser reload strips it from the URL by design (see the top of this
// file), or `mailctl ui` is no longer running. That is a completely
// different situation from a provider error, and demands a completely
// different response (reopen the tab, versus fix a credential), so it gets
// its own message instead of falling into generic body parsing.
async function describeFailure(response: Response): Promise<string> {
  if (response.status === 401 || response.status === 403) {
    return (
      'Session token missing or no longer valid. Reopen the URL printed by ' +
      '`mailctl ui` (relaunch it if the command is no longer running).'
    )
  }

  const text = await response.text()
  if (!text) {
    return `Request failed with ${response.status}`
  }
  try {
    const body = JSON.parse(text)
    if (body && typeof body.error === 'string') {
      return body.error
    }
  } catch {
    // Not JSON — the raw text is the best description available.
  }
  return text
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
