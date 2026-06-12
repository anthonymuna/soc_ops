const TOKEN_KEY = 's4_token'

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function setToken(token) {
  sessionStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY)
}

export function isLoggedIn() {
  return Boolean(sessionStorage.getItem(TOKEN_KEY))
}

export async function login(username, password) {
  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!r.ok) {
    const err = await r.json().catch(() => ({}))
    throw new Error(err.detail || 'Login failed')
  }
  const data = await r.json()
  const token = data.access || data.token
  setToken(token)
  return token
}

export async function updateUserCards(cards) {
  const token = getToken()
  if (!token) return
  await fetch('/api/auth/me/', {
    method: 'PATCH',
    headers: { 
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}` 
    },
    body: JSON.stringify({ visible_cards: cards })
  })
}

export async function logout() {
  const token = getToken()
  if (token) {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => {})
  }
  clearToken()
}
