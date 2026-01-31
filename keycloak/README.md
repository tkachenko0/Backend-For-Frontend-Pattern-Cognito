# Keycloak Test Setup

Local Keycloak instance for development and testing with pre-configured realm and client.

## Quick Start

```bash
docker compose up -d --build keycloak
```

Access Keycloak at http://localhost:3030

## Pre-configured Setup

The Keycloak instance automatically imports a realm with a configured OAuth client and test user.

### Admin Access

Access admin console at http://localhost:3030/admin

- Username: `admin`
- Password: `admin`

**Important:** After logging in, switch from the "master" realm to **`bff-realm`** using the dropdown in the top-left corner to see the pre-configured client and settings.

### Test User

Use this account to test the BFF authentication flow:

- Username: `user`
- Password: `user`
- Email: `test@example.com`

### Pre-configured Client

The realm includes a pre-configured OAuth client:

- Realm: `bff-realm`
- Client ID: `bff-client`
- Client Secret: `bff-client-secret`
- Redirect URIs:
  - `http://localhost:3000/auth/callback`
  - `http://localhost:3000/auth/signout-callback`
- Web Origins: `http://localhost:8080`
- PKCE: Enabled (S256)

### Environment Variables

These values are already configured in `.env.keycloak`:

```bash
KEYCLOAK_BASE_URL=http://localhost:3030
KEYCLOAK_INTERNAL_BASE_URL=http://keycloak:8080
KEYCLOAK_REALM=bff-realm
KEYCLOAK_CLIENT_ID=bff-client
KEYCLOAK_CLIENT_SECRET=bff-client-secret
KEYCLOAK_OAUTH_SCOPES=openid email profile
```

## Manual Configuration

If you need to modify the realm or client, edit `realm.json` and rebuild:

```bash
docker compose up -d --build keycloak
```
