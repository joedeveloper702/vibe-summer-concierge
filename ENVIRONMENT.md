# Environment Variables

This document lists all the environment variables needed for the Vibe Summer Concierge application.

## Required Secrets (set via `wrangler secret put`)

### Authentication
- `BETTER_AUTH_URL` - The base URL of your deployed worker (e.g., `https://your-worker.your-subdomain.workers.dev`)
- `BETTER_AUTH_SECRET` - A random secret string for signing tokens (generate with `openssl rand -base64 32`)

### OAuth Providers

#### Google OAuth
- `GOOGLE_CLIENT_ID` - Your Google OAuth client ID
- `GOOGLE_CLIENT_SECRET` - Your Google OAuth client secret

#### Spotify OAuth
- `SPOTIFY_CLIENT_ID` - Your Spotify app client ID
- `SPOTIFY_CLIENT_SECRET` - Your Spotify app client secret

#### ClickUp OAuth
- `CLICKUP_CLIENT_ID` - Your ClickUp app client ID
- `CLICKUP_CLIENT_SECRET` - Your ClickUp app client secret

### AI Services
- `OPENAI_API_KEY` - Your OpenAI API key for GPT integration

### Fiberplane (Optional - for debugging)
- `FP_AUTH_ISSUER` - Fiberplane auth issuer URL
- `FP_CLIENT_ID` - Fiberplane client ID
- `FP_CLIENT_SECRET` - Fiberplane client secret

## Configuration Variables (set in wrangler.toml)

### Cloudflare Resources
- `account_id` - Your Cloudflare account ID
- `database_id` - D1 database ID
- `id` (KV namespace) - KV namespace ID
- `bucket_name` - R2 bucket name

## Drizzle Configuration (set in drizzle.config.ts or environment variables)

### Option 1: Environment Variables (Recommended)
Set these environment variables:
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID
- `CLOUDFLARE_DATABASE_ID` - Your D1 database ID
- `CLOUDFLARE_D1_TOKEN` - Your Cloudflare API token (get from Cloudflare dashboard)

### Option 2: Direct Configuration
Update `drizzle.config.ts` with your actual values (less secure).

## Setting Secrets

Use the Wrangler CLI to set secrets:

```bash
wrangler secret put VARIABLE_NAME --env production
```

Example:
```bash
wrangler secret put BETTER_AUTH_SECRET --env production
# You'll be prompted to enter the secret value
```

## Security Best Practices

1. **Never commit secrets to version control**
2. **Use strong, randomly generated secrets**
3. **Rotate secrets regularly**
4. **Use different secrets for different environments**
5. **Limit OAuth redirect URIs to your actual domains**
