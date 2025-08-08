# Vibe Summer Concierge

Intelligent calendar management, focus music, and AI-powered task synthesis powered by Cloudflare Workers.

## Features

- 🗓️ **Calendar Management**: Intelligent scheduling and event management
- 🎵 **Focus Music**: AI-curated playlists for productivity
- 🤖 **AI Task Synthesis**: Smart task organization and prioritization
- 🔐 **OAuth Integration**: Support for Google, Spotify, ClickUp, and more
- 📊 **MCP Server**: Model Context Protocol for AI integrations

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono.js
- **Database**: Cloudflare D1 (SQLite)
- **Storage**: Cloudflare KV + R2
- **ORM**: Drizzle
- **Authentication**: Better Auth
- **AI**: OpenAI GPT integration

## Setup Instructions

### Prerequisites

- Node.js 18+ and npm
- Cloudflare account
- Wrangler CLI installed globally: `npm install -g wrangler`

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd vibe-summer-concierge
npm install
```

### 2. Cloudflare Setup

```bash
# Login to Cloudflare
wrangler login

# Create D1 database
wrangler d1 create vibe-summer-concierge-db

# Create KV namespace
wrangler kv:namespace create "KV" --env production

# Create R2 bucket
wrangler r2 bucket create vibe-summer-concierge-storage
```

### 3. Configuration

1. Copy the example configurations:
   ```bash
   cp wrangler.toml.example wrangler.toml
   cp drizzle.config.ts.example drizzle.config.ts
   ```

2. Update `wrangler.toml` with your Cloudflare resource IDs:
   - Replace `YOUR_ACCOUNT_ID` with your Cloudflare account ID
   - Replace `YOUR_DATABASE_ID` with the D1 database ID from step 2
   - Replace `YOUR_KV_NAMESPACE_ID` with the KV namespace ID from step 2
   - Replace `YOUR_BUCKET_NAME` with your R2 bucket name

3. Update `drizzle.config.ts` with your Cloudflare credentials:
   - Replace `YOUR_ACCOUNT_ID` with your Cloudflare account ID
   - Replace `YOUR_DATABASE_ID` with the D1 database ID
   - Replace `YOUR_CLOUDFLARE_API_TOKEN` with your Cloudflare API token

   **Alternative**: Set environment variables:
   ```bash
   export CLOUDFLARE_ACCOUNT_ID="your_account_id"
   export CLOUDFLARE_DATABASE_ID="your_database_id" 
   export CLOUDFLARE_D1_TOKEN="your_api_token"
   ```

### 4. Environment Variables

Set up your secrets using Wrangler:

```bash
# Authentication secrets
wrangler secret put BETTER_AUTH_URL --env production
wrangler secret put BETTER_AUTH_SECRET --env production

# OAuth provider credentials
wrangler secret put GOOGLE_CLIENT_ID --env production
wrangler secret put GOOGLE_CLIENT_SECRET --env production
wrangler secret put SPOTIFY_CLIENT_ID --env production
wrangler secret put SPOTIFY_CLIENT_SECRET --env production
wrangler secret put CLICKUP_CLIENT_ID --env production
wrangler secret put CLICKUP_CLIENT_SECRET --env production

# Fiberplane (optional, for debugging)
wrangler secret put FP_AUTH_ISSUER --env production
wrangler secret put FP_CLIENT_ID --env production
wrangler secret put FP_CLIENT_SECRET --env production

# OpenAI API
wrangler secret put OPENAI_API_KEY --env production
```

### 5. Database Migration

```bash
# Generate migration files
npm run db:generate

# Apply migrations
npm run db:migrate
```

### 6. Development

```bash
# Start development server
npm run dev

# Build for production
npm run build

# Deploy to Cloudflare
npm run deploy
```

## OAuth Provider Setup

### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project and enable Google+ API
3. Create OAuth 2.0 credentials
4. Add your callback URL: `https://your-worker.your-subdomain.workers.dev/api/auth/callback/google`

### Spotify OAuth
1. Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Create an app
3. Add your callback URL: `https://your-worker.your-subdomain.workers.dev/api/auth/callback/spotify`

### ClickUp OAuth
1. Go to [ClickUp API](https://clickup.com/api)
2. Create an app
3. Add your callback URL: `https://your-worker.your-subdomain.workers.dev/api/auth/callback/clickup`

## Project Structure

```
src/
├── index.ts          # Main application entry point
├── db/
│   └── schema.ts     # Database schema definitions
└── types.d.ts        # TypeScript type definitions

drizzle/              # Database migrations
wrangler.toml         # Cloudflare Workers configuration (gitignored)
wrangler.toml.example # Template configuration for setup
```

## API Endpoints

- `GET /openapi.json` - OpenAPI specification
- `GET /fp/*` - Fiberplane debugging interface
- `POST /api/auth/*` - Authentication endpoints
- `GET /mcp` - MCP server interface

## Security Notes

- All sensitive configuration is stored in Cloudflare Workers secrets
- `wrangler.toml` is gitignored to prevent exposure of resource IDs
- Use environment-specific configurations for different deployment stages

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details
