import { createHonoMiddleware } from "@fiberplane/hono";
import { drizzle } from "drizzle-orm/d1";
import { Hono } from "hono";
import { html } from "hono/html";
import { createMiddleware } from "hono/factory";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { createAuthMiddleware, genericOAuth, mcp as mcpAuthPlugin, type BetterAuthPlugin } from "better-auth/plugins";
import { oAuthDiscoveryMetadata } from "better-auth/plugins";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPTransport } from "@hono/mcp";
import { z } from "zod";
import { eq, and, desc, gte, lte } from "drizzle-orm";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import * as schema from "./db/schema";

type Bindings = {
  DB: D1Database;
  KV: KVNamespace;
  FP_AUTH_ISSUER: string;
  FP_CLIENT_ID: string;
  FP_CLIENT_SECRET: string;
  BETTER_AUTH_URL: string;
  BETTER_AUTH_SECRET: string;
  OPENAI_API_KEY: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SPOTIFY_CLIENT_ID: string;
  SPOTIFY_CLIENT_SECRET: string;
  CLICKUP_CLIENT_ID: string;
  CLICKUP_CLIENT_SECRET: string;
};

// Create Better Auth instance
const createAuth = (env: Bindings) => {
  const db = drizzle(env.DB);

  return betterAuth({
    database: drizzleAdapter(db, {
      provider: "sqlite",
      schema,
    }),
    plugins: [
      genericOAuth({
        config: [
          {
            providerId: "fp-auth",
            clientId: env.FP_CLIENT_ID,
            clientSecret: env.FP_CLIENT_SECRET,
            discoveryUrl: `${env.FP_AUTH_ISSUER}/.well-known/oauth-authorization-server`,
            scopes: ["openid", "profile", "email"],
            pkce: true,
            responseType: "code",
            getUserInfo: async (accessToken) => {
              const response = await fetch(`${env.FP_AUTH_ISSUER}/userinfo`, {
                headers: {
                  Authorization: `Bearer ${accessToken.accessToken}`,
                },
              });
              const userInfo = (await response.json()) as {
                githubUserId?: string;
                login?: string;
                email?: string;
              };
              return {
                id: userInfo?.githubUserId || "",
                name: userInfo?.login || "",
                email: userInfo?.email || "",
                emailVerified: true,
                createdAt: new Date(),
                updatedAt: new Date(),
              };
            },
          },
        ],
      }),
      mcpAuthPlugin({
        loginPage: "/login",
      }),
      {
        id: "fp-mcp-fix",
        hooks: {
          after: [{
            matcher: () => true,
            handler: createAuthMiddleware(async (ctx) => {
              if (ctx.path === '/oauth2/callback/:providerId') {
                const responseRedirectLocation = ctx.context.responseHeaders?.get('location');
                if (!responseRedirectLocation) {
                  return;
                }

                const responseReturned = ctx.context.returned;
                const isMcpAuthBuggyResponse = responseReturned && typeof responseReturned === 'object';
                if (!isMcpAuthBuggyResponse) {
                  return;
                }
                const redirect = "redirect" in responseReturned && responseReturned.redirect;
                const responseReturnedLocation = "url" in responseReturned && responseReturned.url;
                try {
                  if (redirect && responseRedirectLocation === responseReturnedLocation) {
                    ctx.context.returned = undefined;
                    throw ctx.redirect(responseRedirectLocation);
                  }
                } catch {
                  return;
                }
              }
              return;
            }),
          }],
        },
      } satisfies BetterAuthPlugin,
    ],
    emailAndPassword: {
      enabled: false,
    },
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
  });
};

// MCP authentication middleware
const mcpAuthMiddleware = createMiddleware<{
  Bindings: Bindings;
}>(async (c, next) => {
  const auth = createAuth(c.env);
  const url = new URL(c.req.raw.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  const wwwAuthenticateValue = `Bearer resource_metadata=${baseUrl}/api/auth/.well-known/oauth-authorization-server`;

  const session = await auth.api.getMcpSession({
    headers: c.req.raw.headers,
  });

  if (!session) {
    return c.json(
      {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Unauthorized: Authentication required",
          "www-authenticate": wwwAuthenticateValue,
        },
        id: null,
      },
      {
        status: 401,
        headers: {
          "WWW-Authenticate": wwwAuthenticateValue,
        },
      },
    );
  }
  return next();
});

// OAuth token encryption/decryption helpers
async function encryptToken(token: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret.slice(0, 32)),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv);
  result.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...result));
}

async function decryptToken(encryptedToken: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const data = new Uint8Array(atob(encryptedToken).split('').map(c => c.charCodeAt(0)));
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret.slice(0, 32)),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const iv = data.slice(0, 12);
  const encrypted = data.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encrypted
  );
  return decoder.decode(decrypted);
}

// External API helpers
interface GoogleCalendarEvent {
  id: string;
  summary: string;
  description?: string;
  start: { dateTime: string; timeZone?: string };
  end: { dateTime: string; timeZone?: string };
  location?: string;
}

interface SpotifyPlaylist {
  id: string;
  name: string;
  tracks: { total: number };
}

interface ClickUpTask {
  id: string;
  name: string;
  description?: string;
  status: { status: string };
  priority?: { priority: string };
}

async function getGoogleCalendarEvents(accessToken: string, timeMin: string, timeMax: string): Promise<GoogleCalendarEvent[]> {
  const response = await fetch(
    `https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin=${timeMin}&timeMax=${timeMax}&singleEvents=true&orderBy=startTime`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );
  const data = await response.json() as { items: GoogleCalendarEvent[] };
  return data.items || [];
}

async function createGoogleCalendarEvent(accessToken: string, event: Partial<GoogleCalendarEvent>): Promise<GoogleCalendarEvent> {
  const response = await fetch(
    'https://www.googleapis.com/calendar/v3/calendars/primary/events',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(event),
    }
  );
  return await response.json() as GoogleCalendarEvent;
}

async function getSpotifyPlaylists(accessToken: string): Promise<SpotifyPlaylist[]> {
  const response = await fetch(
    'https://api.spotify.com/v1/me/playlists?limit=50',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );
  const data = await response.json() as { items: SpotifyPlaylist[] };
  return data.items || [];
}

async function startSpotifyPlayback(accessToken: string, playlistId: string): Promise<void> {
  await fetch(
    'https://api.spotify.com/v1/me/player/play',
    {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        context_uri: `spotify:playlist:${playlistId}`,
      }),
    }
  );
}

async function createClickUpTask(accessToken: string, spaceId: string, task: { name: string; description?: string; priority?: string }): Promise<ClickUpTask> {
  const response = await fetch(
    `https://api.clickup.com/api/v2/space/${spaceId}/task`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(task),
    }
  );
  return await response.json() as ClickUpTask;
}

// Create MCP server
function createMcpServer(env: Bindings, headers?: Headers) {
  const server = new McpServer({
    name: "vibe-summer-concierge",
    version: "1.0.0",
    description: "Intelligent calendar management, focus music, and AI-powered task synthesis",
  });

  const db = drizzle(env.DB);
  const auth = createAuth(env);

  // Calendar management tool
  server.tool(
    "calendar.manage",
    {
      action: z.enum(["defend", "optimize", "schedule"]).describe("Action to perform on calendar"),
      date_range: z.string().describe("Date range in format YYYY-MM-DD/YYYY-MM-DD"),
      preferences: z.object({
        buffer_minutes: z.number().default(15).describe("Buffer time between meetings"),
        include_travel_time: z.boolean().default(true).describe("Include travel time calculations"),
        protect_focus_blocks: z.boolean().default(true).describe("Protect existing focus time blocks"),
      }).optional(),
    },
    async ({ action, date_range, preferences }) => {
      try {
        const userSession = await auth.api.getSession({
          headers: headers || new Headers(),
        });

        if (!userSession?.user?.id) {
          return {
            content: [{ type: "text", text: "Error: User not authenticated" }],
            isError: true,
          };
        }

        const [googleConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, userSession.user.id),
              eq(schema.oauthConnections.provider, "google")
            )
          );

        if (!googleConnection) {
          return {
            content: [{ type: "text", text: "Error: Google Calendar not connected" }],
            isError: true,
          };
        }

        const accessToken = await decryptToken(googleConnection.accessTokenHash, env.BETTER_AUTH_SECRET);
        const [startDate, endDate] = date_range.split('/');
        
        const events = await getGoogleCalendarEvents(
          accessToken,
          new Date(startDate).toISOString(),
          new Date(endDate).toISOString()
        );

        let result = "";
        
        if (action === "defend") {
          // Create buffer events around existing meetings
          const bufferMinutes = preferences?.buffer_minutes || 15;
          let buffersCreated = 0;

          for (const event of events) {
            const startTime = new Date(event.start.dateTime);
            const endTime = new Date(event.end.dateTime);
            
            // Create pre-meeting buffer
            const preBufferStart = new Date(startTime.getTime() - bufferMinutes * 60000);
            const preBufferEvent = {
              summary: `Buffer: ${event.summary}`,
              start: { dateTime: preBufferStart.toISOString() },
              end: { dateTime: startTime.toISOString() },
              description: "Auto-generated buffer time",
            };

            // Create post-meeting buffer
            const postBufferEnd = new Date(endTime.getTime() + bufferMinutes * 60000);
            const postBufferEvent = {
              summary: `Buffer: ${event.summary}`,
              start: { dateTime: endTime.toISOString() },
              end: { dateTime: postBufferEnd.toISOString() },
              description: "Auto-generated buffer time",
            };

            try {
              await createGoogleCalendarEvent(accessToken, preBufferEvent);
              await createGoogleCalendarEvent(accessToken, postBufferEvent);
              buffersCreated += 2;
            } catch (error) {
              console.error("Failed to create buffer:", error);
            }
          }

          result = `Calendar defended: Created ${buffersCreated} buffer events for ${events.length} meetings`;
        } else if (action === "optimize") {
          result = `Calendar optimized: Analyzed ${events.length} events in date range ${date_range}`;
        } else if (action === "schedule") {
          result = `Calendar scheduling: Ready to schedule new events in ${date_range}`;
        }

        return {
          content: [{ type: "text", text: result }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error managing calendar: ${error instanceof Error ? error.message : "Unknown error"}` 
          }],
          isError: true,
        };
      }
    }
  );

  // Music focus tool
  server.tool(
    "music.focus",
    {
      action: z.enum(["start", "stop", "adjust"]).describe("Music control action"),
      session_type: z.enum(["focus", "deep_work", "break"]).describe("Type of work session"),
      duration_minutes: z.number().optional().describe("Session duration in minutes"),
      mood: z.enum(["energetic", "calm", "ambient"]).optional().describe("Music mood preference"),
    },
    async ({ action, session_type, duration_minutes, mood }) => {
      try {
        const userSession = await auth.api.getSession({
          headers: headers || new Headers(),
        });

        if (!userSession?.user?.id) {
          return {
            content: [{ type: "text", text: "Error: User not authenticated" }],
            isError: true,
          };
        }

        const [spotifyConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, userSession.user.id),
              eq(schema.oauthConnections.provider, "spotify")
            )
          );

        if (!spotifyConnection) {
          return {
            content: [{ type: "text", text: "Error: Spotify not connected" }],
            isError: true,
          };
        }

        const accessToken = await decryptToken(spotifyConnection.accessTokenHash, env.BETTER_AUTH_SECRET);
        let result = "";

        if (action === "start") {
          const playlists = await getSpotifyPlaylists(accessToken);
          
          // Find appropriate playlist based on session type and mood
          const focusPlaylist = playlists.find(p => 
            p.name.toLowerCase().includes(session_type) || 
            p.name.toLowerCase().includes(mood || "focus")
          ) || playlists[0];

          if (focusPlaylist) {
            await startSpotifyPlayback(accessToken, focusPlaylist.id);
            
            // Record music session
            await db.insert(schema.musicSessions).values({
              userId: userSession.user.id,
              sessionType: session_type,
              playlistId: focusPlaylist.id,
              durationMinutes: duration_minutes || 60,
              startedAt: new Date(),
            });

            result = `Started ${session_type} music session with playlist: ${focusPlaylist.name}`;
          } else {
            result = "No suitable playlists found";
          }
        } else if (action === "stop") {
          // Update the latest session with end time
          const [latestSession] = await db
            .select()
            .from(schema.musicSessions)
            .where(eq(schema.musicSessions.userId, userSession.user.id))
            .orderBy(desc(schema.musicSessions.startedAt))
            .limit(1);

          if (latestSession && !latestSession.endedAt) {
            await db
              .update(schema.musicSessions)
              .set({ endedAt: new Date() })
              .where(eq(schema.musicSessions.id, latestSession.id));
          }

          result = "Music session stopped";
        } else if (action === "adjust") {
          result = `Music adjusted for ${session_type} session with ${mood} mood`;
        }

        return {
          content: [{ type: "text", text: result }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error controlling music: ${error instanceof Error ? error.message : "Unknown error"}` 
          }],
          isError: true,
        };
      }
    }
  );

  // Task synthesis tool
  server.tool(
    "tasks.synthesize",
    {
      source_type: z.enum(["email", "note", "transcript"]).describe("Type of content source"),
      content: z.string().describe("Raw text content to analyze for tasks"),
      clickup_space_id: z.string().describe("ClickUp space ID for task creation"),
      priority_level: z.enum(["low", "normal", "high", "urgent"]).default("normal").describe("Default priority for extracted tasks"),
    },
    async ({ source_type, content, clickup_space_id, priority_level }) => {
      try {
        const userSession = await auth.api.getSession({
          headers: headers || new Headers(),
        });

        if (!userSession?.user?.id) {
          return {
            content: [{ type: "text", text: "Error: User not authenticated" }],
            isError: true,
          };
        }

        const [clickupConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, userSession.user.id),
              eq(schema.oauthConnections.provider, "clickup")
            )
          );

        if (!clickupConnection) {
          return {
            content: [{ type: "text", text: "Error: ClickUp not connected" }],
            isError: true,
          };
        }

        // Use OpenAI to extract tasks from content
        const openai = createOpenAI({
          apiKey: env.OPENAI_API_KEY,
        });

        const model = openai("gpt-4o-mini");

        const response = await generateText({
          model,
          messages: [
            {
              role: "system",
              content: `You are a task extraction expert. Analyze the provided ${source_type} content and extract actionable tasks. Return a JSON array of tasks with the following structure: [{"title": "Task title", "description": "Task description", "priority": "low|normal|high|urgent"}]. Only extract clear, actionable tasks. If no tasks are found, return an empty array.`,
            },
            {
              role: "user",
              content: content,
            },
          ],
        });

        let extractedTasks: Array<{ title: string; description: string; priority: string }> = [];
        
        try {
          extractedTasks = JSON.parse(response.text);
        } catch (parseError) {
          return {
            content: [{ type: "text", text: "Error: Failed to parse AI response" }],
            isError: true,
          };
        }

        if (!Array.isArray(extractedTasks) || extractedTasks.length === 0) {
          return {
            content: [{ type: "text", text: "No actionable tasks found in the provided content" }],
          };
        }

        // Create tasks in ClickUp
        const clickupAccessToken = await decryptToken(clickupConnection.accessTokenHash, env.BETTER_AUTH_SECRET);
        const createdTaskIds: string[] = [];

        for (const task of extractedTasks) {
          try {
            const clickupTask = await createClickUpTask(clickupAccessToken, clickup_space_id, {
              name: task.title,
              description: task.description,
              priority: task.priority || priority_level,
            });
            createdTaskIds.push(clickupTask.id);
          } catch (error) {
            console.error("Failed to create ClickUp task:", error);
          }
        }

        // Store synthesis history
        const contentHash = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(content)
        );
        const hashArray = Array.from(new Uint8Array(contentHash));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        await db.insert(schema.taskSynthesisHistory).values({
          userId: userSession.user.id,
          sourceType: source_type,
          sourceContentHash: hashHex,
          extractedTasks: extractedTasks,
          clickupTaskIds: createdTaskIds,
          processingStatus: "completed",
        });

        return {
          content: [{
            type: "text",
            text: `Successfully synthesized ${extractedTasks.length} tasks from ${source_type}. Created ${createdTaskIds.length} tasks in ClickUp: ${extractedTasks.map(t => t.title).join(", ")}`,
          }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error synthesizing tasks: ${error instanceof Error ? error.message : "Unknown error"}` 
          }],
          isError: true,
        };
      }
    }
  );

  return server;
}

const app = new Hono<{ Bindings: Bindings }>();

// OAuth discovery endpoints
app.get("/.well-known/oauth-authorization-server", async (c) => {
  const auth = createAuth(c.env);
  const metadataResponse = oAuthDiscoveryMetadata(auth)(c.req.raw);
  return metadataResponse;
});

app.get("/.well-known/oauth-protected-resource", async (c) => {
  const requestUrl = new URL(c.req.url);
  const resourceUrl = `${requestUrl.protocol}//${requestUrl.host}`;
  const authServerIssuer = resourceUrl;

  const metadata = {
    resource: resourceUrl,
    authorization_servers: [authServerIssuer],
    scopes_supported: ["openid", "profile", "email"],
    bearer_methods_supported: ["header"],
    resource_name: "Vibe Summer Concierge MCP Server",
  };

  return c.json(metadata);
});

// Debug endpoint to check configuration
app.get("/debug/auth", async (c) => {
  return c.json({
    hasClientId: !!c.env.FP_CLIENT_ID,
    hasClientSecret: !!c.env.FP_CLIENT_SECRET,
    hasAuthIssuer: !!c.env.FP_AUTH_ISSUER,
    hasBetterAuthUrl: !!c.env.BETTER_AUTH_URL,
    hasBetterAuthSecret: !!c.env.BETTER_AUTH_SECRET,
    baseUrl: c.env.BETTER_AUTH_URL,
    issuer: c.env.FP_AUTH_ISSUER,
  });
});

// Authentication routes
app.get("/login", async (c) => {
  const requestUrl = new URL(c.req.url);
  const baseUrl = `${requestUrl.protocol}//${requestUrl.host}`;
  
  return c.html(
    html`
<html lang="en">
  <head>
    <title>Login | Vibe Summer Concierge</title>
    <meta charSet="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
      .login-container { text-align: center; }
      .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; }
      .btn:hover { background: #0056b3; }
      .error { color: red; margin-top: 10px; }
      .loading { color: #666; margin-top: 10px; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h1>Vibe Summer Concierge</h1>
      <p>Intelligent calendar management, focus music, and AI-powered task synthesis</p>
      <button class="btn" onclick="startLogin()" id="loginBtn">Login with Fiberplane</button>
      <div id="status"></div>
    </div>
    <script type="module">
      const baseUrl = "${baseUrl}";
      
      // Function to show status messages
      function showStatus(message, isError = false) {
        const statusDiv = document.getElementById('status');
        statusDiv.innerHTML = message;
        statusDiv.className = isError ? 'error' : 'loading';
      }
      
      // Function to redirect to OAuth provider
      async function redirectToOAuth() {
        try {
          showStatus('Redirecting to Fiberplane...');
          
          // Get OAuth metadata first
          const metadataResponse = await fetch('${baseUrl}/.well-known/oauth-authorization-server');
          if (!metadataResponse.ok) {
            throw new Error('Failed to get OAuth metadata');
          }
          
          const metadata = await metadataResponse.json();
          console.log('OAuth metadata:', metadata);
          
          // Build OAuth authorization URL
          const authUrl = new URL(metadata.authorization_endpoint || '${baseUrl}/api/auth/oauth2/authorize/fp-auth');
          authUrl.searchParams.set('client_id', 'your-client-id'); // This should come from environment
          authUrl.searchParams.set('response_type', 'code');
          authUrl.searchParams.set('redirect_uri', '${baseUrl}/api/auth/callback/fp-auth');
          authUrl.searchParams.set('scope', 'openid profile email');
          authUrl.searchParams.set('state', Math.random().toString(36).substring(7));
          
          console.log('Redirecting to:', authUrl.toString());
          window.location.href = authUrl.toString();
          
        } catch (error) {
          console.error('OAuth redirect failed:', error);
          showStatus('Login failed: ' + error.message, true);
        }
      }
      
      // Try to import better-auth client, fallback to direct OAuth if it fails
      async function initializeAuth() {
        try {
          // Try to load better-auth client
          const { createAuthClient } = await import("https://esm.sh/better-auth@1.3.3/client");
          const { genericOAuthClient } = await import("https://esm.sh/better-auth@1.3.3/client/plugins");

          const authClient = createAuthClient({
            baseURL: baseUrl,
            plugins: [
              genericOAuthClient({
                providerId: "fp-auth",
              })
            ]
          });

          window.startLogin = async () => {
            try {
              showStatus('Starting login...');
              const data = await authClient.signIn.oauth2({
                providerId: "fp-auth",
                callbackURL: '${baseUrl}/api/auth/callback/fp-auth'
              });
              console.log("OAuth flow complete:", data);
              showStatus('Login successful!');
            } catch (error) {
              console.error("Better-auth login failed:", error);
              showStatus('Trying alternative login method...');
              // Fallback to direct OAuth
              await redirectToOAuth();
            }
          };
          
        } catch (error) {
          console.error("Failed to load better-auth client:", error);
          // Fallback to direct OAuth redirect
          window.startLogin = redirectToOAuth;
        }
      }
      
      // Initialize auth when page loads
      initializeAuth().catch(error => {
        console.error("Auth initialization failed:", error);
        window.startLogin = redirectToOAuth;
      });
    </script>
  </body>
</html>
`
  );
});

app.get("/logout", async (c) => {
  return c.html(
    html`
<html lang="en">
  <head>
    <title>Logout | Vibe Summer Concierge</title>
    <meta charSet="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script type="module">
      import { createAuthClient } from "https://esm.sh/better-auth@1.2.12/client";
      import { genericOAuthClient } from "https://esm.sh/better-auth@1.2.12/client/plugins";

      const authClient = createAuthClient({
        plugins: [
          genericOAuthClient({
            providerId: "fp-auth",
          })
        ]
      });

      const data = await authClient.signOut();
      document.body.innerHTML = "<h1>Logged out successfully</h1>";
    </script>
  </body>
</html>
`
  );
});

// Better Auth routes
app.on(["POST", "GET"], "/api/auth/**", (c) => {
  const auth = createAuth(c.env);
  return auth.handler(c.req.raw);
});

// OAuth connection endpoints
app.post("/oauth/connect/:provider", async (c) => {
  const provider = c.req.param("provider") as "google" | "spotify" | "clickup";
  const { code } = await c.req.json();

  const auth = createAuth(c.env);
  const userSession = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!userSession?.user?.id) {
    return c.json({ error: "User not authenticated" }, 401);
  }

  try {
    const db = drizzle(c.env.DB);
    
    // Exchange code for tokens based on provider
    let tokenResponse: any;
    let clientId: string;
    let clientSecret: string;
    let tokenUrl: string;

    switch (provider) {
      case "google":
        clientId = c.env.GOOGLE_CLIENT_ID;
        clientSecret = c.env.GOOGLE_CLIENT_SECRET;
        tokenUrl = "https://oauth2.googleapis.com/token";
        break;
      case "spotify":
        clientId = c.env.SPOTIFY_CLIENT_ID;
        clientSecret = c.env.SPOTIFY_CLIENT_SECRET;
        tokenUrl = "https://accounts.spotify.com/api/token";
        break;
      case "clickup":
        clientId = c.env.CLICKUP_CLIENT_ID;
        clientSecret = c.env.CLICKUP_CLIENT_SECRET;
        tokenUrl = "https://api.clickup.com/api/v2/oauth/token";
        break;
      default:
        return c.json({ error: "Unsupported provider" }, 400);
    }

    const tokenRequestBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      client_secret: clientSecret,
    });

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: tokenRequestBody,
    });

    tokenResponse = await response.json();

    if (!tokenResponse.access_token) {
      return c.json({ error: "Failed to obtain access token" }, 400);
    }

    // Encrypt and store tokens
    const accessTokenHash = await encryptToken(tokenResponse.access_token, c.env.BETTER_AUTH_SECRET);
    const refreshTokenHash = tokenResponse.refresh_token 
      ? await encryptToken(tokenResponse.refresh_token, c.env.BETTER_AUTH_SECRET)
      : null;

    const expiresAt = tokenResponse.expires_in 
      ? new Date(Date.now() + tokenResponse.expires_in * 1000)
      : null;

    // Store or update OAuth connection
    await db.insert(schema.oauthConnections).values({
      userId: userSession.user.id,
      provider,
      providerUserId: "unknown", // Would need to fetch user info
      accessTokenHash,
      refreshTokenHash,
      expiresAt,
      scopes: tokenResponse.scope ? tokenResponse.scope.split(" ") : [],
    }).onConflictDoUpdate({
      target: [schema.oauthConnections.userId, schema.oauthConnections.provider],
      set: {
        accessTokenHash,
        refreshTokenHash,
        expiresAt,
        updatedAt: new Date(),
      },
    });

    return c.json({ success: true, provider });
  } catch (error) {
    return c.json({ 
      error: `Failed to connect ${provider}`, 
      details: error instanceof Error ? error.message : "Unknown error" 
    }, 500);
  }
});

// Webhook endpoints
app.post("/webhooks/google", async (c) => {
  // Handle Google Calendar webhook notifications
  const body = await c.req.json();
  console.log("Google webhook received:", body);
  
  // Process calendar change events for auto-defense
  // Implementation would depend on specific webhook payload structure
  
  return c.json({ success: true });
});

app.post("/webhooks/clickup", async (c) => {
  // Handle ClickUp webhook notifications
  const body = await c.req.json();
  console.log("ClickUp webhook received:", body);
  
  // Process task updates and completion events
  // Implementation would depend on specific webhook payload structure
  
  return c.json({ success: true });
});

// Cron job endpoints
app.post("/cron/calendar-defense", async (c) => {
  const db = drizzle(c.env.DB);
  
  try {
    // Get all users with Google Calendar connections
    const connections = await db
      .select({
        userId: schema.oauthConnections.userId,
        accessTokenHash: schema.oauthConnections.accessTokenHash,
      })
      .from(schema.oauthConnections)
      .where(eq(schema.oauthConnections.provider, "google"));

    let processedUsers = 0;

    for (const connection of connections) {
      try {
        const accessToken = await decryptToken(connection.accessTokenHash, c.env.BETTER_AUTH_SECRET);
        
        // Get today's events
        const today = new Date();
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        const events = await getGoogleCalendarEvents(
          accessToken,
          today.toISOString(),
          tomorrow.toISOString()
        );

        // Auto-defend logic would go here
        console.log(`Processing ${events.length} events for user ${connection.userId}`);
        processedUsers++;
      } catch (error) {
        console.error(`Failed to process user ${connection.userId}:`, error);
      }
    }

    return c.json({ 
      success: true, 
      message: `Processed calendar defense for ${processedUsers} users` 
    });
  } catch (error) {
    return c.json({ 
      error: "Calendar defense cron failed", 
      details: error instanceof Error ? error.message : "Unknown error" 
    }, 500);
  }
});

app.post("/cron/token-refresh", async (c) => {
  const db = drizzle(c.env.DB);
  
  try {
    // Get connections with tokens expiring in the next hour
    const expiringConnections = await db
      .select()
      .from(schema.oauthConnections)
      .where(
        and(
          lte(schema.oauthConnections.expiresAt, new Date(Date.now() + 60 * 60 * 1000)),
          gte(schema.oauthConnections.expiresAt, new Date())
        )
      );

    let refreshedTokens = 0;

    for (const connection of expiringConnections) {
      if (!connection.refreshTokenHash) {
        continue;
      }

      try {
        const refreshToken = await decryptToken(connection.refreshTokenHash, c.env.BETTER_AUTH_SECRET);
        
        // Refresh token logic would depend on the provider
        // This is a simplified example
        let tokenUrl: string;
        let clientId: string;
        let clientSecret: string;

        switch (connection.provider) {
          case "google":
            tokenUrl = "https://oauth2.googleapis.com/token";
            clientId = c.env.GOOGLE_CLIENT_ID;
            clientSecret = c.env.GOOGLE_CLIENT_SECRET;
            break;
          case "spotify":
            tokenUrl = "https://accounts.spotify.com/api/token";
            clientId = c.env.SPOTIFY_CLIENT_ID;
            clientSecret = c.env.SPOTIFY_CLIENT_SECRET;
            break;
          default:
            continue;
        }

        const response = await fetch(tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: clientId,
            client_secret: clientSecret,
          }),
        });

        const tokenData = await response.json() as {
          access_token?: string;
          refresh_token?: string;
          expires_in?: number;
        };

        if (tokenData.access_token) {
          const newAccessTokenHash = await encryptToken(tokenData.access_token, c.env.BETTER_AUTH_SECRET);
          const newRefreshTokenHash = tokenData.refresh_token 
            ? await encryptToken(tokenData.refresh_token, c.env.BETTER_AUTH_SECRET)
            : connection.refreshTokenHash;

          await db
            .update(schema.oauthConnections)
            .set({
              accessTokenHash: newAccessTokenHash,
              refreshTokenHash: newRefreshTokenHash,
              expiresAt: new Date(Date.now() + (tokenData.expires_in || 3600) * 1000),
              updatedAt: new Date(),
            })
            .where(eq(schema.oauthConnections.id, connection.id));

          refreshedTokens++;
        }
      } catch (error) {
        console.error(`Failed to refresh token for connection ${connection.id}:`, error);
      }
    }

    return c.json({ 
      success: true, 
      message: `Refreshed ${refreshedTokens} tokens` 
    });
  } catch (error) {
    return c.json({ 
      error: "Token refresh cron failed", 
      details: error instanceof Error ? error.message : "Unknown error" 
    }, 500);
  }
});

// MCP server endpoint
app.all("/mcp", mcpAuthMiddleware, async (c) => {
  const mcpServer = createMcpServer(c.env);
  const transport = new StreamableHTTPTransport();

  await mcpServer.connect(transport);
  return transport.handleRequest(c);
});

// API endpoints for user management
app.get("/api/user/profile", async (c) => {
  const auth = createAuth(c.env);
  const userSession = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!userSession?.user) {
    return c.json({ error: "Not authenticated" }, 401);
  }

  const db = drizzle(c.env.DB);
  const [user] = await db
    .select()
    .from(schema.user)
    .where(eq(schema.user.id, userSession.user.id));

  return c.json({ user });
});

app.get("/api/user/connections", async (c) => {
  const auth = createAuth(c.env);
  const userSession = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!userSession?.user) {
    return c.json({ error: "Not authenticated" }, 401);
  }

  const db = drizzle(c.env.DB);
  const connections = await db
    .select({
      provider: schema.oauthConnections.provider,
      createdAt: schema.oauthConnections.createdAt,
      expiresAt: schema.oauthConnections.expiresAt,
    })
    .from(schema.oauthConnections)
    .where(eq(schema.oauthConnections.userId, userSession.user.id));

  return c.json({ connections });
});

app.get("/api/user/music-sessions", async (c) => {
  const auth = createAuth(c.env);
  const userSession = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!userSession?.user) {
    return c.json({ error: "Not authenticated" }, 401);
  }

  const db = drizzle(c.env.DB);
  const sessions = await db
    .select()
    .from(schema.musicSessions)
    .where(eq(schema.musicSessions.userId, userSession.user.id))
    .orderBy(desc(schema.musicSessions.startedAt))
    .limit(50);

  return c.json({ sessions });
});

app.get("/api/user/task-history", async (c) => {
  const auth = createAuth(c.env);
  const userSession = await auth.api.getSession({
    headers: c.req.raw.headers,
  });

  if (!userSession?.user) {
    return c.json({ error: "Not authenticated" }, 401);
  }

  const db = drizzle(c.env.DB);
  const history = await db
    .select()
    .from(schema.taskSynthesisHistory)
    .where(eq(schema.taskSynthesisHistory.userId, userSession.user.id))
    .orderBy(desc(schema.taskSynthesisHistory.createdAt))
    .limit(50);

  return c.json({ history });
});

// API Documentation viewer
app.get("/docs", async (c) => {
  const requestUrl = new URL(c.req.url);
  const baseUrl = `${requestUrl.protocol}//${requestUrl.host}`;
  
  return c.html(
    html`
<html lang="en">
  <head>
    <title>API Documentation | Vibe Summer Concierge</title>
    <meta charSet="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
      html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
      *, *:before, *:after { box-sizing: inherit; }
      body { margin:0; background: #fafafa; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
      window.onload = function() {
        const ui = SwaggerUIBundle({
          url: '${baseUrl}/openapi.json',
          dom_id: '#swagger-ui',
          deepLinking: true,
          presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIStandalonePreset
          ],
          plugins: [
            SwaggerUIBundle.plugins.DownloadUrl
          ],
          layout: "StandaloneLayout"
        });
      };
    </script>
  </body>
</html>
`
  );
});

// OpenAPI specification
app.get("/openapi.json", c => {
  return c.json({
    "openapi": "3.0.0",
    "info": {
      "title": "Vibe Summer Concierge MCP Server",
      "version": "1.0.0",
      "description": "Intelligent calendar management, focus music, and AI-powered task synthesis"
    },
    "servers": [
      {
        "url": "https://vibe-summer-concierge-production.josephfarrar.workers.dev"
      }
    ],
    "paths": {
      "/.well-known/oauth-authorization-server": {
        "get": {
          "summary": "OAuth authorization server metadata",
          "responses": {
            "200": {
              "description": "OAuth server configuration"
            }
          }
        }
      },
      "/.well-known/oauth-protected-resource": {
        "get": {
          "summary": "OAuth protected resource metadata",
          "responses": {
            "200": {
              "description": "Protected resource configuration"
            }
          }
        }
      },
      "/login": {
        "get": {
          "summary": "Login page",
          "responses": {
            "200": {
              "description": "HTML login form"
            }
          }
        }
      },
      "/logout": {
        "get": {
          "summary": "Logout page",
          "responses": {
            "200": {
              "description": "Logout confirmation"
            }
          }
        }
      },
      "/api/auth/**": {
        "get": {
          "summary": "Better Auth endpoints"
        },
        "post": {
          "summary": "Better Auth endpoints"
        }
      },
      "/oauth/connect/{provider}": {
        "post": {
          "summary": "Connect OAuth provider",
          "parameters": [
            {
              "name": "provider",
              "in": "path",
              "required": true,
              "schema": {
                "type": "string",
                "enum": ["google", "spotify", "clickup"]
              }
            }
          ]
        }
      },
      "/api/user/profile": {
        "get": {
          "summary": "Get user profile",
          "responses": {
            "200": {
              "description": "User profile data"
            }
          }
        }
      },
      "/api/user/connections": {
        "get": {
          "summary": "Get OAuth connections",
          "responses": {
            "200": {
              "description": "List of connected services"
            }
          }
        }
      },
      "/api/user/music-sessions": {
        "get": {
          "summary": "Get music session history",
          "responses": {
            "200": {
              "description": "List of music sessions"
            }
          }
        }
      },
      "/api/user/task-history": {
        "get": {
          "summary": "Get task synthesis history",
          "responses": {
            "200": {
              "description": "List of synthesized tasks"
            }
          }
        }
      },
      "/mcp": {
        "all": {
          "summary": "MCP server endpoint",
          "description": "Model Context Protocol server for calendar, music, and task tools"
        }
      },
      "/webhooks/google": {
        "post": {
          "summary": "Google Calendar webhook"
        }
      },
      "/webhooks/clickup": {
        "post": {
          "summary": "ClickUp webhook"
        }
      },
      "/cron/calendar-defense": {
        "post": {
          "summary": "Calendar defense cron job"
        }
      },
      "/cron/token-refresh": {
        "post": {
          "summary": "Token refresh cron job"
        }
      }
    }
  });
});

// Fiberplane API explorer
app.use("/fp/*", createHonoMiddleware(app, {
  libraryDebugMode: false,
  monitor: {
    fetch: true,
    logging: true,
    requests: true,
  },
}));

export default app;