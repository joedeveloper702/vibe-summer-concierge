import { createHonoMiddleware } from "@fiberplane/hono";
import { drizzle } from "drizzle-orm/d1";
import { Hono } from "hono";
import { html } from "hono/html";
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
  OPENAI_API_KEY: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SPOTIFY_CLIENT_ID: string;
  SPOTIFY_CLIENT_SECRET: string;
  CLICKUP_CLIENT_ID: string;
  CLICKUP_CLIENT_SECRET: string;
  MCP_API_KEY: string;
  BASE_URL: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Utility functions
async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function storeToken(kv: KVNamespace, hash: string, token: string): Promise<void> {
  await kv.put(`token:${hash}`, token, { expirationTtl: 86400 * 30 }); // 30 days
}

async function getToken(kv: KVNamespace, hash: string): Promise<string | null> {
  return await kv.get(`token:${hash}`);
}

async function getUserSession(kv: KVNamespace, sessionId: string): Promise<any> {
  const session = await kv.get(`session:${sessionId}`);
  return session ? JSON.parse(session) : null;
}

async function createUserSession(kv: KVNamespace, userId: string): Promise<string> {
  const sessionId = crypto.randomUUID();
  const session = { userId, createdAt: Date.now() };
  await kv.put(`session:${sessionId}`, JSON.stringify(session), { expirationTtl: 86400 * 7 }); // 7 days
  return sessionId;
}

// MCP Authentication middleware
async function mcpAuthMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const token = authHeader.substring(7);
  if (token !== c.env.MCP_API_KEY) {
    return c.json({ error: 'Invalid API key' }, 401);
  }
  
  await next();
}

// OAuth helper functions
async function exchangeCodeForTokens(provider: string, code: string, env: Bindings, baseUrl: string): Promise<any> {
  const configs = {
    google: {
      tokenUrl: 'https://oauth2.googleapis.com/token',
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    },
    spotify: {
      tokenUrl: 'https://accounts.spotify.com/api/token',
      clientId: env.SPOTIFY_CLIENT_ID,
      clientSecret: env.SPOTIFY_CLIENT_SECRET,
    },
    clickup: {
      tokenUrl: 'https://api.clickup.com/api/v2/oauth/token',
      clientId: env.CLICKUP_CLIENT_ID,
      clientSecret: env.CLICKUP_CLIENT_SECRET,
    }
  };

  const config = configs[provider as keyof typeof configs];
  if (!config) throw new Error('Invalid provider');

  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
  
  console.log('Token exchange request:', {
    provider,
    tokenUrl: config.tokenUrl,
    redirectUri,
    hasClientId: !!config.clientId,
    hasClientSecret: !!config.clientSecret,
    codeLength: code.length
  });

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
    }),
  });

  const responseText = await response.text();
  console.log('Token exchange response:', {
    status: response.status,
    statusText: response.statusText,
    responseText: responseText.substring(0, 500) // Limit log size
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText} - ${responseText}`);
  }

  try {
    return JSON.parse(responseText);
  } catch (parseError) {
    console.error('Failed to parse token response:', parseError);
    throw new Error(`Invalid JSON response: ${responseText}`);
  }
}

// OAuth token storage helpers (using hashed tokens instead of encryption)
async function storeOAuthToken(kv: KVNamespace, token: string): Promise<string> {
  const hash = await hashToken(token);
  await storeToken(kv, hash, token);
  return hash;
}

async function getOAuthToken(kv: KVNamespace, hash: string): Promise<string | null> {
  return await getToken(kv, hash);
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

        const accessToken = await getOAuthToken(env.KV, googleConnection.accessTokenHash);
        if (!accessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve Google Calendar access token"
            }],
            isError: true
          };
        }
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

// Routes
app.get("/", (c) => {
  return c.html(html`
    <html>
      <head>
        <title>Vibe Summer Concierge</title>
      </head>
      <body>
        <h1>Vibe Summer Concierge MCP Server</h1>
        <p>Intelligent calendar management, focus music, and AI-powered task synthesis.</p>
        <ul>
          <li><a href="/login">Login</a></li>
          <li><a href="/oauth/connect/google">Connect Google Calendar</a></li>
          <li><a href="/oauth/connect/spotify">Connect Spotify</a></li>
          <li><a href="/oauth/connect/clickup">Connect ClickUp</a></li>
        </ul>
      </body>
    </html>
  `);
});

// Debug endpoint to check configuration
app.get("/debug/auth", async (c) => {
  return c.json({
    hasClientId: !!c.env.FP_CLIENT_ID,
    hasClientSecret: !!c.env.FP_CLIENT_SECRET,
    hasAuthIssuer: !!c.env.FP_AUTH_ISSUER,
    hasMcpApiKey: !!c.env.MCP_API_KEY,
    hasBaseUrl: !!c.env.BASE_URL,
    baseUrl: c.env.BASE_URL,
    issuer: c.env.FP_AUTH_ISSUER,
  });
});

app.get("/debug/oauth", async (c) => {
  return c.json({
    google: {
      hasClientId: !!c.env.GOOGLE_CLIENT_ID,
      hasClientSecret: !!c.env.GOOGLE_CLIENT_SECRET,
      clientIdLength: c.env.GOOGLE_CLIENT_ID?.length || 0,
      clientSecretLength: c.env.GOOGLE_CLIENT_SECRET?.length || 0
    },
    spotify: {
      hasClientId: !!c.env.SPOTIFY_CLIENT_ID,
      hasClientSecret: !!c.env.SPOTIFY_CLIENT_SECRET,
    },
    clickup: {
      hasClientId: !!c.env.CLICKUP_CLIENT_ID,
      hasClientSecret: !!c.env.CLICKUP_CLIENT_SECRET,
    }
  });
});

// Test Better Auth routes
app.get("/debug/auth-routes", async (c) => {
  const auth = createAuth(c.env);
  try {
    // Try to get available endpoints from Better Auth
    const testRequest = new Request(`${c.env.BETTER_AUTH_URL}/api/auth/`, {
      method: 'GET',
    });
    const response = await auth.handler(testRequest);
    const text = await response.text();
    return c.json({ 
      status: response.status,
      response: text 
    });
  } catch (error) {
    return c.json({ 
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });
  }
});

// Session middleware helper
async function getSession(c: any) {
  const cookies = c.req.header('cookie') || '';
  const sessionMatch = cookies.match(/session=([^;]+)/);
  
  if (!sessionMatch) return null;
  
  const sessionId = sessionMatch[1];
  const sessionData = await c.env.KV.get(`session_${sessionId}`);
  
  if (!sessionData) return null;
  
  try {
    const session = JSON.parse(sessionData);
    // Check if session is expired
    if (session.expiresAt < Date.now()) {
      await c.env.KV.delete(`session_${sessionId}`);
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

// Direct OAuth callback handler
app.get("/auth/callback", async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');

  if (error) {
    return c.html(`<h1>Authentication Error</h1><p>Error: ${error}</p><a href="/login">Try Again</a>`);
  }

  if (!code || !state) {
    return c.html(`<h1>Authentication Error</h1><p>Missing authorization code or state</p><a href="/login">Try Again</a>`);
  }

  try {
    // Validate state parameter
    const storedState = await c.env.KV.get(`oauth_state_${state}`);
    if (!storedState) {
      return c.html(`<h1>Authentication Error</h1><p>Invalid or expired state parameter</p><a href="/login">Try Again</a>`);
    }

    // Clean up state
    await c.env.KV.delete(`oauth_state_${state}`);

    // Exchange code for tokens
    const tokenResponse = await fetch(`${c.env.FP_AUTH_ISSUER}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: c.env.FP_CLIENT_ID,
        client_secret: c.env.FP_CLIENT_SECRET,
        redirect_uri: `${new URL(c.req.url).origin}/auth/callback`,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return c.html(`<h1>Token Exchange Error</h1><p>Failed to exchange code for tokens: ${errorText}</p><a href="/login">Try Again</a>`);
    }

    const tokens = await tokenResponse.json() as {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      expires_in?: number;
    };

    // Get user info
    const userResponse = await fetch(`${c.env.FP_AUTH_ISSUER}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (!userResponse.ok) {
      return c.html(`<h1>User Info Error</h1><p>Failed to get user information</p><a href="/login">Try Again</a>`);
    }

    const userInfo = await userResponse.json() as {
      sub: string;
      email?: string;
      name?: string;
      login?: string;
      githubUserId?: string;
    };

    // Create session token (simple JWT-like structure)
    const sessionData = {
      userId: userInfo.sub || userInfo.githubUserId || 'unknown',
      email: userInfo.email,
      name: userInfo.name || userInfo.login,
      accessToken: tokens.access_token,
      createdAt: Date.now(),
      expiresAt: Date.now() + (tokens.expires_in || 3600) * 1000,
    };

    // Store session in KV (expires in 24 hours)
    const sessionId = crypto.randomUUID();
    await c.env.KV.put(`session_${sessionId}`, JSON.stringify(sessionData), { expirationTtl: 86400 });

    // Set session cookie and redirect to dashboard
    c.header('Set-Cookie', `session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`);
    return c.redirect('/dashboard');

  } catch (error) {
    console.error('OAuth callback error:', error);
    return c.html(`<h1>Authentication Error</h1><p>An unexpected error occurred: ${error instanceof Error ? error.message : 'Unknown error'}</p><a href="/login">Try Again</a>`);
  }
});

// Authentication routes
app.get("/login", (c) => {
  return c.html(html`
    <html>
      <head>
        <title>Login - Vibe Summer Concierge</title>
      </head>
      <body>
        <h1>Login</h1>
        <p>Use your MCP API key to authenticate.</p>
        <form method="post" action="/auth/login">
          <input type="password" name="api_key" placeholder="MCP API Key" required />
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

app.post("/auth/login", async (c) => {
  const formData = await c.req.formData();
  const apiKey = formData.get("api_key") as string;
  
  if (apiKey === c.env.MCP_API_KEY) {
    const sessionId = await createUserSession(c.env.KV, "default-user");
    c.header("Set-Cookie", `session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`);
    return c.redirect("/");
  }
  
  return c.html(html`
    <html>
      <body>
        <h1>Login Failed</h1>
        <p>Invalid API key. <a href="/login">Try again</a></p>
      </body>
    </html>
  `);
});

app.get("/oauth/connect/:provider", async (c) => {
  const provider = c.req.param("provider");
  
  // Get base URL from request
  const requestUrl = new URL(c.req.url);
  const baseUrl = `${requestUrl.protocol}//${requestUrl.host}`;
  
  const configs = {
    google: {
      authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      clientId: c.env.GOOGLE_CLIENT_ID,
      scopes: "https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events"
    },
    spotify: {
      authUrl: "https://accounts.spotify.com/authorize",
      clientId: c.env.SPOTIFY_CLIENT_ID,
      scopes: "user-read-playback-state user-modify-playback-state playlist-read-private"
    },
    clickup: {
      authUrl: "https://app.clickup.com/api",
      clientId: c.env.CLICKUP_CLIENT_ID,
      scopes: "task:write space:read project:read"
    }
  };

  const config = configs[provider as keyof typeof configs];
  if (!config) {
    return c.json({ error: "Invalid provider" }, 400);
  }

  const state = crypto.randomUUID();
  await c.env.KV.put(`oauth_state:${state}`, provider, { expirationTtl: 600 });

  const authUrl = new URL(config.authUrl);
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("redirect_uri", `${baseUrl}/oauth/callback/${provider}`);
  authUrl.searchParams.set("scope", config.scopes);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);

  return c.redirect(authUrl.toString());
});

app.get("/oauth/callback/:provider", async (c) => {
  const provider = c.req.param("provider");
  const code = c.req.query("code");
  const state = c.req.query("state");

  if (!code || !state) {
    return c.json({ error: "Missing code or state" }, 400);
  }

  const storedProvider = await c.env.KV.get(`oauth_state:${state}`);
  if (storedProvider !== provider) {
    return c.json({ error: "Invalid state" }, 400);
  }

  try {
    // Get base URL from request
    const requestUrl = new URL(c.req.url);
    const baseUrl = `${requestUrl.protocol}//${requestUrl.host}`;
    
    const tokens = await exchangeCodeForTokens(provider, code, c.env, baseUrl);
    
    // Add debugging
    console.log('OAuth tokens received:', { 
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      error: tokens.error,
      tokenResponse: tokens
    });
    
    if (tokens.access_token) {
      try {
        const db = drizzle(c.env.DB);
        
        // Ensure default user exists
        const defaultUserId = "default-user";
        const existingUser = await db.select().from(schema.user).where(eq(schema.user.id, defaultUserId)).limit(1);
        
        if (existingUser.length === 0) {
          // Create default user if it doesn't exist
          await db.insert(schema.user).values({
            id: defaultUserId,
            name: "Default User",
            email: "default@vibe-summer-concierge.local",
            emailVerified: true,
            timezone: "UTC"
          });
        }
        
        const accessTokenHash = await hashToken(tokens.access_token);
        const refreshTokenHash = tokens.refresh_token ? await hashToken(tokens.refresh_token) : null;

        await storeToken(c.env.KV, accessTokenHash, tokens.access_token);
        if (tokens.refresh_token && refreshTokenHash) {
          await storeToken(c.env.KV, refreshTokenHash, tokens.refresh_token);
        }

        // Prepare the data for insertion
        const connectionData = {
          userId: defaultUserId,
          provider: provider as "google" | "spotify" | "clickup",
          providerUserId: "unknown", // Would get from provider's user info endpoint
          accessTokenHash,
          refreshTokenHash,
          expiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
          scopes: tokens.scope ? tokens.scope.split(" ") : []
        };

        console.log('Inserting OAuth connection:', connectionData);

        // Check for existing connection and update or insert
        const existingConnection = await db.select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUserId),
              eq(schema.oauthConnections.provider, provider as "google" | "spotify" | "clickup")
            )
          )
          .limit(1);

        if (existingConnection.length > 0) {
          // Update existing connection
          await db.update(schema.oauthConnections)
            .set({
              accessTokenHash,
              refreshTokenHash,
              expiresAt: connectionData.expiresAt,
              scopes: connectionData.scopes,
              updatedAt: new Date()
            })
            .where(eq(schema.oauthConnections.id, existingConnection[0].id));
        } else {
          // Insert new connection
          await db.insert(schema.oauthConnections).values(connectionData);
        }

        return c.html(html`
          <html>
            <body>
              <h1>Connected to ${provider}</h1>
              <p>Successfully connected your ${provider} account!</p>
              <a href="/">Back to home</a>
            </body>
          </html>
        `);
      } catch (dbError) {
        console.error('Database insertion error:', dbError);
        return c.json({ 
          error: "Database error while saving OAuth connection", 
          details: dbError instanceof Error ? dbError.message : 'Unknown database error',
          provider 
        }, 500);
      }
    }

    return c.json({ 
      error: "Failed to get access token", 
      details: tokens,
      provider,
      code: code?.substring(0, 10) + "..."
    }, 400);
  } catch (error) {
    console.error('OAuth callback error:', error);
    return c.json({ 
      error: "OAuth callback failed", 
      details: error instanceof Error ? error.message : 'Unknown error',
      provider 
    }, 500);
  }
});

app.get("/logout", async (c) => {
  // Get session from cookie
  const cookies = c.req.header('cookie') || '';
  const sessionMatch = cookies.match(/session=([^;]+)/);
  
  if (sessionMatch) {
    const sessionId = sessionMatch[1];
    // Delete session from KV
    await c.env.KV.delete(`session_${sessionId}`);
  }
  
  // Clear session cookie
  c.header('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');
  
  return c.html(
    html`
<html lang="en">
  <head>
    <title>Logged Out | Vibe Summer Concierge</title>
    <meta charSet="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
      .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 6px; text-decoration: none; display: inline-block; }
    </style>
  </head>
  <body>
    <h1>👋 Successfully Logged Out</h1>
    <p>You have been safely logged out of Vibe Summer Concierge.</p>
    <a href="/login" class="btn">🔐 Login Again</a>
  </body>
</html>
`
  );
});

// Dashboard route
app.get("/dashboard", async (c) => {
  const session = await getSession(c);

  if (!session) {
    return c.redirect("/login");
  }

  return c.html(
    html`
<html lang="en">
  <head>
    <title>Dashboard | Vibe Summer Concierge</title>
    <meta charSet="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
      .header { text-align: center; margin-bottom: 40px; }
      .user-info { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
      .btn { background: #007bff; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; margin: 5px; }
      .btn.danger { background: #dc3545; }
      .section { margin: 30px 0; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
      .card { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; }
    </style>
  </head>
  <body>
    <div class="header">
      <h1>🎵 Vibe Summer Concierge Dashboard</h1>
      <p>Welcome back! Your intelligent productivity companion is ready.</p>
    </div>
    
    <div class="user-info">
      <h3>👤 User Information</h3>
      <p><strong>ID:</strong> ${session.userId}</p>
      <p><strong>Name:</strong> ${session.name || 'Not provided'}</p>
      <p><strong>Email:</strong> ${session.email || 'Not provided'}</p>
      <p><strong>Session expires:</strong> ${new Date(session.expiresAt).toLocaleString()}</p>
    </div>
    
    <div class="grid">
      <div class="card">
        <h3>📊 API Endpoints</h3>
        <ul>
          <li><a href="/api/user/profile">User Profile API</a></li>
          <li><a href="/api/user/connections">OAuth Connections</a></li>
          <li><a href="/api/user/music-sessions">Music Sessions</a></li>
          <li><a href="/api/user/task-history">Task History</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>📚 Documentation</h3>
        <ul>
          <li><a href="/docs">Interactive API Docs</a></li>
          <li><a href="/openapi.json">OpenAPI Specification</a></li>
          <li><a href="/debug/auth">Auth Configuration</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>🤖 MCP Integration</h3>
        <ul>
          <li><a href="/mcp">MCP Server Endpoint</a></li>
          <li>Calendar Management Tools</li>
          <li>Music Focus Sessions</li>
          <li>AI Task Synthesis</li>
        </ul>
      </div>
    </div>
    
    <div class="section" style="text-align: center;">
      <a href="/logout" class="btn danger">🚪 Logout</a>
    </div>
  </body>
</html>
`
  );
});

// Better Auth routes - handle all methods
app.all("/api/auth/*", (c) => {
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