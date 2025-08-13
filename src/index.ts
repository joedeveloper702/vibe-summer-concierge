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
  
  const result = await response.json() as any;
  
  if (!response.ok) {
    throw new Error(`Google Calendar API error: ${result.error?.message || 'Unknown error'}`);
  }
  
  return result as GoogleCalendarEvent;
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

async function createClickUpTask(accessToken: string, listId: string, task: { name: string; description?: string; priority?: string }): Promise<ClickUpTask> {
  // ClickUp priority mapping: urgent=1, high=2, normal=3, low=4
  const priorityMap: { [key: string]: number } = {
    'urgent': 1,
    'high': 2,
    'normal': 3,
    'low': 4
  };

  const taskData: any = {
    name: task.name,
  };

  if (task.description) {
    taskData.description = task.description;
  }

  if (task.priority && priorityMap[task.priority]) {
    taskData.priority = priorityMap[task.priority];
  }

  // ClickUp API requires tasks to be created in a list, not a space
  const response = await fetch(
    `https://api.clickup.com/api/v2/list/${listId}/task`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(taskData),
    }
  );
  
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`ClickUp API error (${response.status}):`, errorText);
    throw new Error(`ClickUp API error: ${response.status} - ${errorText}`);
  }
  
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

  // Calendar management tool
  server.tool(
    "calendar_manage",
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
        // For MCP API key authentication, we'll use the first available user's connections
        // In a production system, you might want to pass user ID as a parameter
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [googleConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
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

  // Calendar event creation tool
  server.tool(
    "calendar_create_event",
    {
      title: z.string().describe("Event title/summary"),
      start_time: z.string().describe("Start time in ISO format (e.g., 2025-08-09T10:00:00-07:00 for Pacific Time, or 2025-08-09T10:00:00Z for UTC)"),
      end_time: z.string().describe("End time in ISO format (e.g., 2025-08-09T11:00:00-07:00 for Pacific Time, or 2025-08-09T11:00:00Z for UTC)"),
      description: z.string().optional().describe("Event description"),
      location: z.string().optional().describe("Event location"),
      attendees: z.array(z.string()).optional().describe("Array of attendee email addresses"),
      timezone: z.string().optional().describe("IANA timezone (e.g., 'America/Los_Angeles', 'America/New_York'). If not provided, will use the time as specified."),
    },
    async ({ title, start_time, end_time, description, location, attendees, timezone }) => {
      try {
        // For MCP API key authentication, we'll use the first available user's connections
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [googleConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
              eq(schema.oauthConnections.provider, "google")
            )
          );

        if (!googleConnection) {
          return {
            content: [{ type: "text", text: "Error: Google Calendar not connected" }],
            isError: true,
          };
        }

        const accessToken = await getToken(env.KV, googleConnection.accessTokenHash);
        if (!accessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve Google Calendar access token"
            }],
            isError: true
          };
        }

        // Create the event object with timezone support
        const eventData: any = {
          summary: title,
          start: timezone ? 
            { dateTime: start_time, timeZone: timezone } : 
            { dateTime: start_time },
          end: timezone ? 
            { dateTime: end_time, timeZone: timezone } : 
            { dateTime: end_time },
        };

        if (description) {
          eventData.description = description;
        }

        if (location) {
          eventData.location = location;
        }

        if (attendees && attendees.length > 0) {
          eventData.attendees = attendees.map(email => ({ email }));
        }

        const createdEvent = await createGoogleCalendarEvent(accessToken, eventData);

        // Format the display time based on the input
        const startDate = new Date(start_time);
        const displayTime = timezone ? 
          `${startDate.toLocaleString()} (${timezone})` : 
          startDate.toLocaleString();

        return {
          content: [{
            type: "text",
            text: `Successfully created calendar event: "${title}" at ${displayTime}. Event ID: ${createdEvent.id}`
          }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error creating calendar event: ${error instanceof Error ? error.message : "Unknown error"}` 
          }],
          isError: true,
        };
      }
    }
  );

  // Music focus tool
  server.tool(
    "music_focus",
    {
      action: z.enum(["start", "stop", "adjust"]).describe("Music control action"),
      session_type: z.enum(["focus", "deep_work", "break"]).describe("Type of work session"),
      duration_minutes: z.number().optional().describe("Session duration in minutes"),
      mood: z.enum(["energetic", "calm", "ambient"]).optional().describe("Music mood preference"),
    },
    async ({ action, session_type, duration_minutes, mood }) => {
      try {
        // For MCP API key authentication, we'll use the first available user's connections
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [spotifyConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
              eq(schema.oauthConnections.provider, "spotify")
            )
          );

        if (!spotifyConnection) {
          return {
            content: [{ type: "text", text: "Error: Spotify not connected" }],
            isError: true,
          };
        }

        const accessToken = await getToken(env.KV, spotifyConnection.accessTokenHash);
        if (!accessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve Spotify access token"
            }],
            isError: true
          };
        }
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
              userId: defaultUser.id,
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
            .where(eq(schema.musicSessions.userId, defaultUser.id))
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
    "tasks_synthesize",
    {
      source_type: z.enum(["email", "note", "transcript"]).describe("Type of content source"),
      content: z.string().describe("Raw text content to analyze for tasks"),
      clickup_list_id: z.string().describe("ClickUp list ID for task creation"),
      priority_level: z.enum(["low", "normal", "high", "urgent"]).default("normal").describe("Default priority for extracted tasks"),
    },
    async ({ source_type, content, clickup_list_id, priority_level }) => {
      try {
        // For MCP API key authentication, we'll use the first available user's connections
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [clickupConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
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

        let response;
        try {
          response = await generateText({
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
        } catch (openaiError) {
          console.error('OpenAI API error:', openaiError);
          return {
            content: [{ 
              type: "text", 
              text: `Error calling OpenAI API: ${openaiError instanceof Error ? openaiError.message : "Unknown error"}` 
            }],
            isError: true,
          };
        }

        let extractedTasks: Array<{ title: string; description: string; priority: string }> = [];
        
        console.log('OpenAI response:', response.text);
        
        try {
          // Extract JSON from markdown code blocks if present
          let jsonText = response.text.trim();
          if (jsonText.startsWith('```json') && jsonText.endsWith('```')) {
            jsonText = jsonText.slice(7, -3).trim(); // Remove ```json and ```
          } else if (jsonText.startsWith('```') && jsonText.endsWith('```')) {
            jsonText = jsonText.slice(3, -3).trim(); // Remove ``` and ```
          }
          
          extractedTasks = JSON.parse(jsonText);
        } catch (parseError) {
          console.error('Failed to parse OpenAI response:', parseError);
          console.error('Raw response text:', response.text);
          return {
            content: [{ 
              type: "text", 
              text: `Error: Failed to parse AI response. Raw response: ${response.text.substring(0, 200)}...` 
            }],
            isError: true,
          };
        }

        if (!Array.isArray(extractedTasks) || extractedTasks.length === 0) {
          return {
            content: [{ type: "text", text: "No actionable tasks found in the provided content" }],
          };
        }

        // Create tasks in ClickUp
        const clickupAccessToken = await getToken(env.KV, clickupConnection.accessTokenHash);
        if (!clickupAccessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve ClickUp access token"
            }],
            isError: true
          };
        }
        const createdTaskIds: string[] = [];

        for (const task of extractedTasks) {
          try {
            const clickupTask = await createClickUpTask(clickupAccessToken, clickup_list_id, {
              name: task.title,
              description: task.description,
              priority: task.priority || priority_level,
            });
            
            if (clickupTask && clickupTask.id) {
              createdTaskIds.push(clickupTask.id);
            } else {
              console.error("ClickUp task creation returned invalid response:", clickupTask);
            }
          } catch (error) {
            console.error(`Failed to create ClickUp task "${task.title}":`, error);
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
          userId: defaultUser.id,
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

  // Calendar reading tool
  server.tool(
    "calendar_read_events",
    {
      date_range: z.string().describe("Date range to read events from (e.g., 'today', 'this_week', 'next_week', 'YYYY-MM-DD to YYYY-MM-DD')"),
      max_results: z.number().optional().describe("Maximum number of events to return (default: 25)"),
    },
    async ({ date_range, max_results = 25 }) => {
      try {
        // For MCP API key authentication, we'll use the first available user's connections
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [googleConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
              eq(schema.oauthConnections.provider, "google")
            )
          );

        if (!googleConnection) {
          return {
            content: [{ type: "text", text: "Error: Google Calendar not connected" }],
            isError: true,
          };
        }

        const accessToken = await getToken(env.KV, googleConnection.accessTokenHash);
        if (!accessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve Google Calendar access token"
            }],
            isError: true
          };
        }

        // Parse date range
        let timeMin: string, timeMax: string;
        const now = new Date();
        
        switch (date_range.toLowerCase()) {
          case 'today':
            timeMin = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
            timeMax = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1).toISOString();
            break;
          case 'this_week':
            const startOfWeek = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay());
            const endOfWeek = new Date(startOfWeek.getTime() + 7 * 24 * 60 * 60 * 1000);
            timeMin = startOfWeek.toISOString();
            timeMax = endOfWeek.toISOString();
            break;
          case 'next_week':
            const nextWeekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay() + 7);
            const nextWeekEnd = new Date(nextWeekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
            timeMin = nextWeekStart.toISOString();
            timeMax = nextWeekEnd.toISOString();
            break;
          default:
            // Try to parse custom date range like "2025-08-12 to 2025-08-15"
            const dateRangeMatch = date_range.match(/(\d{4}-\d{2}-\d{2})\s+to\s+(\d{4}-\d{2}-\d{2})/);
            if (dateRangeMatch) {
              timeMin = new Date(dateRangeMatch[1] + 'T00:00:00Z').toISOString();
              timeMax = new Date(dateRangeMatch[2] + 'T23:59:59Z').toISOString();
            } else {
              return {
                content: [{ type: "text", text: "Invalid date range format. Use 'today', 'this_week', 'next_week', or 'YYYY-MM-DD to YYYY-MM-DD'" }],
                isError: true,
              };
            }
        }

        // Fetch calendar events
        const response = await fetch(
          `https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin=${encodeURIComponent(timeMin)}&timeMax=${encodeURIComponent(timeMax)}&maxResults=${max_results}&singleEvents=true&orderBy=startTime`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          }
        );

        const result = await response.json() as any;

        if (!response.ok) {
          throw new Error(`Google Calendar API error: ${result.error?.message || 'Unknown error'}`);
        }

        const events = result.items || [];
        
        if (events.length === 0) {
          return {
            content: [{
              type: "text",
              text: `No events found for ${date_range}`
            }],
          };
        }

        const eventsList = events.map((event: any) => {
          const startTime = event.start?.dateTime || event.start?.date;
          const endTime = event.end?.dateTime || event.end?.date;
          return `• ${event.summary || 'No title'} (${new Date(startTime).toLocaleString()} - ${new Date(endTime).toLocaleString()})${event.location ? ` at ${event.location}` : ''}`;
        }).join('\n');

        return {
          content: [{
            type: "text",
            text: `Found ${events.length} calendar events for ${date_range}:\n\n${eventsList}`
          }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error reading calendar events: ${error instanceof Error ? error.message : "Unknown error"}` 
          }],
          isError: true,
        };
      }
    }
  );

  // Tasks reading tool
  server.tool(
    "tasks_read_list",
    {
      list_filter: z.string().optional().describe("Filter tasks by status: 'open', 'in_progress', 'completed', or 'all' (default: 'open')"),
      max_results: z.number().optional().describe("Maximum number of tasks to return (default: 25)"),
    },
    async ({ list_filter = 'open', max_results = 25 }) => {
      try {
        // For MCP API key authentication, we'll use the first available user's connections
        const [defaultUser] = await db
          .select()
          .from(schema.user)
          .limit(1);

        if (!defaultUser) {
          return {
            content: [{ type: "text", text: "Error: No users found in system" }],
            isError: true,
          };
        }

        const [clickupConnection] = await db
          .select()
          .from(schema.oauthConnections)
          .where(
            and(
              eq(schema.oauthConnections.userId, defaultUser.id),
              eq(schema.oauthConnections.provider, "clickup")
            )
          );

        if (!clickupConnection) {
          return {
            content: [{ type: "text", text: "Error: ClickUp not connected" }],
            isError: true,
          };
        }

        const accessToken = await getToken(env.KV, clickupConnection.accessTokenHash);
        if (!accessToken) {
          return {
            content: [{
              type: "text",
              text: "Failed to retrieve ClickUp access token"
            }],
            isError: true
          };
        }

        // Get the team and space info
        const teamsResponse = await fetch('https://api.clickup.com/api/v2/team', {
          headers: {
            Authorization: accessToken,
          },
        });

        const teamsData = await teamsResponse.json() as any;
        if (!teamsResponse.ok || !teamsData.teams?.length) {
          throw new Error('Failed to get ClickUp teams');
        }

        const teamId = teamsData.teams[0].id;
        
        // Get spaces
        const spacesResponse = await fetch(`https://api.clickup.com/api/v2/team/${teamId}/space?archived=false`, {
          headers: {
            Authorization: accessToken,
          },
        });

        const spacesData = await spacesResponse.json() as any;
        if (!spacesResponse.ok || !spacesData.spaces?.length) {
          throw new Error('Failed to get ClickUp spaces');
        }

        const spaceId = spacesData.spaces[0].id;

        // Get folders and lists
        const foldersResponse = await fetch(`https://api.clickup.com/api/v2/space/${spaceId}/folder?archived=false`, {
          headers: {
            Authorization: accessToken,
          },
        });

        const foldersData = await foldersResponse.json() as any;
        let listId: string;

        if (foldersData.folders?.length > 0) {
          listId = foldersData.folders[0].lists[0].id;
        } else {
          // Try to get folderless lists
          const listsResponse = await fetch(`https://api.clickup.com/api/v2/space/${spaceId}/list?archived=false`, {
            headers: {
              Authorization: accessToken,
            },
          });
          const listsData = await listsResponse.json() as any;
          if (!listsResponse.ok || !listsData.lists?.length) {
            throw new Error('No lists found in ClickUp workspace');
          }
          listId = listsData.lists[0].id;
        }

        // Build status filter
        let statusFilter = '';
        switch (list_filter.toLowerCase()) {
          case 'open':
            statusFilter = '&statuses[]=Open&statuses[]=to do';
            break;
          case 'in_progress':
            statusFilter = '&statuses[]=in progress&statuses[]=doing';
            break;
          case 'completed':
            statusFilter = '&statuses[]=complete&statuses[]=closed&statuses[]=done';
            break;
          case 'all':
            statusFilter = '';
            break;
        }

        // Get tasks
        const tasksResponse = await fetch(`https://api.clickup.com/api/v2/list/${listId}/task?archived=false${statusFilter}&page=0&order_by=created&reverse=true&subtasks=true&include_closed=${list_filter === 'all' || list_filter === 'completed'}`, {
          headers: {
            Authorization: accessToken,
          },
        });

        const tasksData = await tasksResponse.json() as any;

        if (!tasksResponse.ok) {
          throw new Error(`ClickUp API error: ${tasksData.err || 'Unknown error'}`);
        }

        const tasks = (tasksData.tasks || []).slice(0, max_results);

        if (tasks.length === 0) {
          return {
            content: [{
              type: "text",
              text: `No ${list_filter} tasks found`
            }],
          };
        }

        const tasksList = tasks.map((task: any) => {
          const priority = task.priority ? ` [Priority: ${task.priority.priority}]` : '';
          const dueDate = task.due_date ? ` [Due: ${new Date(parseInt(task.due_date)).toLocaleDateString()}]` : '';
          const assignees = task.assignees?.length > 0 ? ` [Assigned: ${task.assignees.map((a: any) => a.username).join(', ')}]` : '';
          return `• ${task.name} (${task.status.status})${priority}${dueDate}${assignees}`;
        }).join('\n');

        return {
          content: [{
            type: "text",
            text: `Found ${tasks.length} ${list_filter} tasks:\n\n${tasksList}`
          }],
        };
      } catch (error) {
        return {
          content: [{ 
            type: "text", 
            text: `Error reading tasks: ${error instanceof Error ? error.message : "Unknown error"}` 
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
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
            line-height: 1.6;
          }
          .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
          }
          .logo {
            font-size: 4rem;
            margin-bottom: 20px;
            animation: float 3s ease-in-out infinite;
          }
          @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
          }
          h1 {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
          }
          .subtitle {
            font-size: 1.1rem;
            color: #666;
            margin-bottom: 35px;
            font-weight: 400;
          }
          .actions {
            display: grid;
            gap: 15px;
          }
          .btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding: 16px 24px;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s ease;
            border: 2px solid transparent;
            position: relative;
            overflow: hidden;
          }
          .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
          }
          .btn:hover::before {
            left: 100%;
          }
          .btn-primary {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
          }
          .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
          }
          .btn-secondary {
            background: #f8f9fa;
            color: #495057;
            border: 2px solid #e9ecef;
          }
          .btn-secondary:hover {
            background: #e9ecef;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
          }
          .btn-google {
            background: #4285f4;
            color: white;
          }
          .btn-google:hover {
            background: #3367d6;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(66, 133, 244, 0.4);
          }
          .btn-spotify {
            background: #1db954;
            color: white;
          }
          .btn-spotify:hover {
            background: #1ed760;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(29, 185, 84, 0.4);
          }
          .btn-clickup {
            background: #7b68ee;
            color: white;
          }
          .btn-clickup:hover {
            background: #6c5ce7;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(123, 104, 238, 0.4);
          }
          .divider {
            margin: 25px 0;
            display: flex;
            align-items: center;
            color: #999;
            font-size: 0.9rem;
          }
          .divider::before,
          .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: #e0e0e0;
          }
          .divider span {
            padding: 0 15px;
          }
          .footer {
            margin-top: 30px;
            font-size: 0.85rem;
            color: #999;
          }
          .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
          }
          @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="logo">🎵</div>
          <h1>Vibe Summer Concierge</h1>
          <p class="subtitle">
            <span class="status-indicator"></span>
            Intelligent calendar management, focus music, and AI-powered task synthesis
          </p>
          
          <div class="actions">
            <a href="/login" class="btn btn-primary">
              🔐 Access MCP Server
            </a>
            
            <div class="divider">
              <span>Connect Your Services</span>
            </div>
            
            <a href="/oauth/connect/google" class="btn btn-google">
              📅 Connect Google Calendar
            </a>
            
            <a href="/oauth/connect/spotify" class="btn btn-spotify">
              🎶 Connect Spotify
            </a>
            
            <a href="/oauth/connect/clickup" class="btn btn-clickup">
              ✅ Connect ClickUp
            </a>
          </div>
          
          <div class="footer">
            <p>🤖 Powered by Model Context Protocol</p>
          </div>
        </div>
      </body>
    </html>
  `);
});

// Debug endpoint to check configuration
app.get("/debug/auth", async (c) => {
  return c.json({
    hasMcpApiKey: !!c.env.MCP_API_KEY,
    hasBaseUrl: !!c.env.BASE_URL,
    baseUrl: c.env.BASE_URL,
    hasGoogleOAuth: !!(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET),
    hasSpotifyOAuth: !!(c.env.SPOTIFY_CLIENT_ID && c.env.SPOTIFY_CLIENT_SECRET),
    hasClickUpOAuth: !!(c.env.CLICKUP_CLIENT_ID && c.env.CLICKUP_CLIENT_SECRET),
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
  
  // Add provider-specific parameters for refresh tokens
  if (provider === "google") {
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("prompt", "consent"); // Force consent to get refresh token
  }

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

        console.log('Inserting OAuth connection:', {
          ...connectionData,
          hasRefreshToken: !!refreshTokenHash,
          expiresIn: tokens.expires_in,
          tokenScopes: tokens.scope
        });

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
        const accessToken = await getToken(c.env.KV, connection.accessTokenHash);
        if (!accessToken) {
          console.error(`Failed to retrieve access token for user ${connection.userId}`);
          continue;
        }
        
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
        const refreshToken = await getToken(c.env.KV, connection.refreshTokenHash);
        if (!refreshToken) {
          console.error(`Failed to retrieve refresh token for connection ${connection.id}`);
          continue;
        }
        
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
          case "clickup":
            tokenUrl = "https://api.clickup.com/api/v2/oauth/token";
            clientId = c.env.CLICKUP_CLIENT_ID;
            clientSecret = c.env.CLICKUP_CLIENT_SECRET;
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
          const newAccessTokenHash = await hashToken(tokenData.access_token);
          await storeToken(c.env.KV, newAccessTokenHash, tokenData.access_token);
          
          let newRefreshTokenHash = connection.refreshTokenHash;
          if (tokenData.refresh_token) {
            newRefreshTokenHash = await hashToken(tokenData.refresh_token);
            await storeToken(c.env.KV, newRefreshTokenHash, tokenData.refresh_token);
          }

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

// Token status debug endpoint
app.get("/debug/tokens", async (c) => {
  const db = drizzle(c.env.DB);
  
  try {
    const connections = await db
      .select({
        id: schema.oauthConnections.id,
        provider: schema.oauthConnections.provider,
        expiresAt: schema.oauthConnections.expiresAt,
        hasRefreshToken: schema.oauthConnections.refreshTokenHash,
        createdAt: schema.oauthConnections.createdAt,
        updatedAt: schema.oauthConnections.updatedAt,
      })
      .from(schema.oauthConnections);

    const now = new Date();
    const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000);

    const tokenStatus = connections.map(conn => ({
      provider: conn.provider,
      expiresAt: conn.expiresAt,
      expiresIn: conn.expiresAt ? Math.round((conn.expiresAt.getTime() - now.getTime()) / (1000 * 60)) : null, // minutes
      needsRefresh: conn.expiresAt ? conn.expiresAt <= oneHourFromNow : false,
      hasRefreshToken: !!conn.hasRefreshToken,
      lastUpdated: conn.updatedAt,
    }));

    return c.json({
      currentTime: now.toISOString(),
      oneHourFromNow: oneHourFromNow.toISOString(),
      connections: tokenStatus,
      summary: {
        total: connections.length,
        needingRefresh: tokenStatus.filter(t => t.needsRefresh).length,
        withoutRefreshToken: tokenStatus.filter(t => !t.hasRefreshToken).length,
      }
    });
  } catch (error) {
    return c.json({ 
      error: "Failed to get token status", 
      details: error instanceof Error ? error.message : "Unknown error" 
    }, 500);
  }
});

// ClickUp debug endpoint
app.get("/debug/clickup", async (c) => {
  const db = drizzle(c.env.DB);
  
  try {
    // Get ClickUp connection
    const [defaultUser] = await db
      .select()
      .from(schema.user)
      .limit(1);

    if (!defaultUser) {
      return c.json({ error: "No users found in system" });
    }

    const [clickupConnection] = await db
      .select()
      .from(schema.oauthConnections)
      .where(
        and(
          eq(schema.oauthConnections.userId, defaultUser.id),
          eq(schema.oauthConnections.provider, "clickup")
        )
      );

    if (!clickupConnection) {
      return c.json({ error: "ClickUp not connected" });
    }

    const accessToken = await getToken(c.env.KV, clickupConnection.accessTokenHash);
    if (!accessToken) {
      return c.json({ error: "Failed to retrieve ClickUp access token" });
    }

    // Get teams
    const teamsResponse = await fetch('https://api.clickup.com/api/v2/team', {
      headers: { Authorization: accessToken },
    });
    const teamsData = await teamsResponse.json() as any;
    
    if (!teamsResponse.ok) {
      return c.json({ 
        error: "Failed to get ClickUp teams", 
        response: teamsData,
        status: teamsResponse.status 
      });
    }

    const teamId = teamsData.teams[0]?.id;
    if (!teamId) {
      return c.json({ error: "No teams found", teamsData });
    }

    // Get spaces
    const spacesResponse = await fetch(`https://api.clickup.com/api/v2/team/${teamId}/space?archived=false`, {
      headers: { Authorization: accessToken },
    });
    const spacesData = await spacesResponse.json() as any;

    if (!spacesResponse.ok) {
      return c.json({ 
        error: "Failed to get spaces", 
        response: spacesData,
        status: spacesResponse.status 
      });
    }

    const spaceId = spacesData.spaces[0]?.id;
    if (!spaceId) {
      return c.json({ error: "No spaces found", spacesData });
    }

    // Get folders and lists
    const foldersResponse = await fetch(`https://api.clickup.com/api/v2/space/${spaceId}/folder?archived=false`, {
      headers: { Authorization: accessToken },
    });
    const foldersData = await foldersResponse.json() as any;

    let listId: string | null = null;
    let debugInfo: any = {
      teamId,
      spaceId,
      foldersFound: foldersData.folders?.length || 0,
    };

    if (foldersData.folders?.length > 0) {
      listId = foldersData.folders[0].lists[0]?.id;
      debugInfo.listFromFolder = listId;
    } else {
      // Try to get folderless lists
      const listsResponse = await fetch(`https://api.clickup.com/api/v2/space/${spaceId}/list?archived=false`, {
        headers: { Authorization: accessToken },
      });
      const listsData = await listsResponse.json() as any;
      
      if (listsResponse.ok && listsData.lists?.length > 0) {
        listId = listsData.lists[0].id;
        debugInfo.listFromSpace = listId;
        debugInfo.folderlessLists = listsData.lists.length;
      } else {
        debugInfo.listsError = listsData;
      }
    }

    if (!listId) {
      return c.json({ 
        error: "No lists found in ClickUp workspace",
        debugInfo,
        foldersData,
      });
    }

    // Get tasks from the found list
    const tasksResponse = await fetch(`https://api.clickup.com/api/v2/list/${listId}/task?archived=false&page=0&order_by=created&reverse=true&subtasks=true&include_closed=true`, {
      headers: { Authorization: accessToken },
    });
    const tasksData = await tasksResponse.json() as any;

    return c.json({
      success: true,
      debugInfo,
      tasksFound: tasksData.tasks?.length || 0,
      firstFewTasks: tasksData.tasks?.slice(0, 3).map((task: any) => ({
        id: task.id,
        name: task.name,
        status: task.status?.status,
        priority: task.priority?.priority,
      })) || [],
      rawTasksResponse: tasksData,
    });

  } catch (error) {
    return c.json({ 
      error: "Debug failed", 
      details: error instanceof Error ? error.message : "Unknown error" 
    }, 500);
  }
});

// API endpoints for user management
app.get("/api/user/profile", async (c) => {
  // For MCP API key authentication, return default user profile
  const db = drizzle(c.env.DB);
  const [user] = await db
    .select()
    .from(schema.user)
    .where(eq(schema.user.id, "default-user"))
    .limit(1);

  if (!user) {
    return c.json({ error: "Default user not found" }, 404);
  }

  return c.json({ user });
});

app.get("/api/user/connections", async (c) => {
  // For MCP API key authentication, return default user connections
  const db = drizzle(c.env.DB);
  const connections = await db
    .select({
      provider: schema.oauthConnections.provider,
      createdAt: schema.oauthConnections.createdAt,
      expiresAt: schema.oauthConnections.expiresAt,
    })
    .from(schema.oauthConnections)
    .where(eq(schema.oauthConnections.userId, "default-user"));

  return c.json({ connections });
});

app.get("/api/user/music-sessions", async (c) => {
  // For MCP API key authentication, return default user music sessions
  const db = drizzle(c.env.DB);
  const sessions = await db
    .select()
    .from(schema.musicSessions)
    .where(eq(schema.musicSessions.userId, "default-user"))
    .orderBy(desc(schema.musicSessions.startedAt))
    .limit(50);

  return c.json({ sessions });
});

app.get("/api/user/task-history", async (c) => {
  // For MCP API key authentication, return default user task history
  const db = drizzle(c.env.DB);
  const history = await db
    .select()
    .from(schema.taskSynthesisHistory)
    .where(eq(schema.taskSynthesisHistory.userId, "default-user"))
    .orderBy(desc(schema.taskSynthesisHistory.createdAt))
    .limit(50);

  return c.json({ history });
});

// ClickUp debugging endpoint
app.get("/api/clickup/debug", async (c) => {
  const db = drizzle(c.env.DB);
  
  // Check if default user has ClickUp connection
  const [clickupConnection] = await db
    .select()
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.userId, "default-user"),
        eq(schema.oauthConnections.provider, "clickup")
      )
    );

  if (!clickupConnection) {
    return c.json({
      hasConnection: false,
      message: "No ClickUp connection found for default user",
      connectUrl: `${new URL(c.req.url).origin}/oauth/connect/clickup`
    });
  }

  // Try to get access token
  const accessToken = await getToken(c.env.KV, clickupConnection.accessTokenHash);
  
  if (!accessToken) {
    return c.json({
      hasConnection: true,
      hasValidToken: false,
      message: "ClickUp connection exists but token is not available",
      connectionInfo: {
        createdAt: clickupConnection.createdAt,
        expiresAt: clickupConnection.expiresAt,
        scopes: clickupConnection.scopes
      }
    });
  }

  // Try to get user's spaces
  try {
    const spacesResponse = await fetch("https://api.clickup.com/api/v2/team", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!spacesResponse.ok) {
      const errorText = await spacesResponse.text();
      return c.json({
        hasConnection: true,
        hasValidToken: true,
        apiError: true,
        message: "ClickUp API error when fetching teams",
        error: errorText,
        status: spacesResponse.status
      });
    }

    const teamsData = await spacesResponse.json() as any;
    
    // Also try to get spaces separately
    const allSpaces: any[] = [];
    const allLists: any[] = [];
    
    if (teamsData.teams && teamsData.teams.length > 0) {
      for (const team of teamsData.teams) {
        try {
          const teamSpacesResponse = await fetch(`https://api.clickup.com/api/v2/team/${team.id}/space`, {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          });
          
          if (teamSpacesResponse.ok) {
            const spacesData = await teamSpacesResponse.json() as any;
            if (spacesData.spaces) {
              for (const space of spacesData.spaces) {
                allSpaces.push({
                  id: space.id,
                  name: space.name,
                  teamId: team.id,
                  teamName: team.name
                });
                
                // Get lists for each space
                try {
                  const listsResponse = await fetch(`https://api.clickup.com/api/v2/space/${space.id}/list`, {
                    headers: {
                      Authorization: `Bearer ${accessToken}`,
                    },
                  });
                  
                  if (listsResponse.ok) {
                    const listsData = await listsResponse.json() as any;
                    if (listsData.lists) {
                      allLists.push(...listsData.lists.map((list: any) => ({
                        id: list.id,
                        name: list.name,
                        spaceId: space.id,
                        spaceName: space.name,
                        teamId: team.id,
                        teamName: team.name
                      })));
                    }
                  }
                } catch (listError) {
                  console.error(`Error fetching lists for space ${space.id}:`, listError);
                }
              }
            }
          }
        } catch (spaceError) {
          console.error(`Error fetching spaces for team ${team.id}:`, spaceError);
        }
      }
    }
    
    return c.json({
      hasConnection: true,
      hasValidToken: true,
      apiWorking: true,
      teams: teamsData.teams?.map((team: any) => ({
        id: team.id,
        name: team.name,
        spaces: team.spaces?.map((space: any) => ({
          id: space.id,
          name: space.name
        }))
      })) || [],
      allSpaces: allSpaces,
      allLists: allLists,
      suggestedListId: allLists.length > 0 ? allLists[0].id : null,
      message: allLists.length > 0 
        ? `Found ${allLists.length} lists. Use list ID: ${allLists[0].id} for task creation.`
        : allSpaces.length > 0
          ? `Found ${allSpaces.length} spaces but no lists. Create a list in ClickUp first.`
          : "No spaces or lists found. Create a space and list in ClickUp first."
    });

  } catch (error) {
    return c.json({
      hasConnection: true,
      hasValidToken: true,
      apiError: true,
      message: "Error calling ClickUp API",
      error: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

// Test ClickUp task creation
app.post("/api/clickup/test-task", async (c) => {
  const { listId, taskName } = await c.req.json();
  
  if (!listId || !taskName) {
    return c.json({ error: "Missing listId or taskName" }, 400);
  }

  const db = drizzle(c.env.DB);
  
  // Get ClickUp connection
  const [clickupConnection] = await db
    .select()
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.userId, "default-user"),
        eq(schema.oauthConnections.provider, "clickup")
      )
    );

  if (!clickupConnection) {
    return c.json({ error: "No ClickUp connection found" });
  }

  const accessToken = await getToken(c.env.KV, clickupConnection.accessTokenHash);
  if (!accessToken) {
    return c.json({ error: "No valid access token" });
  }

  try {
    const task = await createClickUpTask(accessToken, listId, {
      name: taskName,
      description: "Test task created via API",
      priority: "normal"
    });

    return c.json({ 
      success: true, 
      task: task,
      message: "Task created successfully!"
    });
  } catch (error) {
    return c.json({ 
      error: "Failed to create task",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

// Token status debug endpoint
app.get("/api/clickup/token-status", async (c) => {
  const db = drizzle(c.env.DB);
  
  const [clickupConnection] = await db
    .select()
    .from(schema.oauthConnections)
    .where(
      and(
        eq(schema.oauthConnections.userId, "default-user"),
        eq(schema.oauthConnections.provider, "clickup")
      )
    );

  if (!clickupConnection) {
    return c.json({ error: "No ClickUp connection found" });
  }

  const now = new Date();
  const timeUntilExpiry = clickupConnection.expiresAt 
    ? clickupConnection.expiresAt.getTime() - now.getTime()
    : null;

  return c.json({
    connectionId: clickupConnection.id,
    userId: clickupConnection.userId,
    provider: clickupConnection.provider,
    createdAt: clickupConnection.createdAt,
    updatedAt: clickupConnection.updatedAt,
    expiresAt: clickupConnection.expiresAt,
    hasRefreshToken: !!clickupConnection.refreshTokenHash,
    isExpired: clickupConnection.expiresAt ? now > clickupConnection.expiresAt : false,
    timeUntilExpiryMs: timeUntilExpiry,
    timeUntilExpiryHours: timeUntilExpiry ? Math.round(timeUntilExpiry / (1000 * 60 * 60)) : null,
    scopes: clickupConnection.scopes
  });
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

// Scheduled event handler for cron jobs
export default {
  fetch: app.fetch,
  scheduled: async (event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) => {
    console.log('Cron job triggered at:', new Date().toISOString());
    
    try {
      // Refresh OAuth tokens
      const db = drizzle(env.DB);
      
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
          const refreshToken = await getToken(env.KV, connection.refreshTokenHash);
          if (!refreshToken) {
            console.error(`Failed to retrieve refresh token for connection ${connection.id}`);
            continue;
          }
          
          let tokenUrl: string;
          let clientId: string;
          let clientSecret: string;

          switch (connection.provider) {
            case "google":
              tokenUrl = "https://oauth2.googleapis.com/token";
              clientId = env.GOOGLE_CLIENT_ID;
              clientSecret = env.GOOGLE_CLIENT_SECRET;
              break;
            case "spotify":
              tokenUrl = "https://accounts.spotify.com/api/token";
              clientId = env.SPOTIFY_CLIENT_ID;
              clientSecret = env.SPOTIFY_CLIENT_SECRET;
              break;
            case "clickup":
              tokenUrl = "https://api.clickup.com/api/v2/oauth/token";
              clientId = env.CLICKUP_CLIENT_ID;
              clientSecret = env.CLICKUP_CLIENT_SECRET;
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
            const newAccessTokenHash = await hashToken(tokenData.access_token);
            await storeToken(env.KV, newAccessTokenHash, tokenData.access_token);
            
            let newRefreshTokenHash = connection.refreshTokenHash;
            if (tokenData.refresh_token) {
              newRefreshTokenHash = await hashToken(tokenData.refresh_token);
              await storeToken(env.KV, newRefreshTokenHash, tokenData.refresh_token);
            }

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
            console.log(`Successfully refreshed token for ${connection.provider} connection ${connection.id}`);
          }
        } catch (error) {
          console.error(`Failed to refresh token for connection ${connection.id}:`, error);
        }
      }

      console.log(`Cron job completed. Refreshed ${refreshedTokens} tokens.`);
    } catch (error) {
      console.error('Cron job failed:', error);
    }
  }
};
;