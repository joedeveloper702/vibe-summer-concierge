// import { sql } from "drizzle-orm"; // Removed unused import
import { integer, sqliteTable, text, index, uniqueIndex } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";

export const user = sqliteTable("user", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" })
    .$defaultFn(() => false)
    .notNull(),
  image: text("image"),
  timezone: text("timezone").notNull().default("UTC"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  uniqueIndex("user_email_unique").on(t.email),
]);

export const session = sqliteTable("session", {
  id: text("id").primaryKey(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  token: text("token").notNull().unique(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
});

export const account = sqliteTable("account", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: integer("access_token_expires_at", {
    mode: "timestamp",
  }),
  refreshTokenExpiresAt: integer("refresh_token_expires_at", {
    mode: "timestamp",
  }),
  scope: text("scope"),
  password: text("password"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const verification = sqliteTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
  updatedAt: integer("updated_at", { mode: "timestamp" }).$defaultFn(
    () => new Date(),
  ),
});

export const oauthApplication = sqliteTable("oauth_application", {
  id: text("id").primaryKey(),
  name: text("name"),
  icon: text("icon"),
  metadata: text("metadata"),
  clientId: text("client_id").unique(),
  clientSecret: text("client_secret"),
  redirectURLs: text("redirect_u_r_ls"),
  type: text("type"),
  disabled: integer("disabled", { mode: "boolean" }),
  userId: text("user_id"),
  createdAt: integer("created_at", { mode: "timestamp" }),
  updatedAt: integer("updated_at", { mode: "timestamp" }),
});

export const oauthAccessToken = sqliteTable("oauth_access_token", {
  id: text("id").primaryKey(),
  accessToken: text("access_token").unique(),
  refreshToken: text("refresh_token").unique(),
  accessTokenExpiresAt: integer("access_token_expires_at", {
    mode: "timestamp",
  }),
  refreshTokenExpiresAt: integer("refresh_token_expires_at", {
    mode: "timestamp",
  }),
  clientId: text("client_id"),
  userId: text("user_id"),
  scopes: text("scopes"),
  createdAt: integer("created_at", { mode: "timestamp" }),
  updatedAt: integer("updated_at", { mode: "timestamp" }),
});

export const oauthConsent = sqliteTable("oauth_consent", {
  id: text("id").primaryKey(),
  clientId: text("client_id"),
  userId: text("user_id"),
  scopes: text("scopes"),
  createdAt: integer("created_at", { mode: "timestamp" }),
  updatedAt: integer("updated_at", { mode: "timestamp" }),
  consentGiven: integer("consent_given", { mode: "boolean" }),
});

export const oauthConnections = sqliteTable("oauth_connections", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  provider: text("provider", { enum: ["google", "spotify", "clickup"] }).notNull(),
  providerUserId: text("provider_user_id").notNull(),
  accessTokenHash: text("access_token_hash").notNull(),
  refreshTokenHash: text("refresh_token_hash"),
  expiresAt: integer("expires_at", { mode: "timestamp" }),
  scopes: text("scopes", { mode: "json" }).$type<string[]>(),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  uniqueIndex("oauth_connections_user_provider_unique").on(t.userId, t.provider),
  index("oauth_connections_provider_idx").on(t.provider),
]);

export const calendarPreferences = sqliteTable("calendar_preferences", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  defaultBufferMinutes: integer("default_buffer_minutes").notNull().default(15),
  travelTimeEnabled: integer("travel_time_enabled", { mode: "boolean" }).notNull().default(true),
  autoDefenseEnabled: integer("auto_defense_enabled", { mode: "boolean" }).notNull().default(true),
  focusTimeBlocks: text("focus_time_blocks", { mode: "json" }).$type<Array<{ start: string; end: string; days: string[] }>>(),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  uniqueIndex("calendar_preferences_user_unique").on(t.userId),
]);

export const taskSynthesisHistory = sqliteTable("task_synthesis_history", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  sourceType: text("source_type", { enum: ["email", "note", "transcript"] }).notNull(),
  sourceContentHash: text("source_content_hash").notNull(),
  extractedTasks: text("extracted_tasks", { mode: "json" }).$type<Array<{ title: string; description: string; priority: string }>>().notNull(),
  clickupTaskIds: text("clickup_task_ids", { mode: "json" }).$type<string[]>(),
  processingStatus: text("processing_status", { enum: ["pending", "completed", "failed"] }).notNull().default("pending"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  index("task_synthesis_history_user_idx").on(t.userId),
  index("task_synthesis_history_status_idx").on(t.processingStatus),
  index("task_synthesis_history_source_type_idx").on(t.sourceType),
]);

export const musicSessions = sqliteTable("music_sessions", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  sessionType: text("session_type", { enum: ["focus", "break", "deep_work"] }).notNull(),
  playlistId: text("playlist_id"),
  durationMinutes: integer("duration_minutes"),
  startedAt: integer("started_at", { mode: "timestamp" }).notNull(),
  endedAt: integer("ended_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  index("music_sessions_user_idx").on(t.userId),
  index("music_sessions_type_idx").on(t.sessionType),
  index("music_sessions_started_at_idx").on(t.startedAt),
]);

export const calendarEvents = sqliteTable("calendar_events", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  googleEventId: text("google_event_id").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  startTime: integer("start_time", { mode: "timestamp" }).notNull(),
  endTime: integer("end_time", { mode: "timestamp" }).notNull(),
  location: text("location"),
  isDefended: integer("is_defended", { mode: "boolean" }).notNull().default(false),
  bufferMinutes: integer("buffer_minutes"),
  travelTimeMinutes: integer("travel_time_minutes"),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  uniqueIndex("calendar_events_user_google_event_unique").on(t.userId, t.googleEventId),
  index("calendar_events_user_idx").on(t.userId),
  index("calendar_events_start_time_idx").on(t.startTime),
  index("calendar_events_is_defended_idx").on(t.isDefended),
]);

export const notes = sqliteTable("notes", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  content: text("content").notNull(),
  tags: text("tags", { mode: "json" }).$type<string[]>(),
  isProcessed: integer("is_processed", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  index("notes_user_idx").on(t.userId),
  index("notes_is_processed_idx").on(t.isProcessed),
  index("notes_created_at_idx").on(t.createdAt),
]);

export const actions = sqliteTable("actions", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  type: text("type", { enum: ["calendar_defense", "task_synthesis", "music_session", "token_refresh"] }).notNull(),
  status: text("status", { enum: ["pending", "in_progress", "completed", "failed"] }).notNull().default("pending"),
  payload: text("payload", { mode: "json" }).$type<Record<string, any>>(),
  result: text("result", { mode: "json" }).$type<Record<string, any>>(),
  errorMessage: text("error_message"),
  scheduledFor: integer("scheduled_for", { mode: "timestamp" }),
  startedAt: integer("started_at", { mode: "timestamp" }),
  completedAt: integer("completed_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  index("actions_user_idx").on(t.userId),
  index("actions_type_idx").on(t.type),
  index("actions_status_idx").on(t.status),
  index("actions_scheduled_for_idx").on(t.scheduledFor),
]);

export const cache = sqliteTable("cache", {
  id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
  key: text("key").notNull().unique(),
  value: text("value", { mode: "json" }).$type<any>().notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" })
    .$defaultFn(() => new Date())
    .notNull(),
}, (t) => [
  uniqueIndex("cache_key_unique").on(t.key),
  index("cache_expires_at_idx").on(t.expiresAt),
]);

export const userRelations = relations(user, ({ many, one }) => ({
  oauthConnections: many(oauthConnections),
  calendarPreferences: one(calendarPreferences),
  taskSynthesisHistory: many(taskSynthesisHistory),
  musicSessions: many(musicSessions),
  calendarEvents: many(calendarEvents),
  notes: many(notes),
  actions: many(actions),
}));

export const oauthConnectionsRelations = relations(oauthConnections, ({ one }) => ({
  user: one(user, {
    fields: [oauthConnections.userId],
    references: [user.id],
  }),
}));

export const calendarPreferencesRelations = relations(calendarPreferences, ({ one }) => ({
  user: one(user, {
    fields: [calendarPreferences.userId],
    references: [user.id],
  }),
}));

export const taskSynthesisHistoryRelations = relations(taskSynthesisHistory, ({ one }) => ({
  user: one(user, {
    fields: [taskSynthesisHistory.userId],
    references: [user.id],
  }),
}));

export const musicSessionsRelations = relations(musicSessions, ({ one }) => ({
  user: one(user, {
    fields: [musicSessions.userId],
    references: [user.id],
  }),
}));

export const calendarEventsRelations = relations(calendarEvents, ({ one }) => ({
  user: one(user, {
    fields: [calendarEvents.userId],
    references: [user.id],
  }),
}));

export const notesRelations = relations(notes, ({ one }) => ({
  user: one(user, {
    fields: [notes.userId],
    references: [user.id],
  }),
}));

export const actionsRelations = relations(actions, ({ one }) => ({
  user: one(user, {
    fields: [actions.userId],
    references: [user.id],
  }),
}));