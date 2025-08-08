CREATE TABLE `account` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`provider_id` text NOT NULL,
	`user_id` text NOT NULL,
	`access_token` text,
	`refresh_token` text,
	`id_token` text,
	`access_token_expires_at` integer,
	`refresh_token_expires_at` integer,
	`scope` text,
	`password` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `actions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`type` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`payload` text,
	`result` text,
	`error_message` text,
	`scheduled_for` integer,
	`started_at` integer,
	`completed_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `actions_user_idx` ON `actions` (`user_id`);--> statement-breakpoint
CREATE INDEX `actions_type_idx` ON `actions` (`type`);--> statement-breakpoint
CREATE INDEX `actions_status_idx` ON `actions` (`status`);--> statement-breakpoint
CREATE INDEX `actions_scheduled_for_idx` ON `actions` (`scheduled_for`);--> statement-breakpoint
CREATE TABLE `cache` (
	`id` text PRIMARY KEY NOT NULL,
	`key` text NOT NULL,
	`value` text NOT NULL,
	`expires_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `cache_key_unique` ON `cache` (`key`);--> statement-breakpoint
CREATE INDEX `cache_expires_at_idx` ON `cache` (`expires_at`);--> statement-breakpoint
CREATE TABLE `calendar_events` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`google_event_id` text NOT NULL,
	`title` text NOT NULL,
	`description` text,
	`start_time` integer NOT NULL,
	`end_time` integer NOT NULL,
	`location` text,
	`is_defended` integer DEFAULT false NOT NULL,
	`buffer_minutes` integer,
	`travel_time_minutes` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `calendar_events_user_google_event_unique` ON `calendar_events` (`user_id`,`google_event_id`);--> statement-breakpoint
CREATE INDEX `calendar_events_user_idx` ON `calendar_events` (`user_id`);--> statement-breakpoint
CREATE INDEX `calendar_events_start_time_idx` ON `calendar_events` (`start_time`);--> statement-breakpoint
CREATE INDEX `calendar_events_is_defended_idx` ON `calendar_events` (`is_defended`);--> statement-breakpoint
CREATE TABLE `calendar_preferences` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`default_buffer_minutes` integer DEFAULT 15 NOT NULL,
	`travel_time_enabled` integer DEFAULT true NOT NULL,
	`auto_defense_enabled` integer DEFAULT true NOT NULL,
	`focus_time_blocks` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `calendar_preferences_user_unique` ON `calendar_preferences` (`user_id`);--> statement-breakpoint
CREATE TABLE `music_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`session_type` text NOT NULL,
	`playlist_id` text,
	`duration_minutes` integer,
	`started_at` integer NOT NULL,
	`ended_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `music_sessions_user_idx` ON `music_sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `music_sessions_type_idx` ON `music_sessions` (`session_type`);--> statement-breakpoint
CREATE INDEX `music_sessions_started_at_idx` ON `music_sessions` (`started_at`);--> statement-breakpoint
CREATE TABLE `notes` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`title` text NOT NULL,
	`content` text NOT NULL,
	`tags` text,
	`is_processed` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `notes_user_idx` ON `notes` (`user_id`);--> statement-breakpoint
CREATE INDEX `notes_is_processed_idx` ON `notes` (`is_processed`);--> statement-breakpoint
CREATE INDEX `notes_created_at_idx` ON `notes` (`created_at`);--> statement-breakpoint
CREATE TABLE `oauth_access_token` (
	`id` text PRIMARY KEY NOT NULL,
	`access_token` text,
	`refresh_token` text,
	`access_token_expires_at` integer,
	`refresh_token_expires_at` integer,
	`client_id` text,
	`user_id` text,
	`scopes` text,
	`created_at` integer,
	`updated_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_access_token_access_token_unique` ON `oauth_access_token` (`access_token`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_access_token_refresh_token_unique` ON `oauth_access_token` (`refresh_token`);--> statement-breakpoint
CREATE TABLE `oauth_application` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text,
	`icon` text,
	`metadata` text,
	`client_id` text,
	`client_secret` text,
	`redirect_u_r_ls` text,
	`type` text,
	`disabled` integer,
	`user_id` text,
	`created_at` integer,
	`updated_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_application_client_id_unique` ON `oauth_application` (`client_id`);--> statement-breakpoint
CREATE TABLE `oauth_connections` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`provider` text NOT NULL,
	`provider_user_id` text NOT NULL,
	`access_token_hash` text NOT NULL,
	`refresh_token_hash` text,
	`expires_at` integer,
	`scopes` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_connections_user_provider_unique` ON `oauth_connections` (`user_id`,`provider`);--> statement-breakpoint
CREATE INDEX `oauth_connections_provider_idx` ON `oauth_connections` (`provider`);--> statement-breakpoint
CREATE TABLE `oauth_consent` (
	`id` text PRIMARY KEY NOT NULL,
	`client_id` text,
	`user_id` text,
	`scopes` text,
	`created_at` integer,
	`updated_at` integer,
	`consent_given` integer
);
--> statement-breakpoint
CREATE TABLE `session` (
	`id` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL,
	`token` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`ip_address` text,
	`user_agent` text,
	`user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `session_token_unique` ON `session` (`token`);--> statement-breakpoint
CREATE TABLE `task_synthesis_history` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`source_type` text NOT NULL,
	`source_content_hash` text NOT NULL,
	`extracted_tasks` text NOT NULL,
	`clickup_task_ids` text,
	`processing_status` text DEFAULT 'pending' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `task_synthesis_history_user_idx` ON `task_synthesis_history` (`user_id`);--> statement-breakpoint
CREATE INDEX `task_synthesis_history_status_idx` ON `task_synthesis_history` (`processing_status`);--> statement-breakpoint
CREATE INDEX `task_synthesis_history_source_type_idx` ON `task_synthesis_history` (`source_type`);--> statement-breakpoint
CREATE TABLE `user` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`email` text NOT NULL,
	`email_verified` integer NOT NULL,
	`image` text,
	`timezone` text DEFAULT 'UTC' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_email_unique` ON `user` (`email`);--> statement-breakpoint
CREATE TABLE `verification` (
	`id` text PRIMARY KEY NOT NULL,
	`identifier` text NOT NULL,
	`value` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer,
	`updated_at` integer
);
