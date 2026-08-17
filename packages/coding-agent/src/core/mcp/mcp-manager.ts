// Host side of MCP integrations. The protocol itself runs Python-side in the kernel; the host
// only registers OAuth providers, gates integration skills by auth, and serves mcp.* host-requests.

import {
	BUILTIN_MCP_CATALOG,
	createMcpOAuthProvider,
	getCatalogEntry,
	registerBuiltinMcpOAuthProviders,
} from "@zero-agent/ai/mcp";
import { registerOAuthProvider, unregisterOAuthProvider } from "@zero-agent/ai/oauth";
import type { AuthStorage } from "../auth-storage.js";
import type { McpServerConfig } from "../settings-manager.js";

export interface McpManagerOptions {
	authStorage: AuthStorage;
	/** Reads the current Settings.mcpServers (name → config). Re-read on refresh(). */
	getUserServers?: () => Record<string, McpServerConfig> | undefined;
	/** Start an interactive host-side login for a server. Provided by the UI mode. */
	beginLogin?: (server: string) => Promise<void>;
}

/**
 * A resolved integration: a catalog/user entry plus its provider id.
 *
 * module J: stdio transport support. HTTP integrations still authenticate via
 * the host (OAuth or a bearer env var); a stdio integration's "credential" is
 * the local command itself, so it's always considered configured once
 * declared — there's no host-side auth step to gate it on.
 */
interface ResolvedIntegration {
	server: string;
	label: string;
	transport: "http" | "stdio";
	url?: string;
	usesOAuth: boolean;
	bearerTokenEnvVar?: string;
	enabled?: boolean;
	/** Extra static HTTP headers from the user config. */
	headers?: Record<string, string>;
	/** stdio only: the command to spawn, its args, and extra env vars. */
	command?: string;
	args?: string[];
	env?: Record<string, string>;
	/** True when this came from Settings.mcpServers (may override a catalog name). */
	userDeclared?: boolean;
}

export class McpManager {
	private readonly authStorage: AuthStorage;
	private readonly getUserServers: () => Record<string, McpServerConfig> | undefined;
	private readonly beginLogin?: (server: string) => Promise<void>;
	private integrations = new Map<string, ResolvedIntegration>();
	/** Provider ids we registered for user servers, so refresh can drop removed ones. */
	private registeredUserProviderIds = new Set<string>();

	constructor(options: McpManagerOptions) {
		this.authStorage = options.authStorage;
		this.getUserServers = options.getUserServers ?? (() => undefined);
		this.beginLogin = options.beginLogin;
		this.resolveIntegrations();
		this.registerProviders();
	}

	/** Re-read settings and re-register providers; call after a session reload. */
	refresh(): void {
		this.resolveIntegrations();
		this.registerProviders();
	}

	private providerId(server: string): string {
		return `mcp:${server}`;
	}

	private resolveIntegrations(): void {
		const integrations = new Map<string, ResolvedIntegration>();
		for (const entry of BUILTIN_MCP_CATALOG) {
			integrations.set(entry.server, {
				server: entry.server,
				label: entry.label,
				transport: "http",
				url: entry.url,
				usesOAuth: entry.oauth?.kind === "oauth",
			});
		}
		for (const [server, config] of Object.entries(this.getUserServers() ?? {})) {
			if (config.type === "stdio") {
				integrations.set(server, {
					server,
					label: server,
					transport: "stdio",
					usesOAuth: false,
					enabled: config.enabled,
					command: config.command,
					args: config.args,
					env: config.env,
					userDeclared: true,
				});
				continue;
			}
			integrations.set(server, {
				server,
				label: server,
				transport: "http",
				url: config.url,
				usesOAuth: config.oauth === true,
				bearerTokenEnvVar: config.bearerTokenEnvVar,
				enabled: config.enabled,
				headers: config.headers,
				userDeclared: true,
			});
		}
		this.integrations = integrations;
	}

	private registerProviders(): void {
		registerBuiltinMcpOAuthProviders();
		this.registerUserProviders();
	}

	/**
	 * Register OAuth providers for user-declared (non-catalog) servers. Public so it
	 * can run after ModelRegistry.refresh() resets the registry — otherwise custom
	 * `mcp:<server>` providers vanish on every refresh (e.g. post-login).
	 */
	registerUserProviders(): void {
		const current = new Set<string>();
		for (const integration of this.integrations.values()) {
			if (!integration.userDeclared) continue;
			const id = this.providerId(integration.server);
			if (integration.usesOAuth && integration.url) {
				// Register pointing at the user's URL (overrides a catalog default too).
				// usesOAuth is only ever true for the http transport, so url is always
				// set here — the check is for the type-checker, not runtime behavior.
				current.add(id);
				registerOAuthProvider(
					createMcpOAuthProvider({
						server: integration.server,
						label: integration.label,
						url: integration.url,
					}),
				);
			} else if (getCatalogEntry(integration.server)) {
				// User overrode a catalog server with a custom URL but no oauth: drop the
				// built-in provider so we never send the official token to that URL.
				unregisterOAuthProvider(id);
			}
		}
		// Drop providers for user servers removed since the last registration.
		for (const id of this.registeredUserProviderIds) {
			if (!current.has(id)) unregisterOAuthProvider(id);
		}
		this.registeredUserProviderIds = current;
	}

	/** True when valid credentials exist for the integration (drives enablement). */
	private isAuthed(integration: ResolvedIntegration): boolean {
		if (integration.enabled === false) return false;
		// A stdio integration's "credential" is the local command itself — there is
		// no host-side auth step to gate it on, unlike an HTTP integration.
		if (integration.transport === "stdio") return Boolean(integration.command);
		if (integration.bearerTokenEnvVar && process.env[integration.bearerTokenEnvVar]?.trim()) {
			return true;
		}
		// A user server that overrides a catalog name must NOT inherit the built-in's
		// stored mcp: creds — those were issued for the official endpoint and could be
		// sent to the override URL. Such an override authenticates only via a bearer
		// env var (handled above); we don't trust auth.json OAuth creds for it.
		if (integration.userDeclared && getCatalogEntry(integration.server)) {
			return false;
		}
		const cred = this.authStorage.get(this.providerId(integration.server));
		return cred !== undefined;
	}

	/** `-<server>/SKILL.md` overrides for every built-in integration the user isn't logged into. */
	getDisabledBuiltinSkillOverrides(): string[] {
		const overrides: string[] = [];
		for (const entry of BUILTIN_MCP_CATALOG) {
			const integration = this.integrations.get(entry.server);
			if (integration && !this.isAuthed(integration)) {
				overrides.push(`-${entry.server}/SKILL.md`);
			}
		}
		return overrides;
	}

	/** Host-request handlers exposed to the kernel. */
	hostHandlers(): Record<string, (payload: Record<string, unknown>) => Promise<Record<string, unknown>>> {
		const handlers: Record<string, (payload: Record<string, unknown>) => Promise<Record<string, unknown>>> = {
			"mcp.refresh": async (payload) => {
				const server = String(payload.server ?? "");
				if (!server) throw new Error("mcp.refresh requires a server");
				// getApiKey refreshes + rewrites auth.json under lock; Python re-reads.
				// Surface failure (throw) instead of a false success so the kernel can
				// report a refresh error rather than a misleading "not enabled".
				const key = await this.authStorage.getApiKey(this.providerId(server));
				if (!key) throw new Error(`Could not refresh credentials for ${server}`);
				return {};
			},
			// Resolved config so the kernel skill connects the same way the host
			// registered/authenticated (honors a user's mcpServers override), for
			// either transport: HTTP gets {type, url, headers?}, stdio gets
			// {type, command, args?, env?} — the skill never hardcodes either.
			"mcp.config": async (payload) => {
				const server = String(payload.server ?? "");
				if (!server) throw new Error("mcp.config requires a server");
				const integration = this.integrations.get(server);
				if (!integration) return {};
				if (integration.transport === "stdio") {
					const config: Record<string, unknown> = { type: "stdio", command: integration.command };
					if (integration.args && integration.args.length > 0) config.args = integration.args;
					if (integration.env && Object.keys(integration.env).length > 0) config.env = integration.env;
					return config;
				}
				const config: Record<string, unknown> = { type: "http", url: integration.url };
				if (integration.headers && Object.keys(integration.headers).length > 0) {
					config.headers = integration.headers;
				}
				return config;
			},
		};
		// Only expose begin_login when an interactive login is actually wired, so the
		// kernel doesn't get a handler whose only behavior is to throw.
		const beginLogin = this.beginLogin;
		if (beginLogin) {
			handlers["mcp.begin_login"] = async (payload) => {
				const server = String(payload.server ?? "");
				if (!server) throw new Error("mcp.begin_login requires a server");
				await beginLogin(server);
				return {};
			};
		}
		return handlers;
	}

	/** Status for the /mcp list command. */
	listStatus(): Array<{
		server: string;
		label: string;
		enabled: boolean;
		usesOAuth: boolean;
		transport: "http" | "stdio";
	}> {
		return Array.from(this.integrations.values()).map((integration) => ({
			server: integration.server,
			label: integration.label,
			enabled: this.isAuthed(integration),
			usesOAuth: integration.usesOAuth,
			transport: integration.transport,
		}));
	}
}
