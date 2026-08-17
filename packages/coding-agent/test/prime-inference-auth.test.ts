import { Buffer } from "node:buffer";
import { constants, publicEncrypt } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	checkPrimeAgentTracesAccess,
	loadPrimeCliConfig,
	loginPrimeAgentTraces,
} from "../src/core/prime-inference-auth.js";

function jsonResponse(body: unknown, status: number = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
		},
	});
}

function getUrl(input: string | URL | Request): string {
	if (typeof input === "string") {
		return input;
	}
	if (input instanceof URL) {
		return input.toString();
	}
	return input.url;
}

function getJsonBody(init?: RequestInit): Record<string, unknown> {
	if (typeof init?.body !== "string") {
		throw new Error(`Expected string request body, got ${typeof init?.body}`);
	}
	return JSON.parse(init.body) as Record<string, unknown>;
}

function getAuthorization(init?: RequestInit): string | undefined {
	const headers = init?.headers;
	if (!headers || Array.isArray(headers)) {
		return undefined;
	}
	if (headers instanceof Headers) {
		return headers.get("Authorization") ?? undefined;
	}
	const headerRecord = headers as Record<string, string | undefined>;
	return headerRecord.Authorization ?? headerRecord.authorization;
}

function encryptChallengeResult(publicKey: string, value: string): string {
	return publicEncrypt(
		{
			key: publicKey,
			padding: constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: "sha256",
		},
		Buffer.from(value, "utf-8"),
	).toString("base64");
}

describe("Prime Inference auth", () => {
	let tempDir: string;
	let configPath: string;
	let originalTraceBaseUrl: string | undefined;

	beforeEach(() => {
		tempDir = join(tmpdir(), `pi-prime-auth-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(tempDir, { recursive: true });
		configPath = join(tempDir, "config.json");
		originalTraceBaseUrl = process.env.PRIME_AGENT_TRACES_BASE_URL;
		delete process.env.PRIME_AGENT_TRACES_BASE_URL;
	});

	afterEach(() => {
		if (originalTraceBaseUrl === undefined) {
			delete process.env.PRIME_AGENT_TRACES_BASE_URL;
		} else {
			process.env.PRIME_AGENT_TRACES_BASE_URL = originalTraceBaseUrl;
		}
		if (existsSync(tempDir)) {
			rmSync(tempDir, { recursive: true });
		}
		vi.restoreAllMocks();
	});

	it("loads Prime CLI config with defaults", () => {
		writeFileSync(
			configPath,
			JSON.stringify({
				api_key: "prime-key",
				base_url: "https://prime-api.example/api/v1",
				frontend_url: "https://prime-app.example/",
			}),
		);

		expect(loadPrimeCliConfig(configPath)).toEqual({
			apiKey: "prime-key",
			baseUrl: "https://prime-api.example",
			frontendUrl: "https://prime-app.example",
			path: configPath,
		});
	});

	it("checks Prime Agent trace access with Prime whoami permissions", async () => {
		const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
			expect(getUrl(input)).toBe("https://prime-api.example/api/v1/user/whoami");
			expect(init?.method).toBe("GET");
			expect(getAuthorization(init)).toBe("Bearer prime-key");
			return jsonResponse({ data: { scope: { agent_traces: { read: true, write: true } } } });
		});

		await expect(
			checkPrimeAgentTracesAccess("prime-key", "https://prime-api.example", { fetchFn: fetchMock }),
		).resolves.toEqual({ ok: true });
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("validates imported Prime CLI trace credentials against the production trace API by default", async () => {
		writeFileSync(
			configPath,
			JSON.stringify({
				api_key: "prime-cli-key",
				base_url: "https://dev-api.example/api/v1",
			}),
		);
		const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
			expect(getUrl(input)).toBe("https://api.primeintellect.ai/api/v1/user/whoami");
			expect(getAuthorization(init)).toBe("Bearer prime-cli-key");
			return jsonResponse({ data: { scope: { agent_traces: { write: true } } } });
		});
		const onAuth = vi.fn();

		const result = await loginPrimeAgentTraces(
			{ onAuth },
			{ configPath, fetchFn: fetchMock, requestTimeoutMs: 1000 },
		);

		expect(result).toEqual({ apiKey: "prime-cli-key", source: "prime-cli" });
		expect(onAuth).not.toHaveBeenCalled();
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("validates imported Prime CLI trace credentials against PRIME_AGENT_TRACES_BASE_URL", async () => {
		process.env.PRIME_AGENT_TRACES_BASE_URL = "https://trace-api.example/api/v1";
		writeFileSync(
			configPath,
			JSON.stringify({
				api_key: "prime-cli-key",
				base_url: "https://dev-api.example/api/v1",
			}),
		);
		const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
			expect(getUrl(input)).toBe("https://trace-api.example/api/v1/user/whoami");
			expect(getAuthorization(init)).toBe("Bearer prime-cli-key");
			return jsonResponse({ data: { scope: { agent_traces: { write: true } } } });
		});
		const onAuth = vi.fn();

		const result = await loginPrimeAgentTraces(
			{ onAuth },
			{ configPath, fetchFn: fetchMock, requestTimeoutMs: 1000 },
		);

		expect(result).toEqual({ apiKey: "prime-cli-key", source: "prime-cli" });
		expect(onAuth).not.toHaveBeenCalled();
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it("requests agent trace scope during Prime Agent trace browser login", async () => {
		process.env.PRIME_AGENT_TRACES_BASE_URL = "https://prime-api.example/api/v1";
		writeFileSync(
			configPath,
			JSON.stringify({
				base_url: "https://prime-api.example",
				frontend_url: "https://prime-app.example",
			}),
		);
		let challengePublicKey = "";
		const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
			const url = getUrl(input);
			if (url === "https://prime-api.example/api/v1/auth_challenge/generate") {
				challengePublicKey = String(getJsonBody(init).encryptionPublicKey);
				return jsonResponse({ challenge: "challenge-code", status_auth_token: "status-token" });
			}
			if (url.startsWith("https://prime-api.example/api/v1/auth_challenge/status")) {
				expect(getAuthorization(init)).toBe("Bearer status-token");
				return jsonResponse({ result: encryptChallengeResult(challengePublicKey, "trace-key") });
			}
			if (url === "https://prime-api.example/api/v1/user/whoami") {
				expect(getAuthorization(init)).toBe("Bearer trace-key");
				return jsonResponse({ data: { scope: { agent_traces: { read: true, write: true } } } });
			}
			throw new Error(`Unexpected fetch URL: ${url}`);
		});
		const onAuth = vi.fn();

		const result = await loginPrimeAgentTraces(
			{
				onAuth,
			},
			{ configPath, fetchFn: fetchMock, pollIntervalMs: 0, requestTimeoutMs: 1000 },
		);

		expect(result).toEqual({ apiKey: "trace-key", source: "browser" });
		expect(onAuth).toHaveBeenCalledWith({
			url: "https://prime-app.example/dashboard/tokens/challenge?code=challenge-code&scope=agent_traces",
			instructions: "Code: challenge-code",
		});
	});
});
