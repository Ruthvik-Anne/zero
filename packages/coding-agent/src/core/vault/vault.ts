import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { getAgentDir } from "../../config.js";

/**
 * Native per-project credential vault (task #78) — a local, passwordless
 * secret store for the "credential" ask_user variant. The model never sees
 * plaintext: it only ever gets back an opaque `zero-cred://<name>/<hex>`
 * placeholder token, which the tool-definition-wrapper choke point resolves
 * to the real secret immediately before a bash/ipython tool call executes
 * (see tool-definition-wrapper.ts), strictly *after* the harm-check has
 * already scanned the placeholder-only text.
 *
 * Storage: one AES-256-GCM-encrypted vault.json per project, at
 * `<projectRoot>/.zero/vault/vault.json` — the same project-local `.zero/`
 * layout git-worktree.ts already uses (`.zero/worktrees/<id>`), gitignored
 * wholesale by the repo's own `.gitignore`.
 *
 * Encryption key: 32 cryptographically random bytes, generated on first use
 * and persisted at `~/.zero/agent/vault-keys/<sha256-hex-of-realpath>.key`
 * (under the real global agent dir, `getAgentDir()` — NOT a hardcoded path),
 * keyed by the project's realpath so distinct checkouts of the same repo (or
 * the same path reached via a symlink) can't accidentally collide or diverge.
 * "Passwordless" is a hard requirement: this key is never derived from
 * anything the user has to remember or type.
 */

const VAULT_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const VAULT_DIR_NAME = ".zero";

export const CREDENTIAL_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

export function isValidCredentialName(name: string): boolean {
	return typeof name === "string" && CREDENTIAL_NAME_PATTERN.test(name);
}

/** `zero-cred://<name>/<24-hex-chars>` — the opaque placeholder returned to the model. */
export const VAULT_TOKEN_PREFIX = "zero-cred://";
const VAULT_TOKEN_PATTERN = /zero-cred:\/\/([a-zA-Z0-9_-]{1,64})\/([0-9a-f]{24})/g;

interface VaultEntry {
	iv: string;
	authTag: string;
	ciphertext: string;
	createdAt: string;
}

interface VaultFile {
	version: 1;
	entries: Record<string, VaultEntry>;
}

function vaultFilePath(projectRoot: string): string {
	return join(projectRoot, VAULT_DIR_NAME, "vault", "vault.json");
}

function safeRealpath(path: string): string {
	try {
		return realpathSync(path);
	} catch {
		// The project root may not exist yet in narrow test/edge scenarios;
		// fall back to a resolved (but not symlink-canonicalized) path rather
		// than crashing key derivation.
		return resolve(path);
	}
}

function vaultKeyPath(projectRoot: string): string {
	const hash = createHash("sha256").update(safeRealpath(projectRoot)).digest("hex");
	return join(getAgentDir(), "vault-keys", `${hash}.key`);
}

/** Write-temp-then-rename, matching auth-storage.ts/settings-manager.ts/checkpoint.ts's own atomic-write convention. */
function writeFileAtomic(path: string, content: string | Buffer, mode: number): void {
	mkdirSync(dirname(path), { recursive: true });
	const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
	try {
		writeFileSync(temporaryPath, content, { mode });
		renameSync(temporaryPath, path);
	} finally {
		try {
			unlinkSync(temporaryPath);
		} catch {
			// The rename succeeded, or the temp file was never created.
		}
	}
}

function getOrCreateMachineKey(projectRoot: string): Buffer {
	const keyPath = vaultKeyPath(projectRoot);
	if (existsSync(keyPath)) {
		return readFileSync(keyPath);
	}
	const key = randomBytes(VAULT_KEY_BYTES);
	writeFileAtomic(keyPath, key, 0o600);
	return key;
}

function readVaultFile(path: string): VaultFile {
	if (!existsSync(path)) {
		return { version: 1, entries: {} };
	}
	const raw = readFileSync(path, "utf-8");
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		throw new Error(`vault file at ${path} is corrupted (invalid JSON): ${(error as Error).message}`);
	}
	const entries = (parsed as Partial<VaultFile> | null)?.entries;
	if (!parsed || typeof parsed !== "object" || !entries || typeof entries !== "object") {
		throw new Error(`vault file at ${path} has an unexpected shape`);
	}
	return { version: 1, entries: entries as Record<string, VaultEntry> };
}

function writeVaultFile(path: string, file: VaultFile): void {
	writeFileAtomic(path, JSON.stringify(file), 0o600);
}

/** Encrypt `plaintext` with AES-256-GCM and store it under `name` in this project's vault. */
export async function storeCredential(projectRoot: string, name: string, plaintext: string): Promise<void> {
	if (!isValidCredentialName(name)) {
		throw new Error(`invalid credential name: ${JSON.stringify(name)}`);
	}
	const key = getOrCreateMachineKey(projectRoot);
	const iv = randomBytes(GCM_IV_BYTES);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
	const authTag = cipher.getAuthTag();

	const path = vaultFilePath(projectRoot);
	const file = readVaultFile(path);
	file.entries[name] = {
		iv: iv.toString("base64"),
		authTag: authTag.toString("base64"),
		ciphertext: ciphertext.toString("base64"),
		createdAt: new Date().toISOString(),
	};
	writeVaultFile(path, file);
}

/**
 * Decrypt and return the credential stored under `name`, or `undefined` if it
 * doesn't exist, the vault key is wrong, or the ciphertext has been tampered
 * with (GCM auth-tag verification fails). Never throws on a bad decrypt —
 * fails closed instead of leaking why.
 *
 * ONLY ever call this from the host-side substitution point (tool-definition-
 * wrapper.ts); never from anywhere that could relay the result to the model.
 */
export async function getCredential(projectRoot: string, name: string): Promise<string | undefined> {
	if (!isValidCredentialName(name)) return undefined;
	const path = vaultFilePath(projectRoot);
	if (!existsSync(path)) return undefined;
	let entry: VaultEntry | undefined;
	try {
		entry = readVaultFile(path).entries[name];
	} catch {
		return undefined;
	}
	if (!entry) return undefined;
	try {
		const key = getOrCreateMachineKey(projectRoot);
		const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(entry.iv, "base64"));
		decipher.setAuthTag(Buffer.from(entry.authTag, "base64"));
		const plaintext = Buffer.concat([decipher.update(Buffer.from(entry.ciphertext, "base64")), decipher.final()]);
		return plaintext.toString("utf-8");
	} catch {
		return undefined;
	}
}

/**
 * Names only — never values or tokens. Backs the `vault.list` host request.
 * Mirrors `getCredential`'s fail-closed rationale: a corrupted/malformed
 * vault file must never propagate a path-bearing exception out to the model
 * via the host-request error response — treat any read failure as "no
 * credentials" instead.
 */
export async function listCredentialNames(projectRoot: string): Promise<string[]> {
	const path = vaultFilePath(projectRoot);
	if (!existsSync(path)) return [];
	try {
		return Object.keys(readVaultFile(path).entries);
	} catch {
		return [];
	}
}

/**
 * Session-scoped (in-memory, never persisted) registry of placeholder tokens
 * this session has actually issued. Defends against the model fabricating or
 * guessing a `zero-cred://<name>/<hex>` string: a token only resolves to real
 * secret material if it was issued for that exact name in this session.
 */
export class VaultTokenRegistry {
	private issued = new Map<string, Set<string>>();

	/** Issue a fresh opaque token for `name` and remember it as valid. */
	issue(name: string): string {
		if (!isValidCredentialName(name)) {
			throw new Error(`invalid credential name: ${JSON.stringify(name)}`);
		}
		const suffix = randomBytes(12).toString("hex");
		const suffixes = this.issued.get(name);
		if (suffixes) {
			suffixes.add(suffix);
			// Re-issuing for an existing name means it's actively still being used —
			// move it to the end of Map iteration order (delete-then-set; a plain
			// `.set()` on an existing key does NOT change its position) so
			// `issuedNames()` genuinely reflects recency, not just first-ever-issuance.
			this.issued.delete(name);
			this.issued.set(name, suffixes);
		} else {
			this.issued.set(name, new Set([suffix]));
		}
		return `${VAULT_TOKEN_PREFIX}${name}/${suffix}`;
	}

	/** Was this exact name/suffix pair actually issued by this registry? */
	isValid(name: string, suffix: string): boolean {
		return this.issued.get(name)?.has(suffix) ?? false;
	}

	/**
	 * Every credential name this session has issued at least one token for, in
	 * least-to-most-recently-issued order (re-issuing a token for an existing
	 * name moves it to the end — see `issue()`). Used by `scrubKnownSecrets`
	 * and `getActiveCredentialValues` to know which plaintexts to check/return
	 * — never exposes the tokens/suffixes themselves.
	 */
	issuedNames(): string[] {
		return [...this.issued.keys()];
	}

	/**
	 * Some placeholder token previously issued for `name` (the earliest one),
	 * or `undefined` if none was ever issued. Every token issued for the same
	 * name resolves to the same plaintext, so any of them is an interchangeable
	 * substitute when scrubbing a decrypted value back out of outbound text.
	 */
	representativeToken(name: string): string | undefined {
		const suffix = this.issued.get(name)?.values().next().value;
		return suffix === undefined ? undefined : `${VAULT_TOKEN_PREFIX}${name}/${suffix}`;
	}
}

/** (task #84) Bound on how many distinct active credentials one `scrubKnownSecrets` call checks outbound text against. A session realistically holds a handful of live credentials at once, so this never matters in practice — it exists purely to keep worst-case cost proportional rather than unbounded if a session somehow issued an unusually large number of tokens. */
export const SCRUB_MAX_ACTIVE_CREDENTIALS = 32;

/** (task #84) Bound on how much of `text` one `scrubKnownSecrets` call scans, in the same spirit as the ~50KB tool-output truncation convention (`DEFAULT_MAX_BYTES` in `core/tools/truncate.ts`). Anything beyond this leading prefix is left unscanned — and therefore unscrubbed — rather than the call growing unbounded for a pathologically large output. This is a deliberate, documented gap: a secret echoed back only past this prefix will not be caught. */
export const SCRUB_MAX_TEXT_CHARS = 50 * 1024;

/**
 * The credential names this session's currently active tokens cover, capped
 * at `SCRUB_MAX_ACTIVE_CREDENTIALS` and kept to the MOST recently issued
 * names when over the cap (the credential just used is the one most likely
 * to matter). Single source of truth for "which names count as active" —
 * shared by `scrubKnownSecrets` and `getActiveCredentialValues` so the two
 * never diverge on the cap/recency logic.
 */
function activeCredentialNames(registry: VaultTokenRegistry): string[] {
	return registry.issuedNames().slice(-SCRUB_MAX_ACTIVE_CREDENTIALS);
}

/**
 * (finding #1, task #78/#84 follow-up) Decrypted plaintexts for every
 * credential name currently issued in `registry`, capped/ordered by
 * `activeCredentialNames`. This is "what this session's currently active
 * secret values are" — used to keep resolved credentials out of the kernel
 * state snapshot (`state-snapshot.ts`'s `buildSnapshotCode` exclusion list).
 * Deduplicated and empty values filtered out, since either would otherwise
 * either bloat the exclusion list or (for an empty string) match every
 * variable as a false positive.
 */
export async function getActiveCredentialValues(registry: VaultTokenRegistry, projectRoot: string): Promise<string[]> {
	const names = activeCredentialNames(registry);
	const values = new Set<string>();
	for (const name of names) {
		const plaintext = await getCredential(projectRoot, name);
		if (plaintext) values.add(plaintext);
	}
	return [...values];
}

/**
 * Best-effort output scrubber (task #84) — the mirror image of
 * `resolveVaultPlaceholders` above. That function turns a placeholder into
 * its real secret immediately before execution; this one runs the
 * substitution in reverse over OUTBOUND text (tool results, rlm.run
 * payloads), so a secret that gets echoed back out — command output that
 * reflects a submitted value, an f-string a live kernel evaluates using a
 * variable it already decrypted earlier in the session, etc — is caught and
 * replaced with its placeholder token before that text is persisted to a
 * transcript/audit log or forwarded into a child session's prompt.
 *
 * **Known limitation, by design**: this is exact-substring matching only. It
 * cannot catch a secret that has been transformed in any way before being
 * echoed back — base64/hex-encoded, reversed, split across multiple writes,
 * upper/lower-cased, whitespace-mangled, etc. Treat this as a best-effort
 * safety net for the common "accidentally printed the raw value" case, not a
 * guarantee. See `skills/vault/SKILL.md` for the user-facing version of this
 * caveat.
 */
export async function scrubKnownSecrets(
	text: string,
	registry: VaultTokenRegistry,
	projectRoot: string,
): Promise<string> {
	if (!text) return text;
	const names = activeCredentialNames(registry);
	if (names.length === 0) return text;

	const scanLength = Math.min(text.length, SCRUB_MAX_TEXT_CHARS);
	const scanned = text.slice(0, scanLength);
	const rest = text.slice(scanLength);

	let scrubbed = scanned;
	for (const name of names) {
		if (!scrubbed) break;
		// Decrypt on demand and discard immediately after this substring check —
		// never retained beyond this loop iteration.
		const plaintext = await getCredential(projectRoot, name);
		if (!plaintext || !scrubbed.includes(plaintext)) continue;
		const token = registry.representativeToken(name);
		if (!token) continue;
		scrubbed = scrubbed.split(plaintext).join(token);
	}
	return scrubbed + rest;
}

/**
 * Replace every `zero-cred://<name>/<hex>` occurrence in `text` that was
 * actually issued (per `registry`) with its decrypted plaintext from this
 * project's vault. Any occurrence that wasn't issued this session — fabricated,
 * mismatched, or a stale token from a different session — is left as literal
 * text, so it fails naturally as garbage input rather than being treated as an
 * excuse to substitute an unrelated real secret.
 */
export async function resolveVaultPlaceholders(
	text: string,
	projectRoot: string,
	registry: VaultTokenRegistry,
): Promise<string> {
	if (!text.includes(VAULT_TOKEN_PREFIX)) return text;
	let result = "";
	let lastIndex = 0;
	for (const match of text.matchAll(VAULT_TOKEN_PATTERN)) {
		const full = match[0];
		const name = match[1];
		const suffix = match[2];
		const index = match.index ?? 0;
		result += text.slice(lastIndex, index);
		if (name !== undefined && suffix !== undefined && registry.isValid(name, suffix)) {
			const plaintext = await getCredential(projectRoot, name);
			result += plaintext !== undefined ? plaintext : full;
		} else {
			result += full;
		}
		lastIndex = index + full.length;
	}
	result += text.slice(lastIndex);
	return result;
}
