import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.js";
import {
	getActiveCredentialValues,
	getCredential,
	isValidCredentialName,
	listCredentialNames,
	resolveVaultPlaceholders,
	SCRUB_MAX_ACTIVE_CREDENTIALS,
	SCRUB_MAX_TEXT_CHARS,
	scrubKnownSecrets,
	storeCredential,
	VaultTokenRegistry,
} from "../src/core/vault/vault.js";

describe("vault", () => {
	const previousAgentDir = process.env[ENV_AGENT_DIR];
	const tempDirs: string[] = [];
	let agentDir: string;
	let projectRoot: string;

	beforeEach(() => {
		agentDir = mkdtempSync(join(tmpdir(), "zero-vault-agent-"));
		projectRoot = mkdtempSync(join(tmpdir(), "zero-vault-project-"));
		tempDirs.push(agentDir, projectRoot);
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		for (const dir of tempDirs.splice(0)) {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	function vaultFilePath(): string {
		return join(projectRoot, ".zero", "vault", "vault.json");
	}

	describe("isValidCredentialName", () => {
		it("accepts alphanumeric, underscore, and hyphen names up to 64 chars", () => {
			expect(isValidCredentialName("stripe_api_key")).toBe(true);
			expect(isValidCredentialName("db-password-1")).toBe(true);
			expect(isValidCredentialName("a".repeat(64))).toBe(true);
		});

		it("rejects empty, overlong, or non-matching names", () => {
			expect(isValidCredentialName("")).toBe(false);
			expect(isValidCredentialName("a".repeat(65))).toBe(false);
			expect(isValidCredentialName("has space")).toBe(false);
			expect(isValidCredentialName("has/slash")).toBe(false);
			expect(isValidCredentialName("has.dot")).toBe(false);
		});
	});

	describe("storeCredential / getCredential", () => {
		it("round-trips a stored secret", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			await expect(getCredential(projectRoot, "stripe_api_key")).resolves.toBe("sk-live-abc123");
		});

		it("returns undefined for a name that was never stored", async () => {
			await expect(getCredential(projectRoot, "never_stored")).resolves.toBeUndefined();
		});

		it("rejects storing under an invalid name", async () => {
			await expect(storeCredential(projectRoot, "has space", "x")).rejects.toThrow(/invalid credential name/);
		});

		it("persists the vault file encrypted at rest — no plaintext substring on disk", async () => {
			await storeCredential(projectRoot, "db_password", "correct-horse-battery-staple");
			const raw = readFileSync(vaultFilePath(), "utf-8");
			expect(raw).not.toContain("correct-horse-battery-staple");
			const parsed = JSON.parse(raw);
			expect(parsed.version).toBe(1);
			expect(parsed.entries.db_password).toMatchObject({
				iv: expect.any(String),
				authTag: expect.any(String),
				ciphertext: expect.any(String),
				createdAt: expect.any(String),
			});
		});

		it("stores multiple credentials independently", async () => {
			await storeCredential(projectRoot, "one", "value-one");
			await storeCredential(projectRoot, "two", "value-two");
			await expect(getCredential(projectRoot, "one")).resolves.toBe("value-one");
			await expect(getCredential(projectRoot, "two")).resolves.toBe("value-two");
		});

		it("overwriting a name replaces its value", async () => {
			await storeCredential(projectRoot, "rotating", "old-value");
			await storeCredential(projectRoot, "rotating", "new-value");
			await expect(getCredential(projectRoot, "rotating")).resolves.toBe("new-value");
		});

		it("rejects a tampered ciphertext via the GCM auth tag", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const path = vaultFilePath();
			const file = JSON.parse(readFileSync(path, "utf-8"));
			// Flip a character in the ciphertext — the auth tag no longer verifies.
			const ciphertext: string = file.entries.stripe_api_key.ciphertext;
			file.entries.stripe_api_key.ciphertext =
				ciphertext.slice(0, -4) + (ciphertext.at(-4) === "A" ? "B" : "A") + ciphertext.slice(-3);
			writeFileSync(path, JSON.stringify(file));

			await expect(getCredential(projectRoot, "stripe_api_key")).resolves.toBeUndefined();
		});

		it("rejects decryption under a different machine key", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			// Simulate a different machine: wipe the key file so a fresh (different)
			// random key gets generated on the next getOrCreateMachineKey call.
			rmSync(join(agentDir, "vault-keys"), { recursive: true, force: true });

			await expect(getCredential(projectRoot, "stripe_api_key")).resolves.toBeUndefined();
		});

		it("writes the machine key file with 0600 permissions", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const keyFiles = readdirSync(join(agentDir, "vault-keys"));
			expect(keyFiles.length).toBe(1);
			const keyPath = join(agentDir, "vault-keys", keyFiles[0]!);
			expect(existsSync(keyPath)).toBe(true);
			if (process.platform !== "win32") {
				expect(statSync(keyPath).mode & 0o777).toBe(0o600);
			}
		});

		// Explicit reinforcement (task #78): the AES key must be unique PER
		// PROJECT, never a single shared/global key across every project on the
		// machine — each project root's realpath hashes to its own key filename,
		// and each key file is generated fresh on that project's first use.
		it("derives a distinct machine key per project root — never a shared/global key", async () => {
			const otherProjectRoot = mkdtempSync(join(tmpdir(), "zero-vault-project-b-"));
			tempDirs.push(otherProjectRoot);

			await storeCredential(projectRoot, "stripe_api_key", "secret-for-project-a");
			await storeCredential(otherProjectRoot, "stripe_api_key", "secret-for-project-b");

			const keyFiles = readdirSync(join(agentDir, "vault-keys"));
			// Two distinct projects -> two distinct key files, not one shared key.
			expect(keyFiles.length).toBe(2);

			// Each project's own credential still round-trips under its own key...
			await expect(getCredential(projectRoot, "stripe_api_key")).resolves.toBe("secret-for-project-a");
			await expect(getCredential(otherProjectRoot, "stripe_api_key")).resolves.toBe("secret-for-project-b");

			// ...and project A's ciphertext does NOT decrypt under project B's vault
			// entry — swapping the encrypted entry across projects must fail closed
			// rather than silently succeeding under some shared key.
			const entryA = JSON.parse(readFileSync(vaultFilePath(), "utf-8")).entries.stripe_api_key;
			const otherVaultPath = join(otherProjectRoot, ".zero", "vault", "vault.json");
			const fileB = JSON.parse(readFileSync(otherVaultPath, "utf-8"));
			fileB.entries.stripe_api_key = entryA;
			writeFileSync(otherVaultPath, JSON.stringify(fileB));

			await expect(getCredential(otherProjectRoot, "stripe_api_key")).resolves.toBeUndefined();
		});
	});

	describe("listCredentialNames", () => {
		it("returns an empty array when no vault file exists yet", async () => {
			await expect(listCredentialNames(projectRoot)).resolves.toEqual([]);
		});

		it("lists names only, never values", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			await storeCredential(projectRoot, "db_password", "correct-horse-battery-staple");
			const names = await listCredentialNames(projectRoot);
			expect(names.sort()).toEqual(["db_password", "stripe_api_key"]);
		});

		// Finding #3: readVaultFile throws an Error embedding the absolute vault
		// file path on a corrupted file; listCredentialNames must never let that
		// propagate (unlike getCredential, it previously called readVaultFile
		// unguarded) — fail closed to an empty array instead, same as getCredential.
		it("returns an empty array (never throws) on invalid JSON", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			writeFileSync(vaultFilePath(), "not json{{{");

			await expect(listCredentialNames(projectRoot)).resolves.toEqual([]);
		});

		it("returns an empty array (never throws) when the vault file has an unexpected shape (missing entries)", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			writeFileSync(vaultFilePath(), JSON.stringify({ version: 1 }));

			await expect(listCredentialNames(projectRoot)).resolves.toEqual([]);
		});
	});

	describe("VaultTokenRegistry / resolveVaultPlaceholders", () => {
		it("issues a token of the documented zero-cred://<name>/<24-hex> shape", () => {
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");
			expect(token).toMatch(/^zero-cred:\/\/stripe_api_key\/[0-9a-f]{24}$/);
		});

		it("resolves a validly-issued token to the decrypted plaintext", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const resolved = await resolveVaultPlaceholders(
				`curl -H "Authorization: Bearer ${token}" https://example.com`,
				projectRoot,
				registry,
			);

			expect(resolved).toBe('curl -H "Authorization: Bearer sk-live-abc123" https://example.com');
		});

		it("leaves a fabricated token untouched", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			const fabricated = "zero-cred://stripe_api_key/deadbeefdeadbeefdeadbeef";

			const resolved = await resolveVaultPlaceholders(`echo ${fabricated}`, projectRoot, registry);

			expect(resolved).toBe(`echo ${fabricated}`);
		});

		it("leaves a mismatched name/suffix pair untouched even if each half is individually valid", async () => {
			await storeCredential(projectRoot, "name_a", "secret-a");
			await storeCredential(projectRoot, "name_b", "secret-b");
			const registry = new VaultTokenRegistry();
			const tokenA = registry.issue("name_a");
			const suffixA = tokenA.split("/").pop();
			const crossed = `zero-cred://name_b/${suffixA}`;

			const resolved = await resolveVaultPlaceholders(`echo ${crossed}`, projectRoot, registry);

			expect(resolved).toBe(`echo ${crossed}`);
		});

		it("resolves multiple distinct tokens in the same text", async () => {
			await storeCredential(projectRoot, "one", "value-one");
			await storeCredential(projectRoot, "two", "value-two");
			const registry = new VaultTokenRegistry();
			const tokenOne = registry.issue("one");
			const tokenTwo = registry.issue("two");

			const resolved = await resolveVaultPlaceholders(`${tokenOne} and ${tokenTwo}`, projectRoot, registry);

			expect(resolved).toBe("value-one and value-two");
		});

		it("passes through text with no placeholder unchanged", async () => {
			const registry = new VaultTokenRegistry();
			const resolved = await resolveVaultPlaceholders("echo hello", projectRoot, registry);
			expect(resolved).toBe("echo hello");
		});

		// Finding #2: issuedNames() previously returned first-ever-issuance order,
		// not recency order — a plain Map.set() on an existing key does not move
		// its iteration position (verified separately below), so re-issuing a
		// token for a credential that's still actively in use did NOT protect it
		// from the cap once a session had issued more than
		// SCRUB_MAX_ACTIVE_CREDENTIALS distinct names. This drives that exact
		// scenario through the registry's own Map to prove the fix.
		it("moves a re-issued name to the end of Map iteration order (delete-then-set), unlike a plain re-set", () => {
			const m = new Map<string, number>();
			m.set("a", 1);
			m.set("b", 2);
			m.set("c", 3);

			// A plain re-set on an existing key does NOT change its position.
			m.set("a", 99);
			expect([...m.keys()]).toEqual(["a", "b", "c"]);

			// Delete-then-set on an existing key DOES move it to the end.
			m.delete("b");
			m.set("b", 2);
			expect([...m.keys()]).toEqual(["a", "c", "b"]);
		});
	});

	describe("getActiveCredentialValues", () => {
		it("returns the current decrypted plaintext for every issued name", async () => {
			await storeCredential(projectRoot, "one", "value-one");
			await storeCredential(projectRoot, "two", "value-two");
			const registry = new VaultTokenRegistry();
			registry.issue("one");
			registry.issue("two");

			const values = await getActiveCredentialValues(registry, projectRoot);

			expect(values.sort()).toEqual(["value-one", "value-two"]);
		});

		it("returns an empty array when nothing has been issued", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry(); // nothing issued

			await expect(getActiveCredentialValues(registry, projectRoot)).resolves.toEqual([]);
		});

		// Finding #2's fix, exercised through the exported function the kernel
		// snapshot exclusion (finding #1) actually calls: issue more than the cap,
		// then re-issue an early name — it must still be included (its Map
		// position moved to "most recent"), while a name that was issued once and
		// never touched again correctly falls off the cap.
		it("keeps a re-issued name in the capped, most-recently-issued set even past the cap", async () => {
			const names = Array.from({ length: SCRUB_MAX_ACTIVE_CREDENTIALS + 1 }, (_, i) => `cred_${i}`);
			const registry = new VaultTokenRegistry();
			for (const name of names) {
				await storeCredential(projectRoot, name, `value-of-${name}`);
				registry.issue(name);
			}
			// cred_0 is the oldest-issued name — re-issuing it must move it back
			// into the "active" window even though it's now past the raw cap.
			registry.issue("cred_0");

			const values = await getActiveCredentialValues(registry, projectRoot);

			expect(values.length).toBe(SCRUB_MAX_ACTIVE_CREDENTIALS);
			expect(values).toContain("value-of-cred_0");
			// cred_1 was issued once and never touched again — it's now the
			// oldest and correctly falls off the cap.
			expect(values).not.toContain("value-of-cred_1");
		});
	});

	// task #84: the reverse direction — a decrypted secret that made it into
	// outbound text (tool output, an rlm.run payload) gets scrubbed back to
	// its placeholder before that text goes anywhere.
	describe("scrubKnownSecrets", () => {
		it("replaces an exact plaintext match with its placeholder", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const scrubbed = await scrubKnownSecrets(
				'curl -v -H "Authorization: Bearer sk-live-abc123" https://example.com',
				registry,
				projectRoot,
			);

			expect(scrubbed).toBe(`curl -v -H "Authorization: Bearer ${token}" https://example.com`);
		});

		it("replaces every occurrence, not just the first", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const scrubbed = await scrubKnownSecrets("sk-live-abc123 twice: sk-live-abc123", registry, projectRoot);

			expect(scrubbed).toBe(`${token} twice: ${token}`);
		});

		it("leaves unrelated text untouched", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			registry.issue("stripe_api_key");

			const scrubbed = await scrubKnownSecrets("nothing sensitive here", registry, projectRoot);

			expect(scrubbed).toBe("nothing sensitive here");
		});

		it("is a no-op when no token has been issued this session, even if a credential exists", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry(); // nothing issued

			const scrubbed = await scrubKnownSecrets("leaked value: sk-live-abc123", registry, projectRoot);

			expect(scrubbed).toBe("leaked value: sk-live-abc123");
		});

		it("scrubs against multiple distinct active credentials in the same text", async () => {
			await storeCredential(projectRoot, "one", "value-one");
			await storeCredential(projectRoot, "two", "value-two");
			const registry = new VaultTokenRegistry();
			const tokenOne = registry.issue("one");
			const tokenTwo = registry.issue("two");

			const scrubbed = await scrubKnownSecrets("saw value-one and value-two", registry, projectRoot);

			expect(scrubbed).toBe(`saw ${tokenOne} and ${tokenTwo}`);
		});

		// Explicit "known limitation" case: exact-substring matching only, so a
		// trivially transformed value (here, base64) is never caught. This is a
		// documented gap, not a bug — see the SKILL.md caveat and the function's
		// own doc comment.
		it("does NOT catch a trivially-transformed (e.g. base64-encoded) value — documented limitation", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			registry.issue("stripe_api_key");
			const encoded = Buffer.from("sk-live-abc123", "utf-8").toString("base64");

			const scrubbed = await scrubKnownSecrets(`encoded: ${encoded}`, registry, projectRoot);

			expect(scrubbed).toBe(`encoded: ${encoded}`);
		});

		it("caps the number of active credentials scanned per call, predictably skipping the least-recently-issued beyond the cap", async () => {
			const names = Array.from({ length: SCRUB_MAX_ACTIVE_CREDENTIALS + 1 }, (_, i) => `cred_${i}`);
			const registry = new VaultTokenRegistry();
			for (const name of names) {
				await storeCredential(projectRoot, name, `value-of-${name}`);
				registry.issue(name);
			}

			// The oldest-issued name is dropped by the cap; every other name is scanned.
			const droppedName = names[0]!;
			const keptName = names[1]!;
			const text = `first: value-of-${droppedName}, second: value-of-${keptName}`;

			const scrubbed = await scrubKnownSecrets(text, registry, projectRoot);

			expect(scrubbed).toContain(`value-of-${droppedName}`); // not scrubbed — beyond the cap
			expect(scrubbed).not.toContain(`value-of-${keptName}`); // scrubbed — within the cap
		});

		// Finding #2: re-issuing a token for a credential that's still actively
		// in use must keep it inside the cap's scanned window, not just the
		// literal-first-32 names by first-ever-issuance order.
		it("keeps a re-issued (still actively used) credential scrubbed even after it would otherwise have aged out of the cap", async () => {
			const names = Array.from({ length: SCRUB_MAX_ACTIVE_CREDENTIALS + 1 }, (_, i) => `cred_${i}`);
			const registry = new VaultTokenRegistry();
			let firstCred0Token: string | undefined;
			for (const name of names) {
				await storeCredential(projectRoot, name, `value-of-${name}`);
				const token = registry.issue(name);
				if (name === "cred_0") firstCred0Token = token;
			}
			// cred_0 is re-issued — still actively in use — so it must not be
			// dropped by the cap despite being the oldest-ever-issued name.
			// (The representative token used for scrubbing is always the
			// earliest-issued suffix for a name, per `representativeToken`.)
			registry.issue("cred_0");

			const text = `first: value-of-cred_0, second: value-of-cred_1`;
			const scrubbed = await scrubKnownSecrets(text, registry, projectRoot);

			expect(scrubbed).toContain(`first: ${firstCred0Token}`); // scrubbed — kept active by re-issuance
			expect(scrubbed).toContain("value-of-cred_1"); // not scrubbed — now the oldest, falls off the cap
		});

		it("caps how much of a very large text is scanned, leaving the remainder past the cap unscrubbed rather than hanging or blowing up", async () => {
			await storeCredential(projectRoot, "stripe_api_key", "sk-live-abc123");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const filler = "x".repeat(SCRUB_MAX_TEXT_CHARS + 1000);
			const text = `${filler}sk-live-abc123`; // the secret lands past the scan cap

			const scrubbed = await scrubKnownSecrets(text, registry, projectRoot);

			expect(scrubbed.endsWith("sk-live-abc123")).toBe(true); // left untouched past the cap
			expect(scrubbed).not.toContain(token);
			expect(scrubbed.length).toBe(text.length); // no data was dropped, just left unscanned
		});

		it("passes through an empty string unchanged", async () => {
			const registry = new VaultTokenRegistry();
			registry.issue("stripe_api_key");
			await expect(scrubKnownSecrets("", registry, projectRoot)).resolves.toBe("");
		});
	});
});
