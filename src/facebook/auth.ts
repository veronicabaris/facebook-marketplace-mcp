import crypto from "node:crypto";
import { execSync, execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { DatabaseSync } from "node:sqlite";
import type { FacebookCookie } from "./types.js";

// =============================================================================
//  macOS Chrome cookie decryption (original implementation)
//  Key: PBKDF2(Keychain "Chrome Safe Storage" password), AES-128-CBC.
// =============================================================================

const MAC_SALT = "saltysalt";
const MAC_ITERATIONS = 1003;
const MAC_KEY_LENGTH = 16;
const MAC_IV = Buffer.alloc(16, " ");

function macGetChromePassword(): string {
  try {
    return execSync(
      'security find-generic-password -w -s "Chrome Safe Storage" -a "Chrome"',
      { stdio: ["pipe", "pipe", "pipe"] }
    )
      .toString()
      .trim();
  } catch {
    throw new Error(
      "Failed to get Chrome password from Keychain. " +
        "Make sure Chrome is installed and you approve the Keychain prompt."
    );
  }
}

function macDeriveKey(password: string): Buffer {
  return crypto.pbkdf2Sync(
    password,
    MAC_SALT,
    MAC_ITERATIONS,
    MAC_KEY_LENGTH,
    "sha1"
  );
}

function macDecrypt(encrypted: Buffer, key: Buffer): string {
  if (encrypted.length === 0) return "";
  const prefix = encrypted.subarray(0, 3).toString("ascii");
  if (prefix !== "v10") return encrypted.toString("utf8");

  const data = encrypted.subarray(3);
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, MAC_IV);
  decipher.setAutoPadding(false);
  let decoded = Buffer.concat([decipher.update(data), decipher.final()]);

  const padding = decoded[decoded.length - 1];
  if (padding && padding > 0 && padding <= 16) {
    decoded = decoded.subarray(0, decoded.length - padding);
  }
  // Chrome prepends a 32-byte SHA256 domain hash to the plaintext.
  if (decoded.length > 32) decoded = decoded.subarray(32);
  return decoded.toString("utf8");
}

function macCookieDbPath(profile: string): string {
  return path.join(
    os.homedir(),
    "Library/Application Support/Google/Chrome",
    profile,
    "Cookies"
  );
}

// =============================================================================
//  Windows Chrome cookie decryption
//  Key: DPAPI-unprotected os_crypt.encrypted_key from Local State, AES-256-GCM.
//  Cookie value layout for v10/v20: [3-byte prefix][12-byte IV][ciphertext][16-byte tag].
// =============================================================================

function winUserDataDir(): string {
  const localAppData =
    process.env.LOCALAPPDATA ??
    path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "Google", "Chrome", "User Data");
}

// DPAPI CryptUnprotectData (CurrentUser scope) via a short PowerShell shim.
// We pass the ciphertext as base64 on the command line and read base64 back on
// stdout, so no secret is ever written to disk.
function winDpapiUnprotect(protectedBlob: Buffer): Buffer {
  const b64 = protectedBlob.toString("base64");
  const script = [
    "Add-Type -AssemblyName System.Security;",
    `$enc = [Convert]::FromBase64String('${b64}');`,
    "$dec = [System.Security.Cryptography.ProtectedData]::Unprotect(" +
      "$enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser);",
    "[Convert]::ToBase64String($dec)",
  ].join(" ");

  let out: string;
  try {
    out = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { stdio: ["pipe", "pipe", "pipe"] }
    ).toString();
  } catch (err) {
    throw new Error(
      "DPAPI unprotect failed. The Chrome master key can only be decrypted by " +
        "the same Windows user that Chrome runs as. Underlying error: " +
        (err instanceof Error ? err.message : String(err))
    );
  }
  return Buffer.from(out.trim(), "base64");
}

function winGetMasterKey(userDataDir: string): Buffer {
  const localStatePath = path.join(userDataDir, "Local State");
  let raw: string;
  try {
    raw = fs.readFileSync(localStatePath, "utf8");
  } catch {
    throw new Error(`Failed to read Chrome Local State at ${localStatePath}`);
  }

  let encryptedKeyB64: string | undefined;
  try {
    encryptedKeyB64 = JSON.parse(raw)?.os_crypt?.encrypted_key;
  } catch {
    throw new Error("Local State is not valid JSON — cannot read os_crypt key.");
  }
  if (!encryptedKeyB64) {
    throw new Error("os_crypt.encrypted_key missing from Local State.");
  }

  const encryptedKey = Buffer.from(encryptedKeyB64, "base64");
  // The key is prefixed with the ASCII tag "DPAPI" (5 bytes) before the blob.
  const tag = encryptedKey.subarray(0, 5).toString("ascii");
  const blob = tag === "DPAPI" ? encryptedKey.subarray(5) : encryptedKey;
  return winDpapiUnprotect(blob);
}

function winDecrypt(encrypted: Buffer, key: Buffer): string {
  if (encrypted.length === 0) return "";

  const prefix = encrypted.subarray(0, 3).toString("ascii");
  // Older Chrome stored some values DPAPI-encrypted with no version tag.
  if (prefix !== "v10" && prefix !== "v20") {
    if (encrypted[0] === 0x01 && encrypted[1] === 0x00) {
      // Legacy raw DPAPI blob.
      return winDpapiUnprotect(encrypted).toString("utf8");
    }
    return encrypted.toString("utf8");
  }

  const iv = encrypted.subarray(3, 15);
  const tag = encrypted.subarray(encrypted.length - 16);
  const ciphertext = encrypted.subarray(15, encrypted.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decoded: Buffer;
  try {
    decoded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // v20 = app-bound encryption (Chrome 127+). The DPAPI-derived key cannot
    // open these; they need Chrome's app-bound service key. Surface a clear
    // hint rather than a bare GCM auth failure.
    if (prefix === "v20") {
      throw new Error(
        "APP_BOUND_V20: cookie uses Chrome app-bound encryption, which the " +
          "user-DPAPI key cannot decrypt. Use a Chrome profile/version whose " +
          "cookies are still v10, or run Chrome with app-bound encryption disabled."
      );
    }
    throw err;
  }

  // v20 plaintext carries a 32-byte header before the real value; v10 does not.
  if (prefix === "v20" && decoded.length > 32) decoded = decoded.subarray(32);
  return decoded.toString("utf8");
}

function winCookieDbPath(userDataDir: string, profile: string): string {
  const networked = path.join(userDataDir, profile, "Network", "Cookies");
  if (fs.existsSync(networked)) return networked;
  // Pre-Chrome-96 location.
  return path.join(userDataDir, profile, "Cookies");
}

// =============================================================================
//  Cross-platform entry points (public API — unchanged signatures)
// =============================================================================

export function extractChromeCookies(
  domain: string,
  profile = "Default"
): FacebookCookie[] {
  const platform = process.platform;

  let cookiePath: string;
  let decryptFn: (encrypted: Buffer, key: Buffer) => string;
  let key: Buffer;

  if (platform === "darwin") {
    cookiePath = macCookieDbPath(profile);
    key = macDeriveKey(macGetChromePassword());
    decryptFn = macDecrypt;
  } else if (platform === "win32") {
    const userDataDir = winUserDataDir();
    cookiePath = winCookieDbPath(userDataDir, profile);
    key = winGetMasterKey(userDataDir);
    decryptFn = winDecrypt;
  } else {
    throw new Error(
      `Unsupported platform '${platform}'. Only macOS (darwin) and Windows (win32) are implemented.`
    );
  }

  if (!fs.existsSync(cookiePath)) {
    throw new Error(
      `Chrome cookie DB not found at ${cookiePath}. ` +
        `Check the profile name (got '${profile}'; set CHROME_PROFILE to override).`
    );
  }

  // Chrome locks the DB while running — copy it first (cross-platform via fs).
  const tmpPath = path.join(os.tmpdir(), `chrome_cookies_${Date.now()}`);
  try {
    fs.copyFileSync(cookiePath, tmpPath);
  } catch (copyErr) {
    // On Windows copyFileSync uses CopyFileEx, which asks for FILE_SHARE_READ
    // only and so loses to Chrome's open handle (EBUSY). A plain read goes
    // through libuv's open, which asks for FILE_SHARE_READ|WRITE|DELETE and
    // succeeds against the same handle — so retry that way before giving up.
    try {
      fs.writeFileSync(tmpPath, fs.readFileSync(cookiePath));
    } catch (readErr) {
      throw new Error(
        `Failed to copy Chrome cookie DB from ${cookiePath}: ` +
          (copyErr instanceof Error ? copyErr.message : String(copyErr)) +
          `; shared-read retry also failed: ` +
          (readErr instanceof Error ? readErr.message : String(readErr)) +
          `. Fully quit Chrome and try again.`
      );
    }
  }

  let db: DatabaseSync;
  try {
    db = new DatabaseSync(tmpPath, { readOnly: true });
  } catch {
    throw new Error(`Failed to open cookie database at ${tmpPath}`);
  }

  try {
    const rows = db
      .prepare(
        // expires_utc is microseconds since 1601 and overflows a JS number
        // (node:sqlite throws above 2^53), so read it as text and convert below.
        `SELECT host_key, name, value, encrypted_value, path,
                CAST(expires_utc AS TEXT) AS expires_utc,
                is_secure, is_httponly
         FROM cookies
         WHERE host_key LIKE ?`
      )
      .all(`%${domain}`) as Array<{
      host_key: string;
      name: string;
      value: string;
      encrypted_value: Buffer;
      path: string;
      expires_utc: string;
      is_secure: number;
      is_httponly: number;
    }>;

    const out: FacebookCookie[] = [];
    for (const row of rows) {
      let value = row.value;
      if (!value && row.encrypted_value && row.encrypted_value.length > 0) {
        try {
          // node:sqlite returns BLOBs as Uint8Array; crypto/Buffer methods need a Buffer.
          value = decryptFn(Buffer.from(row.encrypted_value), key);
        } catch (err) {
          // Skip a single undecryptable cookie (e.g. one stray v20 value)
          // rather than failing the whole session extraction.
          if (process.env.FB_MCP_DEBUG) {
            console.error(
              `[auth] skipping cookie '${row.name}': ` +
                (err instanceof Error ? err.message : String(err))
            );
          }
          continue;
        }
      }
      out.push({
        host: row.host_key,
        name: row.name,
        value,
        path: row.path,
        expires: chromeTimeToUnixSeconds(row.expires_utc),
        secure: !!row.is_secure,
        httpOnly: !!row.is_httponly,
      });
    }
    return out;
  } finally {
    db.close();
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {
      // cleanup failure is non-fatal
    }
  }
}

// Chrome stores timestamps as microseconds since 1601-01-01; convert to Unix
// seconds. 0 means a session cookie, which stays 0.
function chromeTimeToUnixSeconds(raw: string): number {
  let micros: bigint;
  try {
    micros = BigInt(raw);
  } catch {
    return 0;
  }
  if (micros <= 0n) return 0;
  return Number(micros / 1000000n - 11644473600n);
}

export function cookiesToHeader(cookies: FacebookCookie[]): string {
  return cookies
    .map((c) => {
      // Strip non-Latin1 chars — fetch rejects them in Cookie headers.
      const safe = c.value.replace(/[^\x00-\xFF]/g, "");
      return `${c.name}=${safe}`;
    })
    .join("; ");
}

export function getCookieValue(
  cookies: FacebookCookie[],
  name: string
): string | undefined {
  return cookies.find((c) => c.name === name)?.value;
}
