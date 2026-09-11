// =============================================================================
//  CDP-based cookie extraction.
//
//  Chrome 127+ on Windows encrypts cookies with App-Bound Encryption (the
//  "v20" prefix): the key is sealed to Chrome via SYSTEM-level DPAPI, so a
//  user-level process cannot decrypt them by reading the DB directly.
//
//  Instead we launch the user's real profile headless with a DevTools remote
//  debugging port and ask Chrome for the cookies over CDP — Chrome does the
//  decryption for us. Requires no other Chrome instance to be running on the
//  same profile (it would grab the singleton lock and ignore our port).
// =============================================================================

import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FacebookCookie } from "./types.js";

function userDataDir(): string {
  if (process.env.CHROME_USER_DATA_DIR) return process.env.CHROME_USER_DATA_DIR;
  const localAppData =
    process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "Google", "Chrome", "User Data");
}

// Reap any Chrome still holding this dedicated profile's singleton lock.
// --headless=new spawns detached child processes that outlive child.kill(),
// and a leftover one makes every later launch hand off to it (no debug port).
// Matches strictly on the user-data-dir, so the user's real Chrome is untouched.
function killChromeForDir(dir: string): void {
  if (process.platform !== "win32") return;
  try {
    execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | " +
          "Where-Object { $_.CommandLine -and $_.CommandLine.Contains($env:FB_MCP_DIR) } | " +
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }",
      ],
      { env: { ...process.env, FB_MCP_DIR: dir }, stdio: "ignore", timeout: 15000 }
    );
  } catch {
    /* best-effort */
  }
}

function clearSingletonLocks(dir: string): void {
  for (const f of ["SingletonLock", "SingletonCookie", "SingletonSocket"]) {
    try {
      fs.rmSync(path.join(dir, f), { force: true });
    } catch {
      /* ignore */
    }
  }
}

function findChromeExe(): string {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }
  const candidates = [
    path.join(
      process.env["PROGRAMFILES"] ?? "C:/Program Files",
      "Google/Chrome/Application/chrome.exe"
    ),
    path.join(
      process.env["PROGRAMFILES(X86)"] ?? "C:/Program Files (x86)",
      "Google/Chrome/Application/chrome.exe"
    ),
    path.join(
      process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local"),
      "Google/Chrome/Application/chrome.exe"
    ),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error(
    "Could not find chrome.exe. Set CHROME_PATH to the Chrome executable."
  );
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const p = addr.port;
        srv.close(() => resolve(p));
      } else {
        srv.close(() => reject(new Error("Could not determine a free port")));
      }
    });
  });
}

async function waitForDevTools(
  port: number,
  timeoutMs: number
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (res.ok) {
        const j = (await res.json()) as { webSocketDebuggerUrl?: string };
        if (j.webSocketDebuggerUrl) return j.webSocketDebuggerUrl;
      }
    } catch (err) {
      lastErr = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(
    `Chrome DevTools did not come up on port ${port} within ${timeoutMs}ms` +
      (lastErr ? ` (last error: ${lastErr})` : "")
  );
}

interface CdpCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number; // seconds; -1 = session
  secure: boolean;
  httpOnly: boolean;
}

function getAllCookies(wsUrl: string): Promise<CdpCookie[]> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timer = setTimeout(() => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      reject(new Error("Timed out waiting for CDP cookie response"));
    }, 15000);

    ws.addEventListener("open", () => {
      ws.send(JSON.stringify({ id: 1, method: "Storage.getCookies" }));
    });
    ws.addEventListener("message", (ev: MessageEvent) => {
      try {
        const msg = JSON.parse(
          typeof ev.data === "string" ? ev.data : String(ev.data)
        );
        if (msg.id === 1) {
          clearTimeout(timer);
          if (msg.error) {
            reject(new Error(`CDP error: ${JSON.stringify(msg.error)}`));
          } else {
            resolve((msg.result?.cookies ?? []) as CdpCookie[]);
          }
          ws.close();
        }
      } catch (err) {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
        ws.close();
      }
    });
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("WebSocket error talking to Chrome DevTools"));
    });
  });
}

export async function extractCookiesViaCdp(
  domain: string,
  profile: string
): Promise<FacebookCookie[]> {
  const exe = findChromeExe();
  const dir = userDataDir();
  // Clear any stale instance/lock so our launch actually owns the debug port.
  killChromeForDir(dir);
  clearSingletonLocks(dir);
  const port = await freePort();
  const args = [
    "--headless=new",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${dir}`,
    `--profile-directory=${profile}`,
    "--remote-allow-origins=*",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-gpu",
    "about:blank",
  ];

  let child: ChildProcess;
  try {
    child = spawn(exe, args, { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    throw new Error(
      `Failed to launch Chrome: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  let stderr = "";
  child.stderr?.on("data", (d) => {
    stderr += d.toString();
  });

  try {
    const wsUrl = await waitForDevTools(port, 20000).catch((err) => {
      const hint = stderr.includes("SingletonLock")
        ? " — another Chrome instance is using this profile; fully quit Chrome first."
        : "";
      throw new Error(`${err instanceof Error ? err.message : err}${hint}`);
    });
    const all = await getAllCookies(wsUrl);
    const suffix = domain.replace(/^\./, "");
    return all
      .filter((c) => {
        const host = c.domain.replace(/^\./, "");
        return host === suffix || host.endsWith(`.${suffix}`);
      })
      .map((c) => ({
        host: c.domain,
        name: c.name,
        value: c.value,
        path: c.path,
        expires: c.expires > 0 ? Math.floor(c.expires) : 0,
        secure: !!c.secure,
        httpOnly: !!c.httpOnly,
      }));
  } finally {
    try {
      child.kill();
    } catch {
      /* ignore */
    }
    // child.kill() misses detached headless children — reap by data-dir.
    killChromeForDir(dir);
  }
}
