// One-time (and re-login) helper for the Facebook Marketplace MCP.
// Opens a visible Chrome window using the MCP's OWN dedicated user-data-dir
// (never your real Chrome profile), so you can log into Facebook once. After
// you log in and close the window, the MCP can read the session headlessly
// over DevTools — this dedicated dir is non-default, so Chrome allows CDP and
// the App-Bound Encryption barrier that blocks reading your real profile does
// not apply.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function findChromeExe() {
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }
  const c = [
    path.join(process.env["PROGRAMFILES"] ?? "C:/Program Files", "Google/Chrome/Application/chrome.exe"),
    path.join(process.env["PROGRAMFILES(X86)"] ?? "C:/Program Files (x86)", "Google/Chrome/Application/chrome.exe"),
    path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local"), "Google/Chrome/Application/chrome.exe"),
  ];
  for (const p of c) if (fs.existsSync(p)) return p;
  throw new Error("Could not find chrome.exe; set CHROME_PATH.");
}

const dir =
  process.env.CHROME_USER_DATA_DIR ||
  path.join(process.env.LOCALAPPDATA ?? ".", "fb-marketplace-mcp", "chrome");
fs.mkdirSync(dir, { recursive: true });

const exe = findChromeExe();
console.log(`Opening Chrome with dedicated profile:\n  ${dir}\n`);
console.log("Log into Facebook in the window that opens, then CLOSE the window.");

const child = spawn(
  exe,
  [
    `--user-data-dir=${dir}`,
    "--profile-directory=Default",
    "--no-first-run",
    "--no-default-browser-check",
    "https://www.facebook.com/login",
  ],
  { stdio: "ignore", detached: false }
);
child.on("exit", () => {
  console.log("\nChrome closed. If you logged in, the MCP can now read the session.");
  process.exit(0);
});
