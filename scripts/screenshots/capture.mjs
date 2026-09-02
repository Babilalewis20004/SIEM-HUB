// Regenerates docs/screenshots/*.png against a running docker-compose stack.
// Usage: docker compose up -d && docker compose exec backend python seed.py
//        cd scripts/screenshots && npm install && npm run capture
import { chromium } from "playwright";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "..", "..", "docs", "screenshots");
const BASE_URL = process.env.SIEM_BASE_URL || "http://localhost:8080";
const EMAIL = process.env.SIEM_EMAIL || "admin@example.com";
const PASSWORD = process.env.SIEM_PASSWORD || "changeme123";

fs.mkdirSync(OUT_DIR, { recursive: true });

async function shoot(page, name) {
  await page.waitForTimeout(400); // let charts/animations settle
  await page.screenshot({ path: path.join(OUT_DIR, `${name}.png`) });
  console.log(`captured ${name}.png`);
}

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();

async function nav(page, label) {
  await page.click(`a.nav-link:has-text("${label}")`);
  await page.waitForTimeout(700);
}

await page.goto(BASE_URL);
await page.fill('input[type="email"]', EMAIL);
await page.fill('input[type="password"]', PASSWORD);
await page.click('button[type="submit"]');
await page.waitForSelector("nav", { timeout: 15000 });
// Single real socket.io connection for the whole run -- every capture below
// uses client-side <NavLink> navigation (not page.goto) so it's reused
// rather than reconnected per page, and the sidebar's real connection
// indicator is used as the actual readiness signal instead of a fixed sleep.
await page
  .waitForSelector(".connection-status.status-live", { timeout: 10000 })
  .catch(() => console.warn("realtime connection did not reach 'live' in time -- continuing anyway"));

await shoot(page, "01-dashboard");

// The "Live Security Activity" / "Playbook Activity" panels only render
// events pushed over the socket while connected (REST is the source of the
// historical record, sockets mean "something changed" -- see
// docs/ARCHITECTURE.md) -- so generate one fresh detection while the
// dashboard is live-connected and let it stream in before re-shooting.
await page.evaluate(async () => {
  const token = localStorage.getItem("siem_lite_token");
  const now = new Date();
  const lines = Array.from({ length: 6 }, (_, i) => {
    const ts = new Date(now.getTime() - (6 - i) * 1000).toISOString().split(".")[0];
    return `${ts} demo01 sshd[${4000 + i}]: Failed password for root from 192.0.2.55 port ${47000 + i} ssh2`;
  });
  await fetch("/api/logs/upload", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ source: "ssh", host: "demo01", lines }),
  });
  await fetch("/api/alerts/run-detection", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
});
await page.waitForTimeout(2500);
await shoot(page, "01-dashboard");

await nav(page, "Alerts");
const firstAlertRow = page.locator("table tbody tr").first();
if (await firstAlertRow.count()) {
  await firstAlertRow.click();
  await page.waitForTimeout(300);
}
await shoot(page, "02-alerts");

await nav(page, "Incidents");
await shoot(page, "03-incidents");

const firstIncidentRow = page.locator("table tbody tr").first();
if (await firstIncidentRow.count()) {
  await firstIncidentRow.click();
  await page.waitForTimeout(700);
  await shoot(page, "04-incident-detail");
}

await nav(page, "Threat Intel");
await shoot(page, "05-threat-intel");

await nav(page, "Logs");
await shoot(page, "06-log-explorer");

await nav(page, "Playbooks");
await shoot(page, "07-playbooks");

await nav(page, "Approvals");
await shoot(page, "08-approvals");

await browser.close();
console.log("Done.");
