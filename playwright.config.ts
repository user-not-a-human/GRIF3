import { defineConfig, devices } from "@playwright/test";

process.env.NO_PROXY = ["127.0.0.1", "localhost", process.env.NO_PROXY].filter(Boolean).join(",");

export default defineConfig({
  testDir: "web/e2e",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  webServer: [
    {
      command: "python3 web_backend.py --port 8765",
      url: "http://127.0.0.1:8765/api/status",
      reuseExistingServer: !process.env.CI,
      timeout: 10_000,
    },
    {
      command: "npm run dev -- --port 5173",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: !process.env.CI,
      timeout: 15_000,
    },
  ],
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
