import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const publicDir = new URL("../public/", import.meta.url);
const pages = ["index.html", "workers.html", "generator.html", "deploy.html"];

for (const page of pages) {
  test(`${page} has shared page navigation`, async () => {
    const html = await readFile(new URL(page, publicDir), "utf8");
    assert.match(html, /href="workers\.html"/);
    assert.match(html, /href="generator\.html"/);
    assert.match(html, /href="deploy\.html"/);
  });
}

test("deploy page cancel never triggers required-field validation", async () => {
  const html = await readFile(new URL("deploy.html", publicDir), "utf8");
  assert.match(html, /id="cancelDeploy"[^>]*type="button"/);
});

test("client app supports local dummy deploy for VPN and load balancer", async () => {
  const app = await readFile(new URL("app.js", publicDir), "utf8");
  assert.match(app, /deploy-demo/);
  assert.match(app, /load_balancer/);
  assert.match(app, /location\.href = "workers\.html"/);
});
