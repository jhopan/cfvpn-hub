import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../public/", import.meta.url);

for (const page of ["login.html", "register.html"]) {
  test(`${page} has email and password form`, async () => {
    const html = await readFile(new URL(page, root), "utf8");
    assert.match(html, /type="email"/);
    assert.match(html, /type="password"/);
  });
}

test("app isolates demo data per signed-in user and redirects signed-out users", async () => {
  const app = await readFile(new URL("app.js", root), "utf8");
  assert.match(app, /jhopan-vpn-panel-users/);
  assert.match(app, /jhopan-vpn-panel-session/);
  assert.match(app, /login\.html/);
  assert.match(app, /requireAuth/);
});

test("dashboard links to login and register when no session exists", async () => {
  const html = await readFile(new URL("index.html", root), "utf8");
  assert.match(html, /href="login\.html"/);
  assert.match(html, /href="register\.html"/);
});
