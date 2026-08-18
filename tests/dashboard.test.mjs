import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../public/", import.meta.url);
const html = await readFile(new URL("index.html", root), "utf8");
const app = await readFile(new URL("app.js", root), "utf8");

test("dashboard keeps credit summary and links to separate worker, deploy, generator pages", () => {
  assert.match(html, /id="credits"/);
  assert.match(html, /href="workers\.html"/);
  assert.match(html, /href="generator\.html"/);
  assert.match(html, /href="deploy\.html"/);
});

test("dashboard JavaScript keeps dummy credit and worker state local", () => {
  assert.match(app, /dummyCredits/);
  assert.match(app, /localStorage/);
  assert.match(app, /load_balancer/);
});
