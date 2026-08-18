import assert from "node:assert/strict";
import test from "node:test";
import { parseSubParams } from "../functions/api/sub.js";

test("parseSubParams accepts supported generator settings", () => {
  const params = parseSubParams(new URL("https://pages.example/api/sub?host=vpn.example.workers.dev&cc=sg,id&vpn=vless,trojan&port=443,80&format=raw&limit=25"));
  assert.deepEqual(params, {
    host: "vpn.example.workers.dev",
    ccList: ["SG", "ID"],
    vpnList: ["vless", "trojan"],
    portList: ["443", "80"],
    format: "raw",
    limit: 25,
    serviceName: "vpn",
  });
});

test("parseSubParams rejects invalid host and unsupported options", () => {
  assert.throws(() => parseSubParams(new URL("https://pages.example/api/sub?host=https://bad.example")), /Host tidak valid/);
  assert.throws(() => parseSubParams(new URL("https://pages.example/api/sub?host=vpn.example&vpn=vmess")), /Protokol tidak didukung/);
  assert.throws(() => parseSubParams(new URL("https://pages.example/api/sub?host=vpn.example&limit=0")), /Limit harus 1-100/);
});

test("parseSubParams ignores client proxy-list URL", () => {
  const params = parseSubParams(new URL("https://pages.example/api/sub?host=vpn.example&prx-list=https://evil.example/list.txt"));
  assert.equal(Object.hasOwn(params, "prxListUrl"), false);
});
