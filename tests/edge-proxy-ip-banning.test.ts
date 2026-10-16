import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { proxy } from "@/proxy";
import {
  blockIp,
  unblockIp,
  isIpBlocked,
  resetThreatAlerts,
} from "@/lib/alerts/threatAlertStore";

test("ShieldDesk Edge Proxy: Complete IP Banning & Containment Suite", async (t) => {
  t.beforeEach(() => {
    resetThreatAlerts();
  });

  t.after(() => {
    resetThreatAlerts();
  });

  const bannedIp = "203.0.113.88";

  await t.test("Unblocked IP: can access public routes without edge IP ban", () => {
    const req = new NextRequest("http://localhost:3000/login", {
      headers: {
        "x-forwarded-for": bannedIp,
      },
    });
    const res = proxy(req);
    // Unblocked IP reaching /login gets normal proxy flow (200 next middleware)
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-shielddesk-blocked"), null);
  });

  await t.test("Edge Ban: Blocked IP cannot access dashboard web pages (/dashboard, /dashboard/plans/..., /login)", async () => {
    blockIp(bannedIp, "Malicious brute-force attack", 6);
    assert.equal(isIpBlocked(bannedIp), true, "IP must be in blocked store");

    const protectedUrls = [
      "http://localhost:3000/dashboard",
      "http://localhost:3000/dashboard/fleet",
      "http://localhost:3000/dashboard/plans/plan-9999",
      "http://localhost:3000/dashboard/threats",
      "http://localhost:3000/login",
      "http://localhost:3000/",
    ];

    for (const targetUrl of protectedUrls) {
      const req = new NextRequest(targetUrl, {
        headers: {
          "x-forwarded-for": bannedIp,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });

      const res = proxy(req);
      assert.equal(
        res.status,
        403,
        `Blocked IP must receive HTTP 403 Forbidden on ${targetUrl}`
      );
      assert.equal(res.headers.get("x-shielddesk-blocked"), "true");
      assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");

      const html = await res.text();
      assert.match(html, /IP Access Banned by SOC Policy/);
      assert.match(html, new RegExp(bannedIp));
      assert.match(html, /Security Quarantine Active/);
      assert.match(html, /TERMINATED/);
    }
  });

  await t.test("Edge Ban: Blocked IP cannot access any API endpoints (/api/incidents, /api/plans, /api/agent/heartbeat)", async () => {
    blockIp(bannedIp, "Automated Threat Containment", 6);

    const apiUrls = [
      "http://localhost:3000/api/incidents",
      "http://localhost:3000/api/plans",
      "http://localhost:3000/api/fleet",
      "http://localhost:3000/api/agent/heartbeat",
      "http://localhost:3000/api/agent/commands",
    ];

    for (const apiUrl of apiUrls) {
      const req = new NextRequest(apiUrl, {
        headers: {
          "x-forwarded-for": bannedIp,
          accept: "application/json",
        },
      });

      const res = proxy(req);
      assert.equal(
        res.status,
        403,
        `Blocked IP must receive HTTP 403 Forbidden on ${apiUrl}`
      );
      assert.equal(res.headers.get("x-shielddesk-blocked"), "true");

      const body = await res.json();
      assert.equal(body.blocked, true);
      assert.equal(body.error, "IP_BANNED");
      assert.equal(body.clientIp, bannedIp);
      assert.match(body.message, /banned by ShieldDesk SOC Security Policy/);
    }
  });

  await t.test("Unblock Restoration: Once unblocked, edge proxy immediately restores full access", () => {
    blockIp(bannedIp, "Temporary drill", 6);
    assert.equal(isIpBlocked(bannedIp), true);

    // Unblock the IP
    unblockIp(bannedIp);
    assert.equal(isIpBlocked(bannedIp), false);

    // Test access again
    const req = new NextRequest("http://localhost:3000/login", {
      headers: {
        "x-forwarded-for": bannedIp,
      },
    });
    const res = proxy(req);
    assert.equal(res.status, 200, "Unblocked IP must be allowed through proxy");
    assert.equal(res.headers.get("x-shielddesk-blocked"), null);
  });
});
