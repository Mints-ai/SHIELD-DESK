import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { POST as loginPOST } from "../src/app/api/auth/login/route";
import { GET as threatsGET, POST as threatsPOST } from "../src/app/api/threats/route";
import {
  isIpBlocked,
  blockIp,
  unblockIp,
  getBlockedIps,
  resetThreatAlerts,
  recordThreatAlert,
  getIpFailureCount,
} from "../src/lib/alerts/threatAlertStore";
import { createSessionToken } from "../src/lib/auth/token";

test("ShieldDesk IP Blocking & Autonomous Containment Suite", async (t) => {
  t.beforeEach(() => {
    resetThreatAlerts();
  });

  t.after(() => {
    resetThreatAlerts();
  });

  await t.test("Unit: IP is not blocked initially and failure count is 0", () => {
    const testIp = "192.168.10.50";
    assert.equal(isIpBlocked(testIp), false);
    assert.equal(getIpFailureCount(testIp), 0);
  });

  await t.test("Unit: Escalation occurs and blocks IP after exceeding 5 failed attempts", () => {
    const testIp = "192.168.10.55";

    // 1 to 5 failed attempts
    for (let i = 1; i <= 5; i++) {
      const alert = recordThreatAlert({
        targetUser: "victim@corp.internal",
        clientIp: testIp,
        failureReason: "Invalid password",
      });
      assert.equal(alert.attemptsCount, i);
      assert.equal(isIpBlocked(testIp), false, `Attempt ${i} should not block yet`);
    }

    // 6th failed attempt (>5)
    const sixthAlert = recordThreatAlert({
      targetUser: "victim@corp.internal",
      clientIp: testIp,
      failureReason: "Invalid password",
    });

    assert.equal(sixthAlert.attemptsCount, 6);
    assert.equal(sixthAlert.severity, "critical");
    assert.equal(sixthAlert.isBlocked, true);
    assert.equal(isIpBlocked(testIp), true, "6th failure must trigger IP containment");

    const blockedList = getBlockedIps();
    assert.ok(blockedList.some((b) => b.ip === testIp));
  });

  await t.test("Integration: /api/auth/login rejects with 403 when IP is blocked (>5 failures)", async () => {
    const attackerIp = "10.0.0.99";

    // Generate 5 failed login attempts via API
    for (let i = 1; i <= 5; i++) {
      const req = new NextRequest("http://localhost:3000/api/auth/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": attackerIp,
        },
        body: JSON.stringify({
          email: "target.user@example.com",
          password: `wrong-password-${i}`,
        }),
      });

      const res = await loginPOST(req);
      assert.ok([401, 503].includes(res.status), `Attempt ${i} should return 401 or 503`);
      const data = await res.json();
      assert.equal(data.blocked, undefined);
    }

    // 6th attempt: triggers block
    const req6 = new NextRequest("http://localhost:3000/api/auth/login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": attackerIp,
      },
      body: JSON.stringify({
        email: "target.user@example.com",
        password: "wrong-password-6",
      }),
    });
    const res6 = await loginPOST(req6);
    // 6th attempt fails with 401/503 and records the 6th failure which sets isIpBlocked = true
    assert.ok([401, 503].includes(res6.status));
    assert.equal(isIpBlocked(attackerIp), true);

    // 7th attempt: blocked at gateway with 403 Forbidden!
    const req7 = new NextRequest("http://localhost:3000/api/auth/login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": attackerIp,
      },
      body: JSON.stringify({
        email: "target.user@example.com",
        password: "any-password",
      }),
    });
    const res7 = await loginPOST(req7);
    assert.equal(res7.status, 403, "Blocked IP must receive 403 Forbidden");
    const data7 = await res7.json();
    assert.equal(data7.blocked, true);
    assert.match(data7.error, /blocked/i);
    assert.equal(data7.clientIp, attackerIp);
  });

  await t.test("Integration: SOC admin can unblock IP via /api/threats unblock_ip action", async () => {
    const blockedIp = "172.16.5.20";
    blockIp(blockedIp, "Manual containment test", 6);
    assert.equal(isIpBlocked(blockedIp), true);

    const adminToken = createSessionToken({
      uid: "dev-admin",
      tenantId: "acme-tenant",
      role: "system_admin",
    });

    const unblockReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `shielddesk_session=${adminToken}`,
      },
      body: JSON.stringify({
        action: "unblock_ip",
        ip: blockedIp,
      }),
    });

    const unblockRes = await threatsPOST(unblockReq);
    assert.equal(unblockRes.status, 200);
    const unblockData = await unblockRes.json();
    assert.equal(unblockData.success, true);
    assert.equal(isIpBlocked(blockedIp), false, "IP must now be unblocked");
  });
});
