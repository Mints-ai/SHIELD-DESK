import test from "node:test";
import assert from "node:assert/strict";
import { validateIpAddress, isLoopbackIp, isValidIpAddress } from "../src/lib/utils/ipValidation";

test("IP Validation Utility Suite", async (t) => {
  await t.test("Rejects malformed IPv4 formats", () => {
    assert.equal(validateIpAddress("197.10.1").valid, false);
    assert.equal(validateIpAddress("197 .10.1").valid, false);
    assert.equal(validateIpAddress("197.10.1.256").valid, false);
    assert.equal(validateIpAddress("197.10.1.01").valid, false); // leading zero
    assert.equal(validateIpAddress("not-an-ip").valid, false);
    assert.equal(validateIpAddress("").valid, false);
  });

  await t.test("Rejects loopback and broadcast addresses", () => {
    assert.equal(validateIpAddress("127.0.0.1").valid, false);
    assert.equal(validateIpAddress("127.0.0.2").valid, false);
    assert.equal(validateIpAddress("::1").valid, false);
    assert.equal(validateIpAddress("0.0.0.0").valid, false);
    assert.equal(validateIpAddress("255.255.255.255").valid, false);
  });

  await t.test("Accepts valid IPv4, CIDR, and IPv6 addresses", () => {
    assert.equal(validateIpAddress("192.168.1.1").valid, true);
    assert.equal(validateIpAddress("10.0.0.1").valid, true);
    assert.equal(validateIpAddress("203.0.113.15").valid, true);
    assert.equal(validateIpAddress("192.168.1.0/24").valid, true);
    assert.equal(validateIpAddress("2001:db8::1").valid, true);
  });

  await t.test("Helper functions behave accurately", () => {
    assert.equal(isLoopbackIp("127.0.0.1"), true);
    assert.equal(isLoopbackIp("::1"), true);
    assert.equal(isLoopbackIp("192.168.1.1"), false);
    assert.equal(isValidIpAddress("197.10.1"), false);
    assert.equal(isValidIpAddress("197.10.1.5"), true);
  });
});
