import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { parseNetshFirewallRules } from "../src/lib/fleet/liveTelemetryCollector";
import { getCapability } from "../src/lib/fleet/capabilities";

test("Endpoint Firewall Authority & Parsing Test Suite", async (t) => {
  await t.test("parseNetshFirewallRules parses netsh advfirewall output into structured items", () => {
    const sampleNetsh = `
Rule Name:                            ShieldDesk-Block-SMB-445
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Block

Rule Name:                            ShieldDesk-Block-In-198.51.100.23
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             
LocalIP:                              Any
RemoteIP:                             198.51.100.23
Protocol:                             Any
Edge traversal:                       No
Action:                               Block
`;

    const rules = parseNetshFirewallRules(sampleNetsh, true);
    assert.equal(rules.length, 2);
    assert.equal(rules[0].name, "ShieldDesk-Block-SMB-445");
    assert.equal(rules[0].direction, "in");
    assert.equal(rules[0].action, "block");
    assert.equal(rules[0].protocol, "TCP");
    assert.equal(rules[0].localPort, "445");
    assert.equal(rules[0].isShieldDeskRule, true);

    assert.equal(rules[1].name, "ShieldDesk-Block-In-198.51.100.23");
    assert.equal(rules[1].remoteIp, "198.51.100.23");
    assert.equal(rules[1].action, "block");
  });

  await t.test("Capabilities Engine accurately resolves firewall authority commands", () => {
    const addRuleCap = getCapability("firewall_add_rule ShieldDesk-Test in block TCP 445");
    assert.ok(addRuleCap);
    assert.equal(addRuleCap?.name, "firewall.block");
    assert.ok(addRuleCap?.supportedOS.includes("windows"));

    const deleteRuleCap = getCapability("firewall_delete_rule ShieldDesk-Test");
    assert.ok(deleteRuleCap);
    assert.equal(deleteRuleCap?.name, "firewall.block");

    const setProfileCap = getCapability("firewall_set_profile domain on");
    assert.ok(setProfileCap);

    const setDefaultCap = getCapability("firewall_set_default block allow");
    assert.ok(setDefaultCap);
  });
});
