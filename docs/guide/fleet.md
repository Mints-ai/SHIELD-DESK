# Fleet & Host Management

**URL:** `/dashboard/fleet`

Shows every endpoint agent enrolled in your ShieldDesk tenant.

## Agent Cards

Each card displays:

| Field | Description |
|-------|-------------|
| **Hostname** | Machine name |
| **IP address** | Endpoint's current public/WAN IP when available; falls back to its local adapter IP when external discovery is unavailable |
| **OS / Platform** | Windows Server, Ubuntu, macOS, etc. |
| **Agent Status** | `online`, `offline`, `compromised`, or `isolated` |
| **CPU and Memory** | Current utilisation |
| **Last Seen** | Most recent heartbeat timestamp |

Agents marked **COMPROMISED** or **ISOLATED** are highlighted red. Investigate immediately.

The agent refreshes its detected IP periodically. Public IP discovery uses the address observed by the control-plane proxy, then an external IP lookup; local adapter IP is used only when those sources are unavailable.

## Issuing Remote Commands

Click an agent to open its detail panel. In the **Command Panel**:

1. Choose a **command** (e.g. `take_safety_snapshot`, `isolate_host`, `run_vulnerability_scan`)
2. Select a **Tier** — determines the approval gate
3. Optionally enter a **Token ID** to reference a pre-issued approval token
4. Click **Execute Command**

Results appear in the **Command Log** with timestamp, status (`succeeded` / `failed` / `executing`), and full output.

## Kill Switch

Emergency network isolation of **all enrolled agents** simultaneously. This is a Tier 3 action requiring Super Admin approval.

{% hint style="danger" %}
**Warning:** The kill switch disconnects every endpoint from the network. Use only during a confirmed active breach.
{% endhint %}
