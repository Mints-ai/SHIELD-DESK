import crypto from "node:crypto";
import {
  CanonicalTelemetryEvent,
  EventCategory,
  SourceFormat,
  TelemetryIngestContext,
  TelemetrySeverity,
  ProcessContext,
  NetworkContext,
  AuthContext,
  FileContext,
  ServiceContext,
} from "./types";

export class TelemetryNormalizer {
  /**
   * Normalizes any supported raw telemetry format (Sysmon, Security Event Logs,
   * auditd, eBPF, CrowdStrike, Wazuh, Defender, or Native Go agent) into
   * the canonical ShieldDesk telemetry event schema.
   */
  public static normalize(
    raw: Record<string, unknown>,
    context: TelemetryIngestContext
  ): CanonicalTelemetryEvent {
    const format = context.sourceFormat || this.detectFormat(raw);
    const tenantId = context.tenantId;
    const agentId = context.agentId;
    const hostname = context.hostname || (raw.hostname as string) || (raw.ComputerName as string) || "UNKNOWN-HOST";

    let category: EventCategory = "system";
    let eventType = "telemetry_event";
    let severity: TelemetrySeverity = "low";
    let timestamp = (raw.timestamp as string) || (raw.time as string) || (raw.UtcTime as string) || new Date().toISOString();

    let process: ProcessContext | undefined;
    let network: NetworkContext | undefined;
    let auth: AuthContext | undefined;
    let file: FileContext | undefined;
    let service: ServiceContext | undefined;

    switch (format) {
      case "windows_sysmon":
      case "windows_security": {
        const eventId = Number(raw.EventID || raw.eventId || raw.event_id || 0);

        if (eventId === 1) {
          // Sysmon Event 1: Process Creation
          category = "process";
          eventType = "process_create";
          process = {
            pid: Number(raw.ProcessId) || undefined,
            ppid: Number(raw.ParentProcessId) || undefined,
            name: this.extractBaseName(String(raw.Image || raw.CommandLine || "")),
            commandLine: String(raw.CommandLine || raw.Image || ""),
            executablePath: String(raw.Image || ""),
            parentName: this.extractBaseName(String(raw.ParentImage || "")),
            parentCommandLine: String(raw.ParentCommandLine || ""),
            sha256: this.extractHash(String(raw.Hashes || "")),
            user: String(raw.User || ""),
          };
          if (process.commandLine?.includes("powershell") || process.commandLine?.includes("vssadmin")) {
            severity = "high";
          }
        } else if (eventId === 3) {
          // Sysmon Event 3: Network Connection
          category = "network";
          eventType = "network_connect";
          network = {
            sourceIp: String(raw.SourceIp || ""),
            sourcePort: Number(raw.SourcePort) || undefined,
            destinationIp: String(raw.DestinationIp || ""),
            destinationPort: Number(raw.DestinationPort) || undefined,
            protocol: String(raw.Protocol || "tcp").toLowerCase() as NetworkContext["protocol"],
            dnsQuery: String(raw.DestinationHostname || ""),
          };
        } else if (eventId === 11) {
          // Sysmon Event 11: File Created
          category = "file";
          eventType = "file_create";
          file = {
            path: String(raw.TargetFilename || ""),
            operation: "create",
            fileExtension: this.extractExtension(String(raw.TargetFilename || "")),
          };
        } else if (eventId === 4624) {
          // Windows Security 4624: Successful Logon
          category = "authentication";
          eventType = "auth_login";
          auth = {
            userName: String(raw.TargetUserName || ""),
            userDomain: String(raw.TargetDomainName || ""),
            logonType: String(raw.LogonType || "3"),
            authResult: "success",
            sourceIp: String(raw.IpAddress || ""),
          };
        } else if (eventId === 4625) {
          // Windows Security 4625: Failed Logon
          category = "authentication";
          eventType = "auth_failed";
          severity = "medium";
          auth = {
            userName: String(raw.TargetUserName || ""),
            userDomain: String(raw.TargetDomainName || ""),
            logonType: String(raw.LogonType || "3"),
            authResult: "failure",
            failureReason: String(raw.Status || raw.SubStatus || "Bad Password / Unknown User"),
            sourceIp: String(raw.IpAddress || ""),
          };
        }
        break;
      }

      case "linux_auditd":
      case "linux_ebpf": {
        const auditType = String(raw.type || raw.record_type || "").toUpperCase();
        if (auditType === "SYSCALL" || raw.syscall === "execve" || raw.syscall === 59 || raw.comm) {
          category = "process";
          eventType = "process_create";
          process = {
            pid: Number(raw.pid) || undefined,
            ppid: Number(raw.ppid) || undefined,
            name: String(raw.comm || ""),
            commandLine: String(raw.proctitle || raw.args || raw.exe || raw.comm || ""),
            executablePath: String(raw.exe || ""),
            user: String(raw.uid || raw.euid || raw.auid || ""),
          };
        } else if (auditType === "SOCKADDR" || raw.saddr || raw.daddr) {
          category = "network";
          eventType = "network_connect";
          network = {
            sourceIp: String(raw.saddr || ""),
            destinationIp: String(raw.daddr || ""),
            destinationPort: Number(raw.dport) || undefined,
            protocol: "tcp",
          };
        } else if (auditType === "USER_LOGIN" || auditType === "USER_AUTH") {
          category = "authentication";
          const isSuccess = String(raw.res || "").toLowerCase() === "success";
          eventType = isSuccess ? "auth_login" : "auth_failed";
          severity = isSuccess ? "low" : "medium";
          auth = {
            userName: String(raw.acct || raw.user || ""),
            authResult: isSuccess ? "success" : "failure",
            sourceIp: String(raw.hostname || raw.addr || ""),
          };
        }
        break;
      }

      case "crowdstrike": {
        const event = (raw.event as Record<string, unknown>) || raw;
        category = "process";
        eventType = "edr_alert";
        severity = Number(event.Severity || 0) >= 4 ? "critical" : "high";
        process = {
          name: this.extractBaseName(String(event.CommandLine || event.FileName || "")),
          commandLine: String(event.CommandLine || ""),
          executablePath: String(event.FileName || ""),
        };
        break;
      }

      case "wazuh": {
        const rule = (raw.rule as Record<string, unknown>) || {};
        const level = Number(rule.level || 0);
        severity = level >= 12 ? "critical" : level >= 8 ? "high" : level >= 4 ? "medium" : "low";
        category = "system";
        eventType = "wazuh_alert";
        break;
      }

      case "defender": {
        const sev = String(raw.severity || "").toLowerCase();
        severity = sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : "low";
        category = "system";
        eventType = "defender_alert";
        break;
      }

      case "shielddesk_native":
      default: {
        const rawType = String(raw.eventType || raw.event_type || raw.type || "").toLowerCase();
        const payload = (raw.payload as Record<string, unknown>) || raw;

        if (rawType.includes("process")) {
          category = "process";
          eventType = rawType.includes("term") ? "process_terminate" : "process_create";
          process = {
            pid: Number(payload.pid) || undefined,
            ppid: Number(payload.ppid) || undefined,
            name: String(payload.name || payload.exe || ""),
            commandLine: String(payload.commandLine || payload.cmd || payload.command || ""),
            executablePath: String(payload.exe || payload.path || ""),
            sha256: String(payload.sha256 || payload.hash || ""),
            user: String(payload.user || ""),
          };
        } else if (rawType.includes("network") || rawType.includes("dns") || rawType.includes("connect")) {
          category = "network";
          eventType = rawType.includes("dns") ? "dns_query" : "network_connect";
          network = {
            sourceIp: String(payload.sourceIp || payload.src_ip || ""),
            sourcePort: Number(payload.sourcePort || payload.src_port) || undefined,
            destinationIp: String(payload.destinationIp || payload.dest_ip || payload.ip || ""),
            destinationPort: Number(payload.destinationPort || payload.dest_port || payload.port) || undefined,
            protocol: (String(payload.protocol || "tcp").toLowerCase() as NetworkContext["protocol"]) || "tcp",
            dnsQuery: String(payload.dnsQuery || payload.domain || payload.query || ""),
          };
        } else if (rawType.includes("auth") || rawType.includes("login")) {
          category = "authentication";
          const failed = rawType.includes("fail") || payload.success === false;
          eventType = failed ? "auth_failed" : "auth_login";
          severity = failed ? "medium" : "low";
          auth = {
            userName: String(payload.userName || payload.user || ""),
            userDomain: String(payload.userDomain || payload.domain || ""),
            authResult: failed ? "failure" : "success",
            sourceIp: String(payload.sourceIp || payload.ip || ""),
          };
        } else if (rawType.includes("file")) {
          category = "file";
          eventType = rawType;
          file = {
            path: String(payload.path || payload.filePath || ""),
            operation: (payload.operation as FileContext["operation"]) || "create",
            fileExtension: this.extractExtension(String(payload.path || payload.filePath || "")),
            sha256: String(payload.sha256 || payload.hash || ""),
          };
        } else if (rawType.includes("service")) {
          category = "service";
          eventType = rawType;
          service = {
            serviceName: String(payload.serviceName || payload.name || ""),
            state: (payload.state as ServiceContext["state"]) || "running",
          };
        } else {
          category = "system";
          eventType = rawType || "system_metric";
        }
        break;
      }
    }

    // Deterministic event fingerprint for deduplication
    const keyData = `${process?.commandLine || ""}|${network?.destinationIp || ""}|${file?.path || ""}|${auth?.userName || ""}`;
    const fingerprint = crypto
      .createHash("sha256")
      .update(`${tenantId}:${agentId}:${category}:${eventType}:${timestamp.substring(0, 16)}:${keyData}`)
      .digest("hex");

    const id = `evt_${fingerprint.substring(0, 24)}`;

    return {
      id,
      tenantId,
      agentId,
      hostname,
      category,
      eventType,
      severity,
      timestamp,
      fingerprint,
      sourceFormat: format,
      process,
      network,
      auth,
      file,
      service,
      raw,
    };
  }

  private static detectFormat(raw: Record<string, unknown>): SourceFormat {
    if (raw.EventID || raw.eventId || raw.EventData) {
      const eid = Number(raw.EventID || raw.eventId);
      return eid >= 4600 && eid <= 4700 ? "windows_security" : "windows_sysmon";
    }
    if (raw.type && typeof raw.type === "string" && (raw.type.startsWith("SYSCALL") || raw.type.startsWith("USER_"))) {
      return "linux_auditd";
    }
    if (raw.event && typeof raw.event === "object" && (raw.event as Record<string, unknown>).DetectName) {
      return "crowdstrike";
    }
    if (raw.rule && raw.agent) {
      return "wazuh";
    }
    if (raw.machineDnsName || raw.threatFamilyName) {
      return "defender";
    }
    return "shielddesk_native";
  }

  private static extractBaseName(pathStr: string): string {
    if (!pathStr) return "";
    const clean = pathStr.split(" ")[0].replace(/["']/g, "");
    const parts = clean.split(/[/\\]/);
    return parts[parts.length - 1] || "";
  }

  private static extractExtension(pathStr: string): string {
    if (!pathStr) return "";
    const dotIndex = pathStr.lastIndexOf(".");
    return dotIndex !== -1 ? pathStr.substring(dotIndex + 1).toLowerCase() : "";
  }

  private static extractHash(hashStr: string): string | undefined {
    if (!hashStr) return undefined;
    const shaMatch = hashStr.match(/SHA256=([A-Fa-f0-9]{64})/i);
    if (shaMatch) return shaMatch[1];
    const md5Match = hashStr.match(/MD5=([A-Fa-f0-9]{32})/i);
    return md5Match ? md5Match[1] : undefined;
  }
}
