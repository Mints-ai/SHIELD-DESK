/**
 * Universal IP Validation Utility
 * Client and server compatible (zero Node.js dependencies).
 */

export interface IpValidationResult {
  valid: boolean;
  error?: string;
  isIpv6?: boolean;
  isCidr?: boolean;
}

/**
 * Checks if an IP string is a loopback address.
 */
export function isLoopbackIp(ip: string): boolean {
  if (!ip || typeof ip !== "string") return false;
  const clean = ip.trim().toLowerCase();
  return (
    clean === "127.0.0.1" ||
    clean === "::1" ||
    clean === "localhost" ||
    clean.startsWith("127.") ||
    clean.startsWith("::ffff:127.")
  );
}

/**
 * Validates an IPv4 or IPv6 address (with optional CIDR prefix).
 */
export function validateIpAddress(ip: string): IpValidationResult {
  if (!ip || typeof ip !== "string") {
    return { valid: false, error: "IP address cannot be empty." };
  }

  const trimmed = ip.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: "IP address cannot be empty." };
  }

  if (/\s/.test(trimmed)) {
    return {
      valid: false,
      error: "IP address cannot contain spaces or whitespace.",
    };
  }

  // Handle optional CIDR notation e.g. 192.168.1.0/24
  let baseIp = trimmed;
  let cidrPrefix: number | null = null;
  const isCidr = trimmed.includes("/");

  if (isCidr) {
    const parts = trimmed.split("/");
    if (parts.length !== 2) {
      return { valid: false, error: "Malformed CIDR notation: multiple '/' detected." };
    }
    baseIp = parts[0];
    const prefixStr = parts[1];
    if (!/^\d+$/.test(prefixStr)) {
      return { valid: false, error: "CIDR prefix must be a numeric integer." };
    }
    cidrPrefix = parseInt(prefixStr, 10);
  }

  // Loopback check
  if (isLoopbackIp(baseIp)) {
    return {
      valid: false,
      error: "Refusing to block loopback interface (127.0.0.1) — local system and management channel would be severed.",
    };
  }

  // IPv4 Check
  if (baseIp.includes(".")) {
    const octets = baseIp.split(".");
    if (octets.length !== 4) {
      return {
        valid: false,
        error: `Invalid IPv4 format: Expected 4 octets separated by dots (e.g. 192.168.1.10), got ${octets.length}.`,
      };
    }

    for (let i = 0; i < 4; i++) {
      const octet = octets[i];
      if (!/^\d{1,3}$/.test(octet)) {
        return {
          valid: false,
          error: `Invalid IPv4 octet '${octet}': Must be numeric digits only.`,
        };
      }
      if (octet.length > 1 && octet.startsWith("0")) {
        return {
          valid: false,
          error: `Invalid IPv4 octet '${octet}': Leading zeroes are not permitted.`,
        };
      }
      const num = parseInt(octet, 10);
      if (num < 0 || num > 255) {
        return {
          valid: false,
          error: `Invalid IPv4 octet '${octet}': Value must be between 0 and 255.`,
        };
      }
    }

    // Check special addresses
    if (baseIp === "0.0.0.0") {
      return {
        valid: false,
        error: "Refusing to block 0.0.0.0 (unspecified address / default route).",
      };
    }
    if (baseIp === "255.255.255.255") {
      return {
        valid: false,
        error: "Refusing to block 255.255.255.255 (local broadcast address).",
      };
    }

    if (cidrPrefix !== null) {
      if (cidrPrefix < 0 || cidrPrefix > 32) {
        return {
          valid: false,
          error: `Invalid IPv4 CIDR prefix '/${cidrPrefix}': Must be between /0 and /32.`,
        };
      }
    }

    return { valid: true, isIpv6: false, isCidr };
  }

  // IPv6 Check
  if (baseIp.includes(":")) {
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d))$/;

    if (!ipv6Regex.test(baseIp)) {
      return {
        valid: false,
        error: "Invalid IPv6 address format (e.g. 2001:db8::1).",
      };
    }

    if (cidrPrefix !== null) {
      if (cidrPrefix < 0 || cidrPrefix > 128) {
        return {
          valid: false,
          error: `Invalid IPv6 CIDR prefix '/${cidrPrefix}': Must be between /0 and /128.`,
        };
      }
    }

    return { valid: true, isIpv6: true, isCidr };
  }

  return {
    valid: false,
    error: "Invalid IP address: Must be a standard IPv4 (e.g. 192.168.1.1) or IPv6 address.",
  };
}

/**
 * Simple boolean validator.
 */
export function isValidIpAddress(ip: string): boolean {
  return validateIpAddress(ip).valid;
}
