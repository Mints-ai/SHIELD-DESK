import { isIP } from "node:net";

export function normalizeEndpointIp(value: unknown): string | null {
  if (typeof value !== "string") return null;

  let ip = value.trim();
  if (ip.toLowerCase().startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  if (!ip || isIP(ip) === 0 || ip === "127.0.0.1" || ip === "::1") {
    return null;
  }

  return ip;
}

function isPublicIp(ip: string): boolean {
  if (isIP(ip) === 6) {
    const firstSegment = Number.parseInt(ip.split(":")[0] || "0", 16);
    return firstSegment >= 0x2000 && firstSegment <= 0x3fff && !ip.toLowerCase().startsWith("2001:db8:");
  }

  const octets = ip.split(".").map(Number);
  const [first, second, third] = octets;
  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && (third === 0 || third === 2)) ||
    (first === 192 && second === 88 && third === 99) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

export function getObservedEndpointIp(headers: Headers): string | null {
  const candidates = [
    headers.get("cf-connecting-ip"),
    headers.get("x-real-ip"),
    headers.get("x-forwarded-for")?.split(",")[0],
  ];

  for (const candidate of candidates) {
    const ip = normalizeEndpointIp(candidate);
    if (ip && isPublicIp(ip)) return ip;
  }

  return null;
}

export function resolveEndpointIp(headers: Headers, bodyIp: unknown): string | null {
  return getObservedEndpointIp(headers) ?? normalizeEndpointIp(bodyIp);
}
