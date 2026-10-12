import { isIP } from 'node:net';

function ipv4Number(address) {
  return address.split('.').reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function inIpv4Range(address, network, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(network) & mask);
}

function ipv6Hextets(address) {
  let normalized = address.toLowerCase();

  // IPv4-embedded IPv6 literals encode the final 32 bits as two hextets.
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    const octets = normalized.slice(lastColon + 1).split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = normalized.slice(0, lastColon + 1) + high + ':' + low;
  }

  const halves = normalized.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length > 1 ? 8 - left.length - right.length : 0;
  return [
    ...left.map(part => Number.parseInt(part, 16)),
    ...Array.from({ length: missing }, () => 0),
    ...right.map(part => Number.parseInt(part, 16)),
  ];
}

/**
 * Only permit globally routable IP literals for reputation lookups.
 * This avoids spending provider quota on loopback, private, link-local,
 * documentation, benchmarking, multicast, and other non-public ranges.
 */
export function isPublicIpAddress(address) {
  const version = isIP(address);
  if (version === 4) {
    const blocked = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24],
      ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
      ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
      ['224.0.0.0', 4], ['240.0.0.0', 4],
    ];
    return !blocked.some(([network, prefix]) => inIpv4Range(address, network, prefix));
  }

  if (version === 6) {
    const [firstHextet, secondHextet] = ipv6Hextets(address);

    // Public IPv6 unicast is in 2000::/3. Use parsed hextets instead of
    // textual prefix checks: IPv6 permits compression and leading zeroes.
    if (firstHextet < 0x2000 || firstHextet > 0x3fff) return false;

    // IANA special-purpose ranges that are not globally reachable.
    if (firstHextet === 0x2001 && secondHextet <= 0x01ff) return false; // 2001::/23
    if (firstHextet === 0x2001 && secondHextet === 0x0db8) return false; // 2001:db8::/32 documentation
    if (firstHextet === 0x3fff) return false; // 3fff:: documentation/reserved block
    if (firstHextet === 0x2002) return false; // deprecated 6to4 transition prefix

    return true;
  }

  return false;
}
