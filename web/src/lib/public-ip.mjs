import { isIP } from 'node:net';

function ipv4Number(address) {
  return address.split('.').reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function inIpv4Range(address, network, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(network) & mask);
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
    const normalized = address.toLowerCase();
    // Public IPv6 unicast is in 2000::/3. Exclude documentation and the
    // legacy protocol-assignment block rather than querying test addresses.
    if (!/^[23]/.test(normalized)) return false;
    if (normalized.startsWith('2001:db8:') || normalized === '2001:db8') return false;
    if (normalized.startsWith('3fff:') || normalized === '3fff') return false; // 3fff::/20 documentation prefix
    if (normalized.startsWith('2002:')) return false; // deprecated 6to4 transition prefix
    if (normalized.startsWith('2001:')) {
      const secondHextet = normalized.split(':')[1];
      const secondValue = secondHextet ? Number.parseInt(secondHextet, 16) : 0;
      if (Number.isFinite(secondValue) && secondValue <= 0x1ff) return false; // 2001::/23 special-purpose block
    }
    return true;
  }

  return false;
}
