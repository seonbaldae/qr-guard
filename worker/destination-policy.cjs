const dns = require("node:dns/promises");
const { BlockList, isIP } = require("node:net");

class UnsafeDestinationError extends Error {}

const blockedIpv4 = new BlockList();
const blockedIpv6 = new BlockList();

for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]) {
  blockedIpv4.addSubnet(network, prefix, "ipv4");
}

for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
]) {
  blockedIpv6.addSubnet(network, prefix, "ipv6");
}

async function assertPublicHttpUrl(value, resolver = resolveHost) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new UnsafeDestinationError("URL 길이나 형식이 올바르지 않습니다.");
  }
  if ([...value].some(character =>
    character === "\\" || /[\s\u0000-\u001f\u007f]/u.test(character)
  )) {
    throw new UnsafeDestinationError("URL에 허용되지 않는 문자가 있습니다.");
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new UnsafeDestinationError("URL 형식이 올바르지 않습니다.");
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new UnsafeDestinationError("HTTP 또는 HTTPS URL만 허용합니다.");
  }
  if (url.username || url.password) {
    throw new UnsafeDestinationError("URL에 사용자 인증정보를 포함할 수 없습니다.");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    throw new UnsafeDestinationError("80 또는 443 포트만 허용합니다.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost")) {
    throw new UnsafeDestinationError("로컬 주소에는 접속할 수 없습니다.");
  }

  const literalFamily = isIP(host);
  const addresses = literalFamily
    ? [{ address: host, family: literalFamily }]
    : await resolver(host);

  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new UnsafeDestinationError("호스트의 IP 주소를 확인할 수 없습니다.");
  }

  for (const record of addresses) {
    const address = typeof record === "string" ? record : record.address;
    const family = isIP(address);
    if (!family) {
      throw new UnsafeDestinationError("DNS 결과의 IP 주소 형식이 올바르지 않습니다.");
    }
    const blockList = family === 4 ? blockedIpv4 : blockedIpv6;
    if (blockList.check(address, family === 4 ? "ipv4" : "ipv6")) {
      throw new UnsafeDestinationError("공개 인터넷이 아닌 주소에는 접속할 수 없습니다.");
    }
  }

  return url.href;
}

async function resolveHost(host) {
  try {
    return await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    throw new UnsafeDestinationError("호스트의 IP 주소를 확인할 수 없습니다.");
  }
}

module.exports = { UnsafeDestinationError, assertPublicHttpUrl };
