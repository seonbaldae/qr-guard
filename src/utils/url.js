const MAX_URL_LENGTH = 2048;

export function validateUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('검사할 사이트 주소를 입력해 주세요.');
  }
  const value = raw.trim();
  if (value.length > MAX_URL_LENGTH) {
    throw new Error('주소가 너무 깁니다. 2,048자 이내의 주소를 입력해 주세요.');
  }
  // Require a nonempty authority before URL() can repair extra slashes.
  const authority = value.match(/^https?:\/\/([^/?#]+)/i)?.[1];
  if (!authority || /[\s\\\p{C}]/u.test(value)) {
    throw new Error('http:// 또는 https://로 시작하는 올바른 주소를 입력해 주세요.');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('주소 형식을 확인해 주세요.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    throw new Error('HTTP 또는 HTTPS 웹사이트만 검사할 수 있습니다.');
  }
  // Reject userinfo, including empty userinfo that URL serialization removes.
  if (parsed.username || parsed.password || authority.includes('@')) {
    throw new Error('계정 정보가 포함된 주소는 검사할 수 없습니다.');
  }
  return parsed.href;
}

// Only user/QR input gets a default scheme. API responses and destinations must
// keep using validateUrl(), which requires an explicit HTTP(S) URL.
export function normalizeInputUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('검사할 사이트 주소를 입력해 주세요.');
  }
  const value = raw.trim();
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(value) || /^https?:/i.test(value)) {
    return validateUrl(value);
  }
  if (/^[/?#]/.test(value)) {
    throw new Error('검사할 웹사이트의 전체 주소를 입력해 주세요.');
  }

  const normalized = validateUrl(`https://${value}`);
  const hostname = new URL(normalized).hostname.replace(/\.$/, '');
  const authority = value.split(/[/?#]/, 1)[0];
  const labels = hostname.split('.');
  const isDomain = labels.length > 1
    && labels.every(label => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label))
    && /[a-z]/i.test(labels[labels.length - 1]);
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(authority);
  const isIpv6 = authority.startsWith('[');
  if (!isDomain && !isIpv4 && !isIpv6 && hostname !== 'localhost') {
    throw new Error('웹사이트 주소가 담긴 QR을 스캔하거나 주소를 확인해 주세요.');
  }
  return normalized;
}

export function displayUrl(raw) {
  try {
    const parsed = new URL(validateUrl(raw));
    return `${parsed.origin}${parsed.pathname}${parsed.search || parsed.hash ? ' …' : ''}`;
  } catch {
    return '주소를 확인할 수 없습니다';
  }
}

export function getHostname(raw) {
  try {
    return new URL(validateUrl(raw)).hostname;
  } catch {
    return '주소 확인 불가';
  }
}
