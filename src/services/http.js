import { frontendConfig } from '../config.js';

export class ServiceError extends Error {
  constructor(message, code = 'request_failed') {
    super(message);
    this.name = 'ServiceError';
    this.code = code;
  }
}

export function createRequestScope(parentSignal, timeoutMs = frontendConfig.requestTimeoutMs) {
  const controller = new AbortController();
  let timedOut = false;
  const abort = () => controller.abort();
  if (parentSignal?.aborted) abort();
  else parentSignal?.addEventListener('abort', abort, { once: true });
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  return {
    signal: controller.signal,
    get timedOut() { return timedOut; },
    dispose() {
      clearTimeout(timeout);
      parentSignal?.removeEventListener('abort', abort);
    },
  };
}

export function waitFor(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('요청이 취소되었습니다.', 'AbortError'));
      return;
    }
    const cleanup = () => signal?.removeEventListener('abort', abort);
    const timeout = setTimeout(() => { cleanup(); resolve(); }, ms);
    const abort = () => {
      clearTimeout(timeout);
      cleanup();
      reject(new DOMException('요청이 취소되었습니다.', 'AbortError'));
    };
    signal?.addEventListener('abort', abort, { once: true });
  });
}

export function apiOrigin() {
  const base = new URL(frontendConfig.apiBaseUrl || '/', globalThis.location?.origin || 'http://localhost');
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
    throw new ServiceError('검사 서버 설정을 확인해 주세요.', 'configuration');
  }
  return base.origin;
}

export function apiUrl(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
    throw new ServiceError('검사 서버 설정을 확인해 주세요.', 'configuration');
  }
  const resolved = new URL(path, apiOrigin());
  if (resolved.origin !== apiOrigin() || !resolved.pathname.startsWith('/api/')) {
    throw new ServiceError('검사 서버 설정을 확인해 주세요.', 'configuration');
  }
  return resolved.href;
}

export async function requestJson(path, { body, signal, method = 'GET' } = {}) {
  signal?.throwIfAborted();
  let response;
  try {
    response = await fetch(apiUrl(path), {
      method,
      signal,
      redirect: 'error',
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch (error) {
    if (signal?.aborted || error?.name === 'AbortError') throw error;
    throw new ServiceError('검사 서버에 연결할 수 없습니다. 연결 상태와 API 설정을 확인해 주세요.', 'network');
  }
  if (!response.ok) {
    throw new ServiceError(
      [404, 405, 501].includes(response.status)
        ? '검사 API가 연결되지 않았습니다. 데모 체험을 이용하거나 서버 연결을 확인해 주세요.'
        : '서버가 요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.',
      'http',
    );
  }
  try {
    const result = await response.json();
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error();
    return result;
  } catch (error) {
    if (signal?.aborted || error?.name === 'AbortError') throw error;
    throw new ServiceError('검사 서버의 응답 형식을 확인할 수 없습니다.', 'invalid_response');
  }
}

export function scopedError(error, scope) {
  if (scope.timedOut) return new ServiceError('검사 응답 시간이 초과되었습니다. 다시 검사해 주세요.', 'timeout');
  if (scope.signal.aborted || error?.name === 'AbortError') return new DOMException('요청이 취소되었습니다.', 'AbortError');
  if (error instanceof ServiceError) return error;
  return new ServiceError('요청을 완료하지 못했습니다. 다시 시도해 주세요.');
}
