import { createRequestScope, scopedError, ServiceError } from './http.js';
import { previewUrl } from './response-adapter.js';

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
const DEMO_IMAGES = new Set(['/assets/demo-clear.svg', '/assets/demo-phishing.svg']);

export async function loadPreviewImage(raw, { signal, demo = false } = {}) {
  const url = previewUrl(raw, { demo });
  if (!url) throw new ServiceError('허용되지 않은 미리보기 이미지 주소입니다.', 'invalid_preview');
  const scope = createRequestScope(signal);
  try {
    scope.signal.throwIfAborted();
    let response;
    try {
      response = await fetch(url, {
        signal: scope.signal,
        redirect: 'error',
        credentials: 'same-origin',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
        headers: { Accept: demo ? 'image/png,image/jpeg,image/webp,image/gif,image/svg+xml' : 'image/png,image/jpeg,image/webp,image/gif' },
      });
    } catch (error) {
      if (scope.signal.aborted || error?.name === 'AbortError') throw error;
      throw new ServiceError('미리보기 이미지에 연결할 수 없습니다.', 'preview_network');
    }
    if (!response.ok) throw new ServiceError('미리보기 이미지를 불러오지 못했습니다.', 'preview_http');
    const type = (response.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
    const fixedDemoSvg = demo === true && DEMO_IMAGES.has(new URL(url).pathname) && type === 'image/svg+xml';
    if (!IMAGE_TYPES.has(type) && !fixedDemoSvg) {
      throw new ServiceError('지원하는 이미지 형식의 미리보기가 아닙니다.', 'preview_type');
    }
    const declaredSize = Number(response.headers.get('Content-Length'));
    if (Number.isFinite(declaredSize) && declaredSize > MAX_IMAGE_BYTES) {
      throw new ServiceError('미리보기 이미지가 너무 큽니다.', 'preview_size');
    }
    const blob = await response.blob();
    scope.signal.throwIfAborted();
    if (!blob.size || blob.size > MAX_IMAGE_BYTES) {
      throw new ServiceError('미리보기 이미지의 크기를 확인해 주세요.', 'preview_size');
    }
    return blob;
  } catch (error) {
    throw scopedError(error, scope);
  } finally {
    scope.dispose();
  }
}
