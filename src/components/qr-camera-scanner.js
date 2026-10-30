import { sharedStyles } from '../styles/shared-styles.js';

const cameraIcon = `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m8.5 5 1-2h5l1 2H19a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h3.5Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.7"/></svg>`;

export class QrCameraScanner extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._generation = 0;
    this._timer = null;
    this._stream = null;
    this._detector = null;
    this._active = false;
    this._busy = false;
    this._started = false;
    this.shadowRoot.innerHTML = `
      <style>
        ${sharedStyles}
        :host { display:block; min-width:0; }
        .frame { position:relative; isolation:isolate; display:flex; align-items:center; justify-content:center; aspect-ratio:1.45; min-height:306px; overflow:hidden; padding:38px 24px; border:1px solid #dce5df; border-radius:20px; background:#eef2ed; color:#1b4736; text-align:center; }
        .frame::before { content:''; z-index:-1; position:absolute; inset:0; opacity:.6; background-image:linear-gradient(#dae2d933 1px, transparent 1px),linear-gradient(90deg,#dae2d933 1px,transparent 1px); background-size:28px 28px; }
        .frame.active { background:#122b23; }
        video { position:absolute; z-index:-1; width:100%; height:100%; inset:0; object-fit:cover; }
        video[hidden] { display:none; }
        .brackets { position:absolute; inset:28px; pointer-events:none; }
        .corner { position:absolute; width:30px; height:30px; border:3px solid #315c44; border-radius:3px; }
        .tl { top:0; left:0; border-right:0; border-bottom:0; border-top-left-radius:11px; }
        .tr { top:0; right:0; border-left:0; border-bottom:0; border-top-right-radius:11px; }
        .bl { bottom:0; left:0; border-right:0; border-top:0; border-bottom-left-radius:11px; }
        .br { bottom:0; right:0; border-left:0; border-top:0; border-bottom-right-radius:11px; }
        .active .corner { border-color:#d6f5b9; }
        .placeholder { display:flex; flex-direction:column; align-items:center; max-width:310px; }
        .placeholder[hidden] { display:none; }
        .qr-mark { width:76px; height:76px; margin-bottom:23px; color:#375f48; }
        h3 { margin:0 0 9px; font-size:17px; font-weight:700; line-height:1.5; letter-spacing:-.5px; }
        .hint { margin:0; font-size:13px; line-height:1.7; color:#77847a; word-break:keep-all; }
        .live-label { display:none; position:absolute; left:42px; bottom:42px; padding:8px 12px; border-radius:7px; background:#102c23d9; color:#f1faec; font-size:12px; gap:7px; align-items:center; }
        .active .live-label { display:flex; }
        .live-dot { width:6px; height:6px; border-radius:50%; background:#c4f69f; }
        .controls { display:flex; flex-direction:column; align-items:center; padding-top:22px; }
        .camera-button { appearance:none; display:inline-flex; justify-content:center; align-items:center; gap:10px; min-height:49px; padding:12px 28px; border:1px solid #214c37; border-radius:10px; background:#214c37; color:#fff; font:inherit; font-size:14px; font-weight:650; cursor:pointer; transition:background-color .15s; }
        .camera-button:hover { background:#163e2b; }
        .camera-button:disabled { opacity:.65; cursor:wait; }
        .camera-button svg { width:19px; height:19px; }
        .camera-button:focus-visible { outline:3px solid #80aa52; outline-offset:4px; }
        .state { min-height:20px; margin:13px 0 0; max-width:470px; text-align:center; color:#738077; font-size:12px; line-height:1.65; word-break:keep-all; }
        .state.error { color:#a43c2c; }
        .privacy { display:flex; justify-content:center; align-items:center; gap:5px; margin:12px 0 0; font-size:11px; line-height:1.6; color:#8a938c; }
        .privacy svg { width:12px; height:12px; flex-shrink:0; }
        @media(max-width:480px) { .frame { min-height:278px; padding:32px 25px; aspect-ratio:1.12; border-radius:15px; } .brackets { inset:20px; } .qr-mark { width:66px; height:66px; margin-bottom:18px; } h3 { font-size:15px; } .hint { font-size:12px; } .camera-button { width:100%; } .live-label { left:30px; bottom:30px; } }
        @media(prefers-reduced-motion:reduce) { .camera-button { transition:none; } }
      </style>
      <div class="frame">
        <video playsinline muted hidden aria-label="QR 코드 촬영을 위한 카메라 화면"></video>
        <div class="brackets" aria-hidden="true"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i></div>
        <div class="placeholder">
          <svg class="qr-mark" viewBox="0 0 80 80" fill="none" aria-hidden="true"><rect x="9" y="9" width="23" height="23" rx="3" stroke="currentColor" stroke-width="3"/><rect x="48" y="9" width="23" height="23" rx="3" stroke="currentColor" stroke-width="3"/><rect x="9" y="48" width="23" height="23" rx="3" stroke="currentColor" stroke-width="3"/><path d="M17 17h7v7h-7zm39 0h7v7h-7zM17 56h7v7h-7z" fill="currentColor"/><path d="M48 48h9v9h14M48 64v7h9M64 48h7v8M64 64h7v7h-7M39 9v9m0 8v14H23m-14 0h6m24 9v8m0 7v7M48 40h8m8 0h7" stroke="currentColor" stroke-width="3" stroke-linejoin="round"/></svg>
          <h3>QR 코드를 프레임 안에 맞춰주세요</h3>
          <p class="hint">카메라를 켜고 QR 코드를 비추면<br>연결된 주소를 먼저 확인해 드려요.</p>
        </div>
        <span class="live-label"><span class="live-dot"></span>QR 코드 인식 중</span>
      </div>
      <div class="controls">
        <button class="camera-button" type="button">${cameraIcon}<span>카메라 켜기</span></button>
        <p class="state" role="status" aria-live="polite">카메라 접근 권한이 필요해요.</p>
        <p class="privacy"><svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3.5" y="7" width="9" height="7" rx="1.5" stroke="currentColor"/><path d="M5.5 7V4.5a2.5 2.5 0 0 1 5 0V7" stroke="currentColor"/></svg>카메라 영상은 저장하거나 전송하지 않아요.</p>
      </div>`;
    this._video = this.shadowRoot.querySelector('video');
    this._frame = this.shadowRoot.querySelector('.frame');
    this._placeholder = this.shadowRoot.querySelector('.placeholder');
    this._button = this.shadowRoot.querySelector('button');
    this._buttonLabel = this._button.querySelector('span');
    this._status = this.shadowRoot.querySelector('.state');
  }

  connectedCallback() {
    this._events?.abort();
    this._events = new AbortController();
    const { signal } = this._events;
    this._button.addEventListener('click', () => {
      if (this._active) {
        this.stop();
        this.setMessage('카메라를 껐어요. 다시 켜서 촬영할 수 있어요.');
      } else {
        this.start();
      }
    }, { signal });
    document.addEventListener('visibilitychange', () => {
      if (document.hidden && (this._active || this._busy)) {
        this.stop();
        this.setMessage('화면을 벗어나 카메라를 껐어요. 다시 켜서 촬영해 주세요.');
      }
    }, { signal });
  }

  disconnectedCallback() {
    this._events?.abort();
    this.stop();
  }

  setMessage(message, error = false) {
    this._status.textContent = message;
    this._status.classList.toggle('error', error);
  }

  stop() {
    this._generation += 1;
    clearTimeout(this._timer);
    this._timer = null;
    this._streamEvents?.abort();
    this._stream?.getTracks().forEach((track) => track.stop());
    this._stream = null;
    this._detector = null;
    this._video.pause();
    this._video.srcObject = null;
    this._video.hidden = true;
    this._active = false;
    this._busy = false;
    this._frame.classList.remove('active');
    this._placeholder.hidden = false;
    this._button.disabled = false;
    this._buttonLabel.textContent = this._started ? '카메라 다시 켜기' : '카메라 켜기';
  }

  async start() {
    if (this._busy || this._active || !this.isConnected || document.hidden) return;
    this.stop();
    const generation = this._generation;
    this._busy = true;
    this._button.disabled = true;
    this._buttonLabel.textContent = '카메라 준비 중';
    this.setMessage('카메라와 QR 인식 기능을 확인하고 있어요.');
    try {
      if (!window.isSecureContext) {
        throw new Error('카메라는 HTTPS 환경에서 사용할 수 있어요. 로컬에서는 localhost 또는 127.0.0.1로 접속해 주세요.');
      }
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error('이 브라우저에서는 카메라를 사용할 수 없어요. 아래에 URL을 직접 입력해 주세요.');
      }
      if (!('BarcodeDetector' in window) || typeof BarcodeDetector.getSupportedFormats !== 'function') {
        throw new Error('이 브라우저는 기본 QR 인식을 지원하지 않아요. 아래에 URL을 직접 입력해 주세요.');
      }
      const formats = await BarcodeDetector.getSupportedFormats();
      if (generation !== this._generation) return;
      if (!formats.includes('qr_code')) {
        throw new Error('이 브라우저는 QR 코드 인식을 지원하지 않아요. 아래에 URL을 직접 입력해 주세요.');
      }
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      let stream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } } });
      } catch (error) {
        if (error.name !== 'OverconstrainedError' || generation !== this._generation) throw error;
        stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: true });
      }
      if (generation !== this._generation || !this.isConnected || document.hidden) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      this._stream = stream;
      this._detector = detector;
      this._video.srcObject = stream;
      this._video.hidden = false;
      await this._video.play();
      if (generation !== this._generation) return;
      this._streamEvents = new AbortController();
      stream.getVideoTracks().forEach((track) => track.addEventListener('ended', () => {
        if (generation !== this._generation) return;
        this.stop();
        this.setMessage('카메라 연결이 끊겼어요. 카메라를 다시 켜 주세요.', true);
      }, { signal: this._streamEvents.signal }));
      this._started = true;
      this._active = true;
      this._busy = false;
      this._button.disabled = false;
      this._buttonLabel.textContent = '카메라 끄기';
      this._frame.classList.add('active');
      this._placeholder.hidden = true;
      this.setMessage('QR 코드를 프레임 안에 비춰 주세요. 사이트는 바로 열리지 않아요.');
      this._detect(generation);
    } catch (error) {
      if (generation !== this._generation) return;
      this.stop();
      const messages = {
        NotAllowedError: '카메라 접근이 허용되지 않았어요. 브라우저의 카메라 권한을 확인하거나 아래에 URL을 직접 입력해 주세요.',
        PermissionDeniedError: '카메라 권한이 거부됐어요. 브라우저 설정에서 권한을 허용해 주세요.',
        NotFoundError: '사용할 수 있는 카메라를 찾지 못했어요. 카메라 연결을 확인하거나 URL을 직접 입력해 주세요.',
        DevicesNotFoundError: '연결된 카메라가 없어요. 아래에 URL을 직접 입력해 주세요.',
        NotReadableError: '다른 앱이 카메라를 사용 중이거나 카메라를 시작할 수 없어요. 다른 앱을 닫고 다시 시도해 주세요.',
        TrackStartError: '카메라를 시작할 수 없어요. 다른 앱의 카메라 사용을 확인해 주세요.',
        OverconstrainedError: '카메라 설정을 적용할 수 없어요. 다른 카메라 또는 URL 직접 입력을 이용해 주세요.',
        SecurityError: '브라우저 보안 설정 때문에 카메라를 사용할 수 없어요. HTTPS 연결과 카메라 권한을 확인해 주세요.',
      };
      // Only locally created guidance is displayed; browser error text may contain device information.
      const localGuidance = error.constructor === Error && /^카메라는 |^이 브라우저/.test(error.message) ? error.message : null;
      this.setMessage(messages[error.name] || localGuidance || '카메라를 시작하지 못했어요. 다시 시도하거나 아래에 URL을 직접 입력해 주세요.', true);
    }
  }

  async _detect(generation) {
    if (generation !== this._generation || !this._active) return;
    try {
      if (this._video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
        const codes = await this._detector.detect(this._video);
        if (generation !== this._generation || !this._active) return;
        const code = codes.find((item) => typeof item.rawValue === 'string' && item.rawValue.trim());
        if (code) {
          this.stop();
          this.setMessage('QR 코드를 찾았어요. 주소를 확인하고 있어요.');
          this.dispatchEvent(new CustomEvent('qr-detected', { detail: { value: code.rawValue, source: 'camera' }, bubbles: true, composed: true }));
          return;
        }
      }
    } catch {
      if (generation !== this._generation) return;
      this.stop();
      this.setMessage('QR 코드를 읽지 못했어요. 카메라를 다시 켜거나 아래에 URL을 직접 입력해 주세요.', true);
      return;
    }
    if (generation === this._generation && this._active) {
      this._timer = setTimeout(() => this._detect(generation), 220);
    }
  }
}
