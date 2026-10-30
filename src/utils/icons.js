const paths = {
  shield: '<path d="M12 3 4.5 6v5.6c0 4.5 3.2 7.5 7.5 9.4 4.3-1.9 7.5-4.9 7.5-9.4V6L12 3Z"/><path d="m8.5 11.8 2.3 2.3 4.7-4.7"/>',
  camera: '<path d="M8 6.5 9.5 4h5L16 6.5h3a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8.5a2 2 0 0 1 2-2Z"/><circle cx="12" cy="13" r="3.5"/>',
  qr: '<rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="3" y="15" width="6" height="6" rx="1"/><path d="M15 15h3v3h3v3h-6v-3h-3v-6h3M12 3v5M3 12h5M18 12h3"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  external: '<path d="M14 3h7v7m0-7L10 14M10 4H5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2v-5"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 6.3a8 8 0 0 1 13 2.7M4.9 15a8 8 0 0 0 13 2.7"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  check: '<path d="m5 12 4.5 4.5L19 7"/>',
  warning: '<path d="m10.3 4.4-8 14A1.8 1.8 0 0 0 3.9 21h16.2a1.8 1.8 0 0 0 1.6-2.6l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/>',
  flag: '<path d="M5 21V4c5-4 9 4 14 0v10c-5 4-9-4-14 0"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a20 20 0 0 1 0 18 20 20 0 0 1 0-18Z"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8" cy="8" r="1"/><path d="m3 16 5-5 4 4 3-3 6 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  chevron: '<path d="m8 5 7 7-7 7"/>',
};
// All SVG fragments are fixed local markup, never QR or API input.
export function icon(name, size = 20) {
  const path = paths[name] || paths.shield;
  const dimension = Number.isFinite(size) ? Math.max(12, Math.min(96, size)) : 20;
  return `<svg class="icon" width="${dimension}" height="${dimension}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${path}</svg>`;
}
