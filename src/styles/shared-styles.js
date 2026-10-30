export const sharedStyles = `
  :host { display:block; color:var(--qr-ink,#202d28); font-family:var(--qr-font,system-ui,sans-serif); font-size:15px; line-height:1.6; }
  *,*::before,*::after { box-sizing:border-box; }
  [hidden] { display:none !important; }
  h1,h2,h3,p { margin:0; }
  button,input,select { font:inherit; }
  button { cursor:pointer; }
  button:disabled { cursor:default; opacity:.6; }
  button,a,input,select,summary { -webkit-tap-highlight-color:transparent; }
  :focus-visible { outline:3px solid #86ae62; outline-offset:4px; }
  button { display:inline-flex; align-items:center; justify-content:center; gap:9px; border:0; }
  .button { min-height:50px; padding:12px 21px; border-radius:12px; font-weight:650; text-decoration:none; line-height:1.4; transition:background .15s; }
  .primary { background:var(--qr-green); color:#fff; }
  .primary:hover:not(:disabled) { background:#103e31; }
  .secondary { background:#fff; color:var(--qr-ink); border:1px solid var(--qr-border); }
  .secondary:hover:not(:disabled) { background:#f2f5f0; }
  .text-button { background:transparent; color:var(--qr-muted); padding:10px; border-radius:8px; }
  .eyebrow { color:var(--qr-green); letter-spacing:.14em; font-size:11px; font-weight:750; }
  .muted { color:var(--qr-muted); }
  .icon { display:inline-block; flex:none; vertical-align:middle; }
  .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
  @media(prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none !important; transition:none !important; scroll-behavior:auto !important; } }
`;
