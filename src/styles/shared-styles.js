export const sharedStyles = `
  :host { display:block; color:var(--qr-ink,#191f28); font-family:var(--qr-font,system-ui,sans-serif); font-size:15px; line-height:1.6; letter-spacing:-.3px; }
  *,*::before,*::after { box-sizing:border-box; }
  [hidden] { display:none !important; }
  h1,h2,h3,p { margin:0; }
  button,input,select { font:inherit; }
  button { cursor:pointer; }
  button:disabled { cursor:default; opacity:.6; }
  button,a,input,select,summary { -webkit-tap-highlight-color:transparent; }
  :focus-visible { outline:3px solid #8cbbff; outline-offset:4px; }
  button { display:inline-flex; align-items:center; justify-content:center; gap:9px; border:0; }
  .button { min-height:56px; padding:15px 20px; border-radius:16px; font-size:17px; font-weight:600; text-decoration:none; line-height:1.4; transition:background .15s; }
  .primary { background:var(--qr-primary,#3182f6); color:#fff; }
  .primary:hover:not(:disabled) { background:var(--qr-primary-hover,#1b64da); }
  .secondary { background:#f2f4f6; color:#4e5968; }
  .secondary:hover:not(:disabled) { background:#e5e8eb; }
  .text-button { background:transparent; color:var(--qr-muted); padding:12px; border-radius:12px; }
  .muted { color:var(--qr-muted); }
  .icon { display:inline-block; flex:none; vertical-align:middle; }
  .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
  @media(prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none !important; transition:none !important; scroll-behavior:auto !important; } }
`;
