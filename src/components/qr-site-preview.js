import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { loadPreviewImage } from '../services/preview-api.js';

export class QrSitePreview extends HTMLElement {
  constructor() {
    super(); this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      section { overflow:hidden; }
      h2 { font-size:15px; font-weight:650; color:#4e5968; margin-bottom:12px; }
      .image-wrap { min-height:180px; display:flex; align-items:flex-start; justify-content:center; position:relative; background:#f2f4f6; border-radius:18px; overflow:hidden; }
      img { display:block; width:100%; height:auto; max-height:330px; object-fit:cover; object-position:top; background:white; }
      .empty { min-height:180px; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; gap:12px; color:#b0b8c1; padding:24px; }
      .empty p { max-width:240px; font-size:14px; color:#8b95a1; }
      .caption { margin-top:10px; color:#8b95a1; font-size:12px; }
    </style><section aria-labelledby="preview-title"><h2 id="preview-title">미리보기</h2><div class="image-wrap"><img hidden alt="격리 환경에서 촬영한 사이트의 정적 미리보기"><div class="empty">${icon('image',28)}<p role="status">미리보기가 없어요</p></div></div><p class="caption">격리 환경에서 촬영한 이미지예요</p></section>`;
    this._generation=0;
    this.shadowRoot.querySelector('img').addEventListener('error',()=>this.showError());
  }
  set result(value) {
    this.cleanup();const generation=this._generation;
    const image=this.shadowRoot.querySelector('img'); image.removeAttribute('src'); image.hidden=true;
    this.shadowRoot.querySelector('.empty').hidden=false;
    this.shadowRoot.querySelector('.empty p').textContent=value?.previewUrl?'미리보기를 불러오고 있어요':'미리보기가 없어요';
    if(value?.previewUrl) {
      const controller=new AbortController();this._controller=controller;
      loadPreviewImage(value.previewUrl,{signal:controller.signal,demo:value.demo}).then(blob=>{
        if(generation!==this._generation||!this.isConnected)return;
        this._objectUrl=URL.createObjectURL(blob);
        image.alt=value.demo?'데모용으로 제작한 사이트 미리보기 이미지':'격리 환경에서 촬영한 사이트의 정적 미리보기';
        image.src=this._objectUrl;image.hidden=false;this.shadowRoot.querySelector('.empty').hidden=true;
      }).catch(()=>{if(generation===this._generation&&!controller.signal.aborted)this.showError();});
    }
    this.shadowRoot.querySelector('.caption').textContent=value?.demo?'테스트용 이미지예요':'격리 환경에서 촬영한 이미지예요';
  }
  showError() {
    this.shadowRoot.querySelector('img').hidden=true;this.shadowRoot.querySelector('.empty').hidden=false;
    this.shadowRoot.querySelector('.empty p').textContent='미리보기를 불러오지 못했어요';
  }
  cleanup() { this._generation+=1;this._controller?.abort();if(this._objectUrl)URL.revokeObjectURL(this._objectUrl);this._objectUrl=null; }
  disconnectedCallback() { this.cleanup(); }
}
