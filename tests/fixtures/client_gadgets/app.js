import DOMPurify from 'dompurify';
import sanitizeHtml from 'sanitize-html';

function hydrateDashboard(payload) {
  const safe = DOMPurify.sanitize(payload.html);
  const sanitized = sanitizeHtml(safe);
  analytics.track('pageview', sanitized);
  window.embedly('card', sanitized);
  goog.load('maps', '3');
  filterXSS(sanitized);
  ko.observable(payload.user).subscribe(() => {});
  Marionette.View.extend({ template: payload.tpl });
  recaptcha.render('captcha');
  Sprint('#app').html(sanitized);
  window[SwiftypeObject || '_st'] = function () {};
  twq('track', 'Purchase', payload.meta);
  utag.view(payload.meta);
  Zepto('#target').text(sanitized);
  Popper.createPopper(anchor, popup, payload.popper || {});
  pendo.initialize({ visitor: payload.visitor });
  i18next.t('key', payload.meta);
  Demandbase?.Log?.info?.(payload.meta);
  mutiny.track('event', payload.meta);
  AMP.push?.(payload.meta);
}

hydrateDashboard({
  html: '<img src onerror=alert(1)>',
  meta: {},
  visitor: {},
});
