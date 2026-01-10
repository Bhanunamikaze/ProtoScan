import DOMPurify from 'dompurify';

const defaults = { theme: 'light', html: '<div>safe</div>' };

function hydrateWithQuery() {
  const userParams = window.location.search;
  const runtimeState = { ...defaults };
  Object.assign(runtimeState, userParams);
  DOMPurify.sanitize(runtimeState.html || '');
}

hydrateWithQuery();
