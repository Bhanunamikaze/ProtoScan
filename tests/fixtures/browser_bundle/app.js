const defaults = { theme: 'light' };
const params = new URLSearchParams(window.location.search);
const config = { ...defaults, ...params }; // browser source + spread sink
const settings = {};
settings[params.get('key')] = params.get('value'); // dynamic property sink
const storage = localStorage.getItem('userData');
const merged = Object.assign({}, config, JSON.parse(storage || '{}'));
window.postMessage(merged, '*');
