import querystring from 'component-querystring';
import { paramsParse as parseParams } from 'analytics-utils';
const Arg = require('arg.js');
const canDeparam = require('can-deparam');
const jqueryDeparam = require('jquery-deparam');
const bbq = require('jquery-bbq');
const purl = require('purl');

function buildConfig() {
  const defaults = { theme: 'light' };
  const search = window.location.search;
  const hash = document.location.hash.substring(1);
  const parsedQuery = querystring.parse(search);
  const analyticsParams = parseParams(hash);
  const argParsed = Arg.parse(search);
  const canParsed = canDeparam(search);
  const jqueryParsed = jqueryDeparam(search);
  const bbqState = $.bbq.getState(hash);
  const purlParams = purl(window.location.href).param();
  const url = new URL(window.location.href);
  const searchParams = new URLSearchParams(search);
  return {
    ...defaults,
    ...parsedQuery,
    ...analyticsParams,
    ...argParsed,
    ...canParsed,
    ...jqueryParsed,
    ...bbqState,
    ...purlParams,
    url,
    searchParams,
  };
}

can.deparam(window.location.search);
