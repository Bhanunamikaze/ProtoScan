const express = require('express');
const bodyParser = require('body-parser');
const child_process = require('child_process');
const vm = require('vm');
const ejs = require('ejs');
const ws = require('ws');
const minimist = require('minimist');
const qs = require('qs');
const merge = require('merge');
const _ = require('lodash');
const fs = require('fs');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());

const userProfile = {};
const runtimeConfig = {};
const template = '<%= user %>';
runtimeConfig.env = process.env;

function requireAuth(req, res, next) {
  if (!req.headers['x-auth']) return res.status(401).send('auth required');
  next();
}

const schema = {
  validate(input) {
    // intentionally unsafe: just returns input
    return input;
  }
};

function unsafeCopy(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}

function poison(target) {
  if (!target) return;
  target.constructor.prototype.compromised = true;
}

app.post('/api/profile', (req, res) => {
  const body = req.body; // source
  Object.assign(userProfile, body); // sink
  merge(userProfile, body.settings); // sink.package.merge
  _.set(userProfile, body.path || '__proto__.polluted', body.value || true); // lodash set sink
  _.defaultsDeep(runtimeConfig.deep || {}, body.deepDefaults || {}); // recursive defaults sink
  const revived = JSON.parse(body.payload || '{}', (key, value) => value); // sink.json.parse.reviver
  runtimeConfig.payload = revived;
  runtimeConfig.cache = runtimeConfig.cache || {};
  runtimeConfig.cache[body.dynamicKey] = body.dynamicValue; // dynamic property sink
  if (body.loopData) unsafeCopy(userProfile, body.loopData);
  poison(body.poisonTarget);
  if (body.template) {
    ejs.render(template, body, {}); // template gadget
  }
  if (body.script) {
    vm.runInNewContext(body.script, {}); // vm gadget
  }
  if (body.command) {
    child_process.exec(body.command); // RCE gadget
    axios.get(body.url || 'https://example.com', { proxy: runtimeConfig.proxy }); // HTTP gadget
  }
  res.json(userProfile);
});

app.post('/api/settings', requireAuth, (req, res) => {
  const validated = schema.validate(req.body);
  Object.assign(runtimeConfig.settings || {}, validated);
  res.json({ status: 'ok' });
});

app.post('/api/public', (req, res) => {
  const data = req.body;
  Object.assign(runtimeConfig.public || {}, data);
  if (data.cmd) child_process.exec(data.cmd);
  res.json({ status: 'public-ok' });
});

app.get('/api/query', (req, res) => {
  const parsed = qs.parse(req.query.payload);
  Object.assign(runtimeConfig.query || {}, parsed);
  res.json(parsed);
});

const argv = minimist(process.argv.slice(2));
Object.assign(runtimeConfig.cli || {}, argv); // CLI source + sink

const socket = new ws.Server({ noServer: true });
socket.on('connection', (client) => {
  ws.on('message', (msg) => {
    const broadcastData = JSON.parse(msg);
    Object.assign(runtimeConfig.wsGlobal || {}, broadcastData);
  });
  client.on('message', (msg) => {
    const data = JSON.parse(msg);
    Object.assign(runtimeConfig.ws || {}, data); // source + sink
    if (data.cmd) child_process.exec(data.cmd);
  });
});

const configFromFile = JSON.parse(fs.readFileSync(__dirname + '/config.json', 'utf8'));
Object.assign(runtimeConfig.file || {}, configFromFile);

app.listen(0);
module.exports = app;
