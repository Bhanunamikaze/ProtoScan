const app = require('express')();
const child_process = require('child_process');
const schema = { validate: (input) => input };
function requireAuth() {}
app.post('/api/user', (req, res) => {
  requireAuth();
  const data = schema.validate(req.body);
  Object.assign(target, data);
  child_process.exec('ls');
});

app.post('/api/settings', (req, res) => {
  const cfg = req.body;
  Object.assign(settings, cfg);
});
