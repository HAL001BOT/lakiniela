const fs = require('fs');
const path = require('path');

function mustExist(p) {
  if (!fs.existsSync(p)) {
    throw new Error(`Missing required file: ${p}`);
  }
}

function checkEjsDir(dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.ejs'));
  if (!files.length) throw new Error('No EJS templates found');
}

function main() {
  mustExist(path.join(__dirname, '..', 'server.js'));
  mustExist(path.join(__dirname, '..', 'db.js'));
  mustExist(path.join(__dirname, '..', 'services', 'updater.js'));
  mustExist(path.join(__dirname, '..', 'public', 'style.css'));
  checkEjsDir(path.join(__dirname, '..', 'views'));

  // Require core modules to catch syntax/runtime import issues early.
  require('../db');
  require('../services/updater');

  console.log('Smoke checks passed.');
}

main();
