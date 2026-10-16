'use strict';
// Directory for the small JSON stores (history.jsonl, institutions.json, teams.json).
//
// Defaults to backend/data. The test suite sets PHISHSHIELD_DATA_DIR to a temp
// directory before requiring the server, so a test run can never append fake
// scans to the real reports the dashboard serves.
const path = require('path');

const dir = (process.env.PHISHSHIELD_DATA_DIR || '').trim() || path.join(__dirname, '..', 'data');

module.exports = dir;
