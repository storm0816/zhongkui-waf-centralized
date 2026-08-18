#!/usr/bin/env node

const path = require('path');

const [workDir, archivePath, packageName] = process.argv.slice(2);
if (!workDir || !archivePath || !packageName) {
  throw new Error('usage: create_release_archive.js WORK_DIR ARCHIVE PACKAGE_NAME');
}

const tarModulePath = path.join(
  path.dirname(process.execPath),
  'node_modules',
  'npm',
  'node_modules',
  'tar'
);
const tar = require(tarModulePath);
const executableFiles = new Set(['install.sh', 'upgrade.sh']);

tar.c({
  cwd: workDir,
  file: archivePath,
  gzip: true,
  portable: true,
  onWriteEntry(entry) {
    const normalized = entry.path.replace(/\\/g, '/');
    const relative = normalized.startsWith(`${packageName}/`)
      ? normalized.slice(packageName.length + 1).replace(/\/$/, '')
      : '';

    if (entry.type === 'Directory') {
      entry.stat.mode = 0o755;
    } else if (entry.type === 'File') {
      entry.stat.mode = executableFiles.has(relative) ? 0o755 : 0o644;
    }
  }
}, [packageName]).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
