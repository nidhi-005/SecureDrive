const fs = require('fs/promises');
const path = require('path');
const RecoveryStore = require('./recoveryStore');

const RECOVERY_DIR = path.join(__dirname, '..', 'recovery-data');
const LEDGER_PATH = path.join(RECOVERY_DIR, 'recovery-ledger.jsonl');

class LocalRecoveryStore extends RecoveryStore {
  async ensureStorage() {
    await fs.mkdir(RECOVERY_DIR, { recursive: true });
  }

  async append(record) {
    await this.ensureStorage();
    await fs.appendFile(
      LEDGER_PATH,
      JSON.stringify(record) + '\n',
      'utf8'
    );
  }

  async readAll() {
    await this.ensureStorage();

    try {
      const contents = await fs.readFile(LEDGER_PATH, 'utf8');

      if (!contents.trim()) return [];

      return contents
        .trim()
        .split('\n')
        .map(line => JSON.parse(line));
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }

  async getMasterKeyHistory(userId) {
    const records = await this.readAll();

    return records
      .filter(record =>
        record.recordType === 'MASTER_KEY' &&
        record.userId === String(userId)
      )
      .sort((a, b) => b.version - a.version);
  }

  async getFileKeyHistory(userId, fileId) {
    const records = await this.readAll();

    return records
      .filter(record =>
        record.recordType === 'FILE_CEK' &&
        record.userId === String(userId) &&
        record.fileId === String(fileId)
      )
      .sort((a, b) => b.version - a.version);
  }

  async deleteUserRecords(userId) {
    await this.ensureStorage();

    const targetId = String(userId);
    const records = await this.readAll();

    const remaining = records.filter(
      record => record.userId !== targetId
    );

    const tempPath = `${LEDGER_PATH}.tmp`;

    const contents = remaining.length
      ? remaining.map(record => JSON.stringify(record)).join('\n') + '\n'
      : '';

    await fs.writeFile(tempPath, contents, {
      encoding: 'utf8',
      mode: 0o600
    });

    // Replace the ledger only after the new contents are written.
    await fs.rename(tempPath, LEDGER_PATH);
  }
}

module.exports = new LocalRecoveryStore();