class RecoveryStore {
  async append(record) {
    throw new Error('append() must be implemented');
  }

  async getMasterKeyHistory(userId) {
    throw new Error('getMasterKeyHistory() must be implemented');
  }

  async getFileKeyHistory(userId, fileId) {
    throw new Error('getFileKeyHistory() must be implemented');
  }
}

module.exports = RecoveryStore;