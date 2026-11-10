import { apiGetMasterKeyRecovery, apiRepairMasterKey } from '../api.js';
import { unwrapMasterKey } from '../crypto.js';

export class MasterKeyRecoveryError extends Error {}

export async function unwrapMasterKeyWithRecovery(metadata, derivedKey) {
  try {
    return {
      masterKey: await unwrapMasterKey(
        metadata.wrappedMasterKey,
        metadata.masterKeyIV,
        derivedKey
      ),
      recovered: false,
      repairError: null
    };
  } catch (primaryError) {
    let recoveryData;

    try {
      recoveryData = await apiGetMasterKeyRecovery();
    } catch (error) {
      console.error('Master Key recovery lookup failed:', error);
      throw new MasterKeyRecoveryError(
        'The active Master Key could not be opened, and S3 recovery data could not be fetched. Check your connection or contact support.'
      );
    }

    const records = Array.isArray(recoveryData.records)
      ? recoveryData.records
      : [];

    if (records.length === 0) {
      throw new MasterKeyRecoveryError(
        'No Master Key recovery records were found. Check your encryption password or contact support.'
      );
    }

    for (const record of records) {
      let masterKey;

      try {
        masterKey = await unwrapMasterKey(
          record.wrappedKey,
          record.iv,
          derivedKey
        );
      } catch {
        continue;
      }

      let repairError = null;

      try {
        await apiRepairMasterKey(record.wrappedKey, record.iv);
      } catch (error) {
        console.error('Recovered Master Key could not repair the active copy:', error);
        repairError = error;
      }

      return { masterKey, recovered: true, repairError };
    }

    throw primaryError;
  }
}
