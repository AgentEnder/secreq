export interface StoredCredential {
  privateKey: CryptoKey;
  nickname: string;
}

const DATABASE_NAME = 'secreq-link';
const STORE_NAME = 'credentials';
const DEVICE_KEY = 'device';

export async function loadCredential(): Promise<StoredCredential | undefined> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, 'readonly');
    const record = await requestResult<StoredCredential | undefined>(
      transaction.objectStore(STORE_NAME).get(DEVICE_KEY),
    );
    await transactionDone(transaction);
    return record;
  } finally {
    database.close();
  }
}

export async function saveCredential(credential: StoredCredential): Promise<void> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    transaction.objectStore(STORE_NAME).put(credential, DEVICE_KEY);
    await transactionDone(transaction);
  } finally {
    database.close();
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.addEventListener('upgradeneeded', () => {
      request.result.createObjectStore(STORE_NAME);
    });
    request.addEventListener('success', () => resolve(request.result));
    request.addEventListener('error', () => reject(request.error));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.addEventListener('success', () => resolve(request.result));
    request.addEventListener('error', () => reject(request.error));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.addEventListener('complete', () => resolve());
    transaction.addEventListener('abort', () => reject(transaction.error));
    transaction.addEventListener('error', () => reject(transaction.error));
  });
}
