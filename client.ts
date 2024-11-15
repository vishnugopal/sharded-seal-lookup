import { seal, context, indexInShardOf, shardSize, explain } from "./common";

const { publicKey, secretKey } = generateKeys();

/**
 * Generate public and secret keys. This should be done once per client instance.
 *
 * @returns The generated public and secret keys.
 */
function generateKeys() {
  const keyGenerator = seal.KeyGenerator(context);
  const publicKey = keyGenerator.createPublicKey();
  const secretKey = keyGenerator.secretKey();

  keyGenerator.delete();

  return { publicKey, secretKey };
}

/**
 * Creates an encrypted query for a mobile number using homomorphic encryption.
 * This can be sent to the server for processing. The query is a byte array
 * where the byte at the index of the mobile number is set to 1
 * (and all others are zeroed out).
 *
 * @param mobileNumber The mobile number to create an encrypted query for.
 * @returns The encrypted query as a UInt8Array.
 */
function createEncryptedQuery(mobileNumber: number) {
  const batchEncoder = seal.BatchEncoder(context);
  const encryptor = seal.Encryptor(context, publicKey);

  const query = new Uint32Array(batchEncoder.slotCount).fill(0);
  query[indexInShardOf(mobileNumber)] = 1; // Target the index within the shard

  const plainQuery = seal.PlainText();

  batchEncoder.encode(query, plainQuery);
  const encryptedQuery = seal.CipherText();
  encryptor.encrypt(plainQuery, encryptedQuery);

  const encryptedArray = encryptedQuery.saveArray();

  batchEncoder.delete();
  encryptor.delete();
  encryptedQuery.delete();

  return encryptedArray;
}

/**
 * Decrypts the result of the server computation using the secret key.
 * Note that the server never decrypts the result at all, instead it
 * performs a homomorphic multiplication evaluation on the encrypted query
 * and that's what's present in the encryptedResultArray.
 *
 * @param encryptedResultArray A Uint8Array representing the encrypted result.
 * @returns Whether the mobile number exists in the server database.
 */
function decryptResult(encryptedResultArray: Uint8Array) {
  explain("Inside decryptedResult", 3);

  const encryptedResult = seal.CipherText();
  encryptedResult.loadArray(context, encryptedResultArray);

  const batchEncoder = seal.BatchEncoder(context);
  const decryptor = seal.Decryptor(context, secretKey);

  const decryptedResult = seal.PlainText();
  decryptor.decrypt(encryptedResult, decryptedResult);
  const decodedResult = batchEncoder.decode(decryptedResult);

  batchEncoder.delete();
  decryptor.delete();
  decryptedResult.delete();
  encryptedResult.delete();

  // Make sure that the slice is normalized to the shard size.
  const normalizedSlice = decodedResult.slice(0, shardSize);

  explain(`Decoded result: ${normalizedSlice}`, 2);

  // Check if any bits are set, if so, the number exists in the server database.
  const exists = normalizedSlice.some((bit) => bit === 1);

  return exists;
}

export { secretKey, createEncryptedQuery, decryptResult };
