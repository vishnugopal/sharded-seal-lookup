import {
  seal,
  context,
  shardSize,
  shardIndexOf,
  indexInShardOf,
  explain,
} from "./common";

/**
 * Shard database
 *
 * This is implemented as a Map, so we can have sparse shards.
 */
const shards = new Map<number, Uint8Array>();

/**
 * Get the number of shards in the database.
 *
 * @returns The number of shards in the database.
 */
function shardCount() {
  return shards.size;
}

/**
 * Split the database into shards
 *
 * @param mobileNumbers The mobile numbers to process into shards.
 */
function initializeDatabase(mobileNumbers: number[]) {
  // Find the maximum mobile number to determine total shards needed
  const maxNumber = 9999999999; // 10-digit mobile number
  const totalShards = Math.ceil((maxNumber + 1) / shardSize);

  explain(
    `Total shards: ${totalShards} assuming max mobile number is ${maxNumber}`
  );

  // Mark existing numbers as 1 (present)
  for (const mobileNumber of mobileNumbers) {
    const shardIndex = shardIndexOf(mobileNumber);

    explain(
      `Storing mobile number ${mobileNumber} in shard ${shardIndex} at index ${indexInShardOf(
        mobileNumber
      )}.`,
      2
    );

    insertMobileNumberInShards(shards, mobileNumber);
  }
}

/**
 * Process a query for a mobile number server-side. Receives both the shard
 * index and an encrypted query from the client. The query is received
 * encrypted, and the server has no-way of decrypting it. Instead, it does
 * a homomorphic multiplication operation with the database shard. The result
 * is a byte array with 0s and 1s, where 1 means the number exists in the
 * shard at that particular position.
 *
 * As an example, let's assume shardSize = 20, and we have to query for a mobile number
 * 9846819005. The shard index would be 492340950, and the query would be a byte array
 * with a 1 at index 5, and all other indices as 0, i.e:
 *
 * 492340950: Uint8Array(20) [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
 *
 * Now let's assume that the server has three mobile numbers in the shard in total:
 * 9846819001, 9846819002, and our queried shard (9846819005). On the server-end the shard will look like:
 *
 * 492340950: Uint8Array(20) [ 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
 *
 * Now multiplying these 0s and 1s in these two shards in order, we will get:
 *
 * 492340950: Uint8Array(20) [ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
 *
 * i.e. an array with a 1 at index 5, which means the number exists in the shard. If the mobile number did
 * not exist, we will get an array with all 0s.
 *
 * Note that these operations are done on encrypted data, and the server never decrypts the data, so the
 * server DOES NOT KNOW the mobile number that was queried for, only the shard index, from which it can
 * only guess that the mobile number was one of the numbers in the shard.
 *
 * The result of the query is sent back to the client encrypted, and it is the client
 * that decrypts it (using its secret key).
 *
 * @param shardIndex The shard index where the number resides.
 * @param encryptedQuery The encrypted query to process.
 * @returns The encrypted result of the query as a Uint8Array or false (if the shard is empty).
 */
function processShardQuery(shardIndex: number, encryptedArray: Uint8Array) {
  const encryptedQuery = seal.CipherText();
  encryptedQuery.loadArray(context, encryptedArray);
  explain(`Processing encrypted shard query, shardIndex: ${shardIndex}`, 2);

  const evaluator = seal.Evaluator(context);
  const result = seal.CipherText();

  // Server data is stored unencrypted, so we can multiply it directly
  evaluator.multiplyPlain(encryptedQuery, shardAsPlainText(shardIndex), result);

  const resultArray = result.saveArray();
  explain("Homomorphic multiplication done");
  explain(`Multiplied array ${resultArray}`, 3);

  evaluator.delete();
  result.delete();

  return resultArray;
}

/**
 * Returns a shard as a Uint8Array.
 *
 * @param shardIndex The index of the shard to return.
 * @returns The shard value as a seal PlainText structure.
 */
function shardAsPlainText(shardIndex) {
  let shard = getShard(shardIndex);

  /**
   * If the shard doesn't exist, we create a new one with all 0s.
   * Except, SEAL doesn't like it as it has inbuilt protection for
   * homomorphic operations that result in transparent ciphertexts
   * (ciphertexts whose underlying plaintext is known). So we increase
   * the shardSize by 1 and set the last element to 1.
   *
   * The client will normalize the data received and only extract the
   * relevantSlice from 0...shardSize, and will ignore this set bit.
   * This lets us preserve the interfaces as such.
   *
   * To see this error in action, uncomment the `shard[shardSize] = 1;`
   * line below.
   */
  if (!shard) {
    explain("Shard does not exist, creating an empty one.", 1);
    shard = new Uint8Array(shardSize + 1);
    shard[shardSize] = 1;
  }

  explain(`Shard contents: ${shard.slice(0, shardSize)}`, 2);

  const batchEncoder = seal.BatchEncoder(context);
  const result = seal.PlainText();
  batchEncoder.encode(Uint32Array.from(shard), result);

  batchEncoder.delete();

  return result;
}

/**
 * Inserts a mobile number in the appropriate position in the shard.
 * We use shardIndexOf and indexInShardOf to determine the position.
 * This acts like a bloom filter: if the number is present, we mark it
 * the appropriate position with 1, otherwise it's initialized to 0.
 *
 * We try to do this in a sparse manner, so we only create shards when
 * necessary.
 *
 * @param shards
 * @param mobileNumber
 */
function insertMobileNumberInShards(shards, mobileNumber: number) {
  const shardIndex = shardIndexOf(mobileNumber);
  const indexInShard = indexInShardOf(mobileNumber);

  createShardIfEmpty(shardIndex);

  const shard = getShard(shardIndex);

  // shard! because we just created the shard above.
  shard![indexInShard] = 1;
}

/**
 * Creates and initializes a shard if it doesn't exist.
 * We just populate the shard with 0s by initializing it with a Uint8Array.
 *
 * @param shardIndex
 */
function createShardIfEmpty(shardIndex) {
  if (!shards.has(shardIndex)) {
    shards.set(shardIndex, new Uint8Array(shardSize));
  }
}

/**
 * Get the shard at the specified index, safely. If the shard doesn't exist,
 * we throw an error.
 *
 * @param shardIndex The shard index to retrieve.
 *
 * @returns The shard as a Uint8Array.
 */
function getShard(shardIndex: number) {
  const shard = shards.get(shardIndex);

  return shard;
}

export { shardCount, initializeDatabase, processShardQuery };
