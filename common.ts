import SEAL from "node-seal";

/**
 * node-seal has a pretty non-standard way to initialze.
 */
const seal = await SEAL();

/**
 * We construct the context once, and re-use.
 */
const context = getSealContext();

/**
 * This is the shard size (the number of values that will be stored together). These
 * number of results will also be returned by the server.
 *
 * The maximum value for this is the polyModulusDegree (see getEncryptionConstants)
 */
const shardSize = 20;

/**
 * Sets various rqeuired homomorphic encryption constants.
 *
 * @returns The encryption constants for the database
 */
function getEncryptionConstants() {
  const polyModulusDegree = 4096;
  const coeffModulusBitSizes = [36, 36, 37];
  const plainModulusBitSize = 20;
  return { polyModulusDegree, coeffModulusBitSizes, plainModulusBitSize };
}

/**
 * Constructs a SEAL context with the encryption parameters.
 *
 * @returns The SEAL context for the encryption parameters
 */
function getSealContext() {
  const { polyModulusDegree, coeffModulusBitSizes, plainModulusBitSize } =
    getEncryptionConstants();

  // Set encryption parameters
  const schemeType = seal.SchemeType.bfv;
  const parms = seal.EncryptionParameters(schemeType);

  parms.setPolyModulusDegree(polyModulusDegree); // Optimized for shard size
  parms.setCoeffModulus(
    seal.CoeffModulus.Create(
      polyModulusDegree,
      Int32Array.from(coeffModulusBitSizes)
    )
  );
  parms.setPlainModulus(
    seal.PlainModulus.Batching(polyModulusDegree, plainModulusBitSize)
  );

  const context = seal.Context(parms, true, seal.SecurityLevel.tc128);

  if (!context.parametersSet()) {
    throw new Error("Invalid encryption parameters.");
  }

  return context;
}

/**
 * To facilitate faster homomorphic encryption operations, we split the database into shards.
 * It's easy (for both the server and the client) to calculate the shard index, and this is
 * a helper function to do so.
 *
 * @param mobileNumber The mobile number to calculate the shard index for.
 * @returns The shard index.
 */
function shardIndexOf(mobileNumber: number) {
  return Math.floor(mobileNumber / shardSize);
}

/**
 * To facilitate faster homomorphic encryption operations, we split the database into shards.
 * It's easy (for both the server and the client) to calculate the index of the mobile number
 * in a shard, and this is a helper function to do so.
 *
 * @param mobileNumber The mobile number to calculate the index of the mobile number in the shard.
 * @returns The index of the mobile number in the shard.
 */
function indexInShardOf(mobileNumber: number) {
  return mobileNumber % shardSize;
}

/**
 * If you set an EXPLAIN environment variable, this function will print out the text.
 * Used for providing more detailed explanations throughout the code. Set EXPLAIN to higher
 * values (2, 3) for more detailed walkthroughs of everything happening.
 */
function explain(text, explainLevel = 1) {
  const explainLevelFromEnv = parseInt(process.env.EXPLAIN || "0");

  if (explainLevelFromEnv < explainLevel) {
    return;
  }

  console.log(text);
}

export {
  seal,
  context,
  shardSize,
  shardIndexOf,
  indexInShardOf,
  getEncryptionConstants,
  explain,
};
