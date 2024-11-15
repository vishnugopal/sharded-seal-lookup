import { shardIndexOf, explain } from "./common";
import { shardCount, initializeDatabase, processShardQuery } from "./server";
import { createEncryptedQuery, decryptResult } from "./client";

explain("\nstep 1 (server): database initialization");
const inputDatabase = [9846819001, 9846819002, 9846819066];
initializeDatabase(inputDatabase);
explain(`Database initialized, shards: ${shardCount()}.`);

explain("\nstep 2 (client): create the query");
const mobileNumber = 9846819066;
const shardIndex = shardIndexOf(mobileNumber);
const query = createEncryptedQuery(mobileNumber);
explain(
  `Sent encrypted query to server with shardIndex: ${shardIndex} asking for ${mobileNumber}`
);

explain("\nstep 3 (server): process the query");
const encryptedResult = processShardQuery(shardIndex, query);
explain("Encrypted result after homomorphic multiply sent back to client");

explain("\nstep 4 (client): decrypt the result and print!");
const exists = encryptedResult ?? decryptResult(encryptedResult);
explain(`Key ${mobileNumber} present:`);
explain(exists ? "Yes" : "No");
