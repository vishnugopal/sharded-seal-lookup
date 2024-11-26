import { shardIndexOf, explain } from "./common";
import { shardCount, initializeDatabase, processShardQuery } from "./server";
import { createEncryptedQuery, decryptResult } from "./client";

explain("\nstep 1 (server): database initialization");
const inputDatabase = [
  9846819001, 9846819002, 9846819003, 9846819006, 9846819007,
];
initializeDatabase(inputDatabase);
explain(`Database initialized, shards: ${shardCount()}.`);

explain("\nstep 2 (client): create the query");
const mobileNumber = 8846819001;
const shardIndex = shardIndexOf(mobileNumber);
explain(
  `Making an encrypted query to send to the server with shardIndex: ${shardIndex} asking for ${mobileNumber}`
);
const query = createEncryptedQuery(mobileNumber);

explain("\nstep 3 (server): process the query");
const encryptedResult = processShardQuery(shardIndex, query);
explain("Encrypted result after homomorphic multiply sent back to client");

explain("\nstep 4 (client): decrypt the result and print!");
const exists = decryptResult(encryptedResult);
explain(`Key ${mobileNumber} present:`);
explain(exists ? "Yes" : "No");
