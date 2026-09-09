/* Scene-free vocabulary shared by several specs: definitions that name no contract, alias, `methods` entry,
 * ghost or Solidity type, so a spec can import it whatever its scene. It declares nothing else, and an
 * importer neither redeclares nor `override`s a name from it. A bound here is tied to the `loop_iter` or
 * `hashing_length_bound` of each conf that uses it; the importing spec states how. */

definition SEL_TRANSFER() returns bytes4 = to_bytes4(0xa9059cbb);
definition SEL_TRANSFER_FROM() returns bytes4 = to_bytes4(0x23b872dd);
definition SEL_APPROVE() returns bytes4 = to_bytes4(0x095ea7b3);

// `_decodeSelector` reverts `InvalidSelector` for 1-3 bytes (PolicyEngine.sol:247-255).
definition badLen(bytes d) returns bool = d.length > 0 && d.length < 4;

// Longest `bytes` a rule calling a policy's `configure` admits.
definition CFG_MAX_BYTES() returns mathint = 256;

