/* Scene-free vocabulary shared by several specs: definitions that name no contract, alias, `methods` entry,
 * ghost or Solidity type, so a spec can import it whatever its scene. It declares nothing else, and an
 * importer neither redeclares nor `override`s a name from it. A bound here is tied to the `loop_iter` or
 * `hashing_length_bound` of each conf that uses it; the importing spec states how. */

// `_decodeSelector` reverts `InvalidSelector` for 1-3 bytes (PolicyEngine.sol:247-255).
definition badLen(bytes d) returns bool = d.length > 0 && d.length < 4;

