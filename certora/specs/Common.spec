/* Shared vocabulary for the specs that verify `SafePolicyGuardHarness` and import it. A conf importing it must
 * list LibHarness, SafeMockHarness and MockPolicyHarness in `files`. Importing forces no DISPATCH list and no
 * policy set, so the engine to policy CALL keeps its AUTO default (D-008) unless an importer adds a
 * per-signature DISPATCH list (D-009). Introduces L-W0-LOOP and D-007. */

import "Vocabulary.spec";

using LibHarness as lib;
using SafeMockHarness as safeMock;
using MockPolicyHarness as mockPolicy;

// Read from the scene policy's ABI so the magic value is the compiler's, not the literal 0xcbd11d55
// (PolicyEngine.sol:202).
definition MAGIC() returns bytes4 = to_bytes4(
    sig:mockPolicy.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T).selector
);

// Guard configuration entry points: the first three sit inside `_allowedCalls` (SafePolicyGuard.sol:186,192),
// `configureImmediately` (:341) outside it.
definition SEL_REQUEST_CONFIGURATION() returns bytes4 = to_bytes4(sig:requestConfiguration(bytes32).selector);
definition SEL_APPLY_CONFIGURATION() returns bytes4 = to_bytes4(sig:applyConfiguration(SafePolicyGuard.Configuration[]).selector);
definition SEL_INVALIDATE_ROOT() returns bytes4 = to_bytes4(sig:invalidateRoot(bytes32).selector);
definition SEL_CONFIGURE_IMMEDIATELY() returns bytes4 = to_bytes4(sig:configureImmediately(SafePolicyGuard.Configuration[]).selector);

// `IPolicy.configure`, the one policy-decoded selector declared here.
definition SEL_CONFIGURE() returns bytes4 = to_bytes4(0xda0b9a55);

// `_decodeSelector` reverts `InvalidSelector` for 1-3 bytes (PolicyEngine.sol:247-255).
// badLen is declared in Vocabulary.spec.

// `CALL`/`DELEGATECALL` are reserved CVL tokens, so the two {Operation} values are read through
// LibHarness; the packed access-selector word is not, CVL modelling `AccessSelector.T` as its
// underlying `uint256`, so `==` on the type and `to_mathint` on it are the raw readers.

definition checkingSafe() returns address = currentContract.$checkingSafe;
definition checkingModule() returns address = currentContract.$checkingModule;

// D-007: the sentinels and the UDVT-keyed policy mapping are private (PolicyEngine.sol:24,35,46), so they are read by
// direct storage access.
definition policyAt(address safe, AccessSelector.T key) returns address = currentContract.$policies[safe][key];

methods {
    function DELAY() external returns (uint256) envfree;
    function rootConfigured(address, bytes32) external returns (uint256) envfree;
    function getPolicy(address, address, bytes, SafePolicyGuardHarness.Operation) external returns (AccessSelector.T, address) envfree;

    function CONTEXT_TYPE_HASH() external returns (bytes32) envfree;
    function GUARD_STORAGE_SLOT() external returns (bytes32) envfree;
    function MODULE_GUARD_STORAGE_SLOT() external returns (bytes32) envfree;
    function allowedCalls(address, uint256, bytes, SafePolicyGuardHarness.Operation) external returns (bool) envfree;
    function decodeSelector(bytes) external returns (bytes4) envfree;
    function decodeContext(bytes) external returns (bytes) envfree;
    function exactKey(address, bytes, SafePolicyGuardHarness.Operation) external returns (AccessSelector.T) envfree;
    function fallbackKey(SafePolicyGuardHarness.Operation) external returns (AccessSelector.T) envfree;
    function configurationRoot(SafePolicyGuard.Configuration[]) external returns (bytes32) envfree;
    function configTarget(SafePolicyGuard.Configuration[], uint256) external returns (address) envfree;
    function configSelector(SafePolicyGuard.Configuration[], uint256) external returns (bytes4) envfree;
    function configOperation(SafePolicyGuard.Configuration[], uint256) external returns (SafePolicyGuardHarness.Operation) envfree;
    function configPolicy(SafePolicyGuard.Configuration[], uint256) external returns (address) envfree;
    function configDataLength(SafePolicyGuard.Configuration[], uint256) external returns (uint256) envfree;
    function configDataHash(SafePolicyGuard.Configuration[], uint256) external returns (bytes32) envfree;
    function configKey(SafePolicyGuard.Configuration[], uint256) external returns (AccessSelector.T) envfree;
    function keccak(bytes) external returns (bytes32) envfree;
    // `tryCheck(...)` makes external calls: not envfree, so its rules pass an env.

    function lib.create(address, bytes4, SafePolicyGuardHarness.Operation) external returns (AccessSelector.T) envfree;
    function lib.createFallback(SafePolicyGuardHarness.Operation) external returns (AccessSelector.T) envfree;
    function lib.getTarget(AccessSelector.T) external returns (address) envfree;
    function lib.getSelector(AccessSelector.T) external returns (bytes4) envfree;
    function lib.getOperation(AccessSelector.T) external returns (SafePolicyGuardHarness.Operation) envfree;
    function lib.opCall() external returns (SafePolicyGuardHarness.Operation) envfree;
    function lib.opDelegateCall() external returns (SafePolicyGuardHarness.Operation) envfree;
    function lib.has(bytes, bytes32) external returns (bool) envfree;
    function lib.payload(bytes, bytes32) external returns (bytes) envfree;
    function lib.payloadLength(bytes, bytes32) external returns (uint256) envfree;
    function lib.payloadHash(bytes, bytes32) external returns (bytes32) envfree;
    function lib.tailWord(bytes) external returns (bytes32) envfree;
    function lib.lengthWord(bytes) external returns (uint256) envfree;
    function lib.selectorOf(bytes) external returns (bytes4) envfree;
    function lib.wordAt(bytes, uint256) external returns (uint256) envfree;

    function safeMock.nonce() external returns (uint256) envfree;
    function safeMock.ownerCount() external returns (uint256) envfree;
    function safeMock.getThreshold() external returns (uint256) envfree;
    function safeMock.mockSafeWellFormed() external returns (bool) envfree;
    function safeMock.getStorageAt(uint256, uint256) external returns (bytes) envfree;
    // `getTransactionHash`/`domainSeparator` read `chainid()`: pass an env.

    function mockPolicy.checkMode() external returns (MockPolicyHarness.CheckMode) envfree;
    function mockPolicy.configureMode() external returns (MockPolicyHarness.ConfigureMode) envfree;
    function mockPolicy.configCall() external returns (MockPolicyHarness.ConfigCall) envfree;
    function mockPolicy.wrongMagic() external returns (bytes4) envfree;
    function mockPolicy.revertCode() external returns (uint256) envfree;
    function mockPolicy.reenterSafe() external returns (address) envfree;
    function mockPolicy.reenterTo() external returns (address) envfree;
    function mockPolicy.reenterValue() external returns (uint256) envfree;
    function mockPolicy.reenterOperation() external returns (SafePolicyGuardHarness.Operation) envfree;
    function mockPolicy.reenterModule() external returns (address) envfree;
    function mockPolicy.reenterDataSkip() external returns (uint256) envfree;
    function mockPolicy.reenterContextSkip() external returns (uint256) envfree;
    function mockPolicy.reenterRoot() external returns (bytes32) envfree;
    function mockPolicy.cfgTarget() external returns (address) envfree;
    function mockPolicy.cfgSelector() external returns (bytes4) envfree;
    // Commented out with the rule that used it.
    // function mockPolicy.cfgOperation() external returns (SafePolicyGuardHarness.Operation) envfree;
    function mockPolicy.cfgPolicy() external returns (address) envfree;
    function mockPolicy.primedRoot() external returns (bytes32) envfree;
    function mockPolicy.depth() external returns (uint256) envfree;
    function mockPolicy.innerCalled() external returns (bool) envfree;
    function mockPolicy.innerReverted() external returns (bool) envfree;
    function mockPolicy.innerErrorSelector() external returns (bytes4) envfree;
    function mockPolicy.innerErrorLength() external returns (uint256) envfree;
    function mockPolicy.innerReturnedPolicy() external returns (address) envfree;
    function mockPolicy.calls() external returns (uint256) envfree;
    function mockPolicy.invSender(uint256) external returns (address) envfree;
    function mockPolicy.invSafe(uint256) external returns (address) envfree;
    function mockPolicy.invTo(uint256) external returns (address) envfree;
    function mockPolicy.invValue(uint256) external returns (uint256) envfree;
    function mockPolicy.invDataHash(uint256) external returns (bytes32) envfree;
    function mockPolicy.invDataLength(uint256) external returns (uint256) envfree;
    function mockPolicy.invOperation(uint256) external returns (SafePolicyGuardHarness.Operation) envfree;
    function mockPolicy.invModule(uint256) external returns (address) envfree;
    function mockPolicy.invContextHash(uint256) external returns (bytes32) envfree;
    function mockPolicy.invContextLength(uint256) external returns (uint256) envfree;
    function mockPolicy.invAccess(uint256) external returns (AccessSelector.T) envfree;
    function mockPolicy.configureCalls() external returns (uint256) envfree;
    function mockPolicy.lastConfigureSender() external returns (address) envfree;
    function mockPolicy.lastConfigureSafe() external returns (address) envfree;
    function mockPolicy.lastConfigureAccess() external returns (AccessSelector.T) envfree;
    function mockPolicy.lastConfigureDataLength() external returns (uint256) envfree;
    function mockPolicy.lastConfigureDataHash() external returns (bytes32) envfree;
    function mockPolicy.observedRootValue() external returns (uint256) envfree;
}

