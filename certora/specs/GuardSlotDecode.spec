// GuardSlotDecode.spec: the decode pin of L-CFG-DECODE, the summary of SafePolicyGuard._readGuardSlot that the
// guard-slot gate and decode rules are stated under.
// Run by conf/GuardSlotDecode.conf.
//
// The subject is harnesses/GuardSlotDecodePin.sol, which holds the guard's decode copied byte for byte
// next to the function the summary computes. The scene is those two functions and nothing else, so the
// pointer analysis that gives up inside the guard (the cause L-CFG-DECODE cuts) has one small, allocation-free
// block to follow.
// File-wide: L-CFG-DECODE (the copy half: what is pinned here is a copy of the private function's
// decode, not the private function), L-W0-BITWISE.

methods {
    function decodeCopy(bool, bytes) external returns (address) envfree;
    function decodeModel(bool, bytes) external returns (address) envfree;
    function word3Of(bytes) external returns (uint256) envfree;
}

// R-CFG-10 (decode pin): on every answer of at most 160 bytes, success or failure, the guard's raw
// `mload` decode is exactly `(success && len >= 96) ? word3 & 0xff..ff : address(0)`, which is the
// function L-CFG-DECODE summarizes the probe by.
rule R_CFG_DECODE_pin(bool success, bytes returnData) {
    require returnData.length <= 160;
    assert decodeCopy(success, returnData) == decodeModel(success, returnData),
        "the raw mload decode equals (success && length >= 96) ? word3 & mask : address(0)";
}

// R-CFG-10 (decode pin, boundary half): the two answers the length test separates, stated as their own
// leaf so a regression that drops the test is a distinct failure.
rule R_CFG_DECODE_pin_len(bool success, bytes returnData) {
    require returnData.length <= 160;
    assert (!success || returnData.length < 96) => decodeCopy(success, returnData) == 0,
        "a failed call or an answer under 96 bytes decodes to address(0)";
    assert (success && returnData.length >= 96)
        => to_mathint(decodeCopy(success, returnData)) == word3Of(returnData) % 2^160,
        "a successful answer of at least 96 bytes decodes to word 3 masked to 160 bits";
}

// R-CFG-10 (decode pin, mask witness): the mask is reachable, that is, some answer has a dirty word 3
// that still decodes to its low 160 bits; without it R_CFG_DECODE_pin_len's second assert could hold on
// masked words alone.
rule W_CFG_DECODE_dirty(bool success, bytes returnData) {
    require returnData.length <= 160;
    satisfy success && returnData.length >= 96 && word3Of(returnData) >= 2^160
        && to_mathint(decodeCopy(success, returnData)) == word3Of(returnData) % 2^160;
}
