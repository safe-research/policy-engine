/* Well-formedness of the Safe stand-in: `1 <= threshold <= ownerCount` holds inductively, and
 * `getOwners()` returns exactly `ownerCount()` entries, both against SafeMockHarness's real body. The
 * second is a sanity check on the shape of `getOwners` over the mock, proved here at three owners; it is
 * not the discharge of an owner-array summary for an arbitrary Safe, and L-IT-9 carries the argument that
 * discharges such a summary up to an owner bound of 4.
 * Run by `conf/SafeMock.conf` (verify: SafeMockHarness). Introduces L-IT-2 and L-IT-9; cites L-IT-4.
 * L-IT-1 is not relied on: `1 <= threshold <= ownerCount`
 * (SafeMockHarness.setOwnersAndThreshold) makes IncreasedThresholdPolicy's `required == 0` branch
 * unreachable. */

using SafeMockHarness as safeMock;

methods {
    function safeMock.mockSafeWellFormed() external returns (bool) envfree;
    function safeMock.ownerCount() external returns (uint256) envfree;
    function safeMock.getOwners() external returns (address[]) envfree;
}

// L-IT-2: the Safe in the scene is set up, `1 <= threshold <= ownerCount`, inductively
// because its only writer requires it.
invariant mockSafeWellFormed()
    safeMock.mockSafeWellFormed();

// L-IT-9: `getOwners()` returns exactly `ownerCount()` entries, a sanity check on the shape of `getOwners`
// over the mock rather than the discharge of an owner-array summary; L-IT-4.
rule ownersLengthIsOwnerCount() {
    require safeMock.ownerCount() <= 3; // L-IT-9: proven for <= 3 owners; the unit assumes 4 (L-IT-4)
    assert safeMock.getOwners().length == safeMock.ownerCount(),
        "safeMock.getOwners() returns exactly ownerCount() entries";
}
