// EngineCheckNative.spec: W-EC-1(h) alone, in its own spec and conf because the witness needs
// NativeTransferPolicy in the engine-to-policy DISPATCH list and a methods entry is per spec; adding it to
// EngineCheck.spec would change the closed scene of L-W0-2 for every iff row there. The witness confirms an
// accepted limitation: NativeTransferPolicy on the CALL fallback key permits any value > 0 to any to with
// any calldata, so a contract call and not only a plain ETH transfer. Conf: EngineCheckNative (L-W0-SENDER).

import "Common.spec";

using NativeTransferPolicy as nativeTransfer;

methods {
    function _.checkTransaction(address,address,uint256,bytes,SafePolicyGuardHarness.Operation,address,bytes,AccessSelector.T) external
        => DISPATCH [ NativeTransferPolicy._, MockPolicyHarness._ ] default NONDET;
    function _.configure(address,AccessSelector.T,bytes) external
        => DISPATCH [ NativeTransferPolicy._, MockPolicyHarness._ ] default NONDET;
}

// W-EC-1(h): with NativeTransferPolicy on P[s][fb(CALL)], the owner hook succeeds at value > 0 and a non-zero selector,
// for any to.
rule W_EC_1_h(env e, address to, uint256 value, bytes data, uint256 safeTxGas, uint256 baseGas,
              uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures,
              address msgSender) {
    require e.msg.sender != 0;
    SafePolicyGuardHarness.Operation op = lib.opCall();
    address s = e.msg.sender;
    require policyAt(s, exactKey(to, data, op)) == 0;
    require policyAt(s, fallbackKey(op)) == nativeTransfer;
    require value > 0 && data.length >= 4 && lib.selectorOf(data) != to_bytes4(0);
    checkTransaction(e, to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver,
        signatures, msgSender);
    satisfy checkingSafe() == 0 && to != 0;
}
