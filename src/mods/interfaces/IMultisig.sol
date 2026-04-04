// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

interface IMultisig {
    function nonce() external view returns (uint32);
    function threshold() external view returns (uint16);
    function ownerCount() external view returns (uint16);
    function isOwner(address account) external view returns (bool);
    function approved(address owner, bytes32 hash) external view returns (bool);
    function cancelQueued(bytes32 hash) external payable;
    function getTransactionHash(address target, uint256 value, bytes calldata data, uint32 _nonce)
        external
        view
        returns (bytes32);
    function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) external payable;
}
