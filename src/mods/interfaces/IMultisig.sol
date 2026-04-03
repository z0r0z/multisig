// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

interface IMultisig {
    function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) external payable;
    function cancelQueued(bytes32 hash) external payable;
    function isOwner(address account) external view returns (bool);
    function threshold() external view returns (uint16);
    function ownerCount() external view returns (uint16);
    function getOwners() external view returns (address[] memory);
}
