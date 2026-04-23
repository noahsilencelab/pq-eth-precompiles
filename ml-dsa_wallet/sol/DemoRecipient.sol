// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract DemoRecipient {
    string public note;
    uint256 public count;
    address public lastCaller;
    uint256 public lastValue;

    event NoteSet(address indexed caller, string note, uint256 value, uint256 count);

    function setNote(string calldata newNote) external payable {
        note = newNote;
        count += 1;
        lastCaller = msg.sender;
        lastValue = msg.value;
        emit NoteSet(msg.sender, newNote, msg.value, count);
    }
}
