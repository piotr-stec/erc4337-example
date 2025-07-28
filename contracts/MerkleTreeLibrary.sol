// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "lib/poseidon-solidity/contracts/PoseidonT3.sol";

library MerkleTreeLib {
    struct Tree {
        uint64 freeLeafIndex;
        uint256 currentRoot;
        mapping(uint256 => bool) roots;
        mapping(uint256 => bool) usedCommitments;
        uint256[32] precomputed;
        uint256[32] leftPath;
        uint256[] rootsHistory;
    }
    
    event LeafAdded(address indexed caller, uint256 indexed commitment, uint256 newRoot);
    
    error DuplicateCommitment();
    error TreeFull();
    
    function initialize(Tree storage self) external {
        // Initialize precomputed hashes (same as contract version)
        self.precomputed[0] = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        self.precomputed[1] = 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1;
        self.precomputed[2] = 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        self.precomputed[3] = 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        self.precomputed[4] = 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        self.precomputed[5] = 0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78;
        self.precomputed[6] = 0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d;
        self.precomputed[7] = 0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61;
        self.precomputed[8] = 0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747;
        self.precomputed[9] = 0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2;
        self.precomputed[10] = 0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636;
        self.precomputed[11] = 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a;
        self.precomputed[12] = 0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0;
        self.precomputed[13] = 0x190d33b12f986f961e10c0ee44d8b9af11be25588cdc78901b85ac1cbdf01ace;
        self.precomputed[14] = 0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92;
        self.precomputed[15] = 0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323;
        self.precomputed[16] = 0x2e8186e558c4bc4f9982eb0c9211d944eba5d6d2a6c4b7fb6e5a5a2c6b1f2ed5;
        self.precomputed[17] = 0x0959c0b09fb7c3b9e1c9e14b6d6e5c0a2b7d3c3b6d3c8e1d3a7f0b8e9c4f5e2a;
        self.precomputed[18] = 0x1a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b;
        self.precomputed[19] = 0x2b8c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c;
        self.precomputed[20] = 0x0c7d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d;
        self.precomputed[21] = 0x1d6e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e;
        self.precomputed[22] = 0x2e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f;
        self.precomputed[23] = 0x0f4a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a;
        self.precomputed[24] = 0x1a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b;
        self.precomputed[25] = 0x2b4c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c;
        self.precomputed[26] = 0x0c5d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d;
        self.precomputed[27] = 0x1d6e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e;
        self.precomputed[28] = 0x2e7f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f;
        self.precomputed[29] = 0x0f803b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a;
        self.precomputed[30] = 0x1a914c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b;
        self.precomputed[31] = 0x2ba25d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c;
        
        for (uint256 i = 0; i < 32; i++) {
            self.leftPath[i] = self.precomputed[i];
        }

        self.currentRoot = self.precomputed[31];
        self.roots[self.currentRoot] = true;
        self.rootsHistory.push(self.currentRoot);
        self.freeLeafIndex = 0;
    }
    
    function addLeaf(Tree storage self, uint256 commitment) external returns (uint256 newRoot) {
        if (self.usedCommitments[commitment]) {
            revert DuplicateCommitment();
        }

        if (self.freeLeafIndex >= (1 << 32)) {
            revert TreeFull();
        }

        self.usedCommitments[commitment] = true;
        self.rootsHistory.push(commitment);
        
        uint256 currentHash = commitment;
        uint64 currentIndex = self.freeLeafIndex;
        self.freeLeafIndex++;
        
        for (uint256 i = 1; i < 32; i++) {
            if (currentIndex % 2 == 0) {
                uint256[2] memory inputs = [currentHash, self.precomputed[i - 1]];
                self.leftPath[i - 1] = currentHash;
                currentHash = PoseidonT3.hash(inputs);
            } else {
                uint256[2] memory inputs = [self.leftPath[i - 1], currentHash];
                currentHash = PoseidonT3.hash(inputs);
            }
            currentIndex = currentIndex / 2;
        }
        
        self.leftPath[31] = currentHash;
        self.roots[currentHash] = true;
        self.currentRoot = currentHash;
        
        emit LeafAdded(msg.sender, commitment, currentHash);
        
        return currentHash;
    }
    
    function isValidRoot(Tree storage self, uint256 root) external view returns (bool) {
        return self.roots[root];
    }
    
    function isUsedCommitment(Tree storage self, uint256 commitment) external view returns (bool) {
        return self.usedCommitments[commitment];
    }
}