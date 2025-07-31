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
        self.precomputed[3] = 0x7f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        self.precomputed[4] = 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        self.precomputed[5] = 0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78;
        self.precomputed[6] = 0x78295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d;
        self.precomputed[7] = 0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61;
        self.precomputed[8] = 0xe884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747;
        self.precomputed[9] = 0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2;
        self.precomputed[10] = 0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636;
        self.precomputed[11] = 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a;
        self.precomputed[12] = 0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0;
        self.precomputed[13] = 0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c;
        self.precomputed[14] = 0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92;
        self.precomputed[15] = 0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323;
        self.precomputed[16] = 0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992;
        self.precomputed[17] = 0xf57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f;
        self.precomputed[18] = 0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca;
        self.precomputed[19] = 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e;
        self.precomputed[20] = 0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1;
        self.precomputed[21] = 0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52b;
        self.precomputed[22] = 0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538d;
        self.precomputed[23] = 0x27171fb4a97b6cc0e9e8f543b5294de866a2af2c9c8d0b1d96e673e4529ed540;
        self.precomputed[24] = 0x2ff6650540f629fd5711a0bc74fc0d28dcb230b9392583e5f8d59696dde6ae21;
        self.precomputed[25] = 0x120c58f143d491e95902f7f5277778a2e0ad5168f6add75669932630ce611518;
        self.precomputed[26] = 0x1f21feb70d3f21b07bf853d5e5db03071ec495a0a565a21da2d665d279483795;
        self.precomputed[27] = 0x24be905fa71335e14c638cc0f66a8623a826e768068a9e968bb1a1dde18a72d2;
        self.precomputed[28] = 0xf8666b62ed17491c50ceadead57d4cd597ef3821d65c328744c74e553dac26d;
        self.precomputed[29] = 0x918d46bf52d98b034413f4a1a1c41594e7a7a3f6ae08cb43d1a2a230e1959ef;
        self.precomputed[30] = 0x1bbeb01b4c479ecde76917645e404dfa2e26f90d0afc5a65128513ad375c5ff2;
        self.precomputed[31] = 0x2f68a1c58e257e42a17a6c61dff5551ed560b9922ab119d5ac8e184c9734ead9;
        
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