
# VePPDA: Verifiable and Privacy-Preserving Dynamic Ascending Auctions on the Blockchain

> **Status**: Research Proof of Concept (PoC)  
> **Paper**: VePPDA: Verifiable and Privacy-Preserving Dynamic Ascending Auctions on the Blockchain

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.24-blue)](https://soliditylang.org)
[![Hardhat](https://img.shields.io/badge/Hardhat-3.0.0--beta.5-blue)](https://hardhat.org)

This repository contains the **Proof of Concept (PoC)** implementation for the academic paper **"VePPDA: Verifiable and Privacy-Preserving Dynamic Ascending Auctions on the Blockchain"**. It demonstrates a decentralized auction protocol achieving bid privacy and public verifiability via **Paillier homomorphic encryption** and **challenge-response mechanisms**.

---

## 🎯 Overview

VePPDA addresses privacy leakage and strategic manipulation in on-chain auctions. Unlike traditional sealed-bid auctions, VePPDA allows:
1.  **Privacy-Preserving Bidding**: Bids are encrypted using Paillier cryptosystem.
2.  **Public Verifiability**: Invalid bids can be challenged and proven via cryptographic proofs.
3.  **Dynamic Ascending Logic**: Supports iterative bidding rounds with privacy guarantees.

---

## 🏗️ System Architecture

The protocol is implemented in Solidity using a modular design:

```
contracts/
├── VePPDA_Main.sol          # Entry point & state management
├── VePPDA_Auction.sol       # Encrypted bidding logic
├── VePPDA_Settlement.sol    # Winner determination & price revelation
├── VePPDA_Dispute.sol       # Dispute resolution & arbitration
├── Verifier.sol             # Cryptographic proof verification
├── GlobalsStruct.sol        # Shared data structures
└── BigNumbers.sol           # Large integer arithmetic for Paillier
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js ≥ 18.x
- npm/yarn

### Installation & Deployment

```bash
# Clone & Install
git clone https://github.com/windxun222/VePPDA.git
cd VePPDA
npm install

# Compile
npx hardhat compile

# Test
npx hardhat test

```

*Note: As a research PoC, gas optimization and mainnet security audits are out of scope.*

---

## 🔐 Security & Limitations

- **Cryptographic Assumptions**: Relies on the Decisional Composite Residuosity Assumption (DCRA) for Paillier security.
- **PoC Status**: This implementation is for research demonstration. **Do not use with real value** without a professional security audit.

---
