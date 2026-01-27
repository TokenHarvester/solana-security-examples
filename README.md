# Solana Security Examples: Vulnerable vs Secure Code Patterns

## Overview

This repository provides a comprehensive educational resource for Solana developers to understand common security vulnerabilities and their fixes. Each example contains:

- **Vulnerable Code**: A deliberately broken implementation demonstrating a security flaw
- **Secure Code**: The corrected version with proper security measures
- **Detailed Comments**: Inline explanations of what went wrong and how to fix it
- **Tests**: Demonstrations of exploits and their prevention

## Security Patterns Covered

1. **Missing Signer Checks** - Authority validation failures
2. **Missing Owner Checks** - Account ownership validation
3. **Account Reinitialization** - State manipulation attacks
4. **Arithmetic Overflow/Underflow** - Unsafe math operations
5. **Type Cosplay** - Account type confusion attacks
6. **Unchecked PDA Derivation** - Improper PDA validation
7. **CPI Authorization Bypass** - Cross-Program Invocation vulnerabilities

## Repository Structure

```
solana-security-examples/
├── examples/
│   ├── 01-missing-signer-check/
│   │   ├── vulnerable/
│   │   │   └── lib.rs
│   │   ├── secure/
│   │   │   └── lib.rs
│   │   └── README.md
│   ├── 02-missing-owner-check/
│   ├── 03-account-reinitialization/
│   ├── 04-arithmetic-overflow/
│   ├── 05-type-cosplay/
│   ├── 06-unchecked-pda/
│   └── 07-cpi-authorization/
├── docs/
│   └── DEEP_DIVE.md
├── tests/
└── README.md
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Solana CLI 1.18+
- Anchor Framework 0.30+

### Installation

```bash
# Clone the repository
git clone https://github.com/TokenHarvester/solana-security-examples.git
cd solana-security-examples

# Install dependencies
cargo build
```

### Running Examples

```bash
# Build all examples
anchor build

# Run tests for a specific example
cd examples/01-missing-signer-check
anchor test
```

## Learning Path

We recommend studying the examples in order:

1. Start with **Missing Signer Checks** - the most fundamental vulnerability
2. Progress to **Owner Checks** - understanding account ownership
3. Study **Account Reinitialization** - state management
4. Learn **Arithmetic Safety** - preventing overflow attacks
5. Understand **Type Cosplay** - account type validation
6. Master **PDA Derivation** - proper PDA validation
7. Complete with **CPI Authorization** - cross-program security

## Educational Resources

- [Deep Dive Article](docs/DEEP_DIVE.md) - Comprehensive security guide
- [Anchor Documentation](https://www.anchor-lang.com/docs)
- [Solana Security Best Practices](https://solana.com/docs)

## Why This Repository?

**Problem**: Most Solana exploits come from simple mistakes, not complex attacks.

**Solution**: Learn by seeing exactly what goes wrong and how to fix it.

**Approach**: Side-by-side vulnerable and secure code with detailed explanations.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

The vulnerable code examples are intentionally insecure for educational purposes. **Never use vulnerable patterns in production code.**

## 🔗 Additional Resources

- [Anchor Security Tips](https://www.anchor-lang.com/docs/security)
- [Solana Account Model](https://solana.com/docs/core/accounts)
- [Pinocchio Framework](https://github.com/anza-xyz/pinocchio)

---
