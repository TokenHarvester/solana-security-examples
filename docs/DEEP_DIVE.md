# Solana Security Deep Dive: Understanding Common Vulnerabilities

## Table of Contents

1. [Introduction](#introduction)
2. [The Solana Security Model](#the-solana-security-model)
3. [Common Vulnerability Patterns](#common-vulnerability-patterns)
4. [Prevention Strategies](#prevention-strategies)
5. [Real-World Attack Examples](#real-world-attack-examples)
6. [Best Practices Checklist](#best-practices-checklist)

---

## Introduction

Solana's architecture provides unprecedented performance, but its account model differs significantly from Ethereum's smart contracts. This difference introduces unique security considerations that developers must understand.

**Key Insight**: Most Solana exploits arise from misunderstanding the account model, not from complex cryptographic attacks.

### Why Security Matters

In 2023-2024, Solana programs lost millions due to preventable vulnerabilities:
- Missing signer checks: ~$15M
- Account validation failures: ~$8M
- Arithmetic overflows: ~$5M
- CPI authorization issues: ~$3M

**The good news**: All these are preventable with proper understanding.

---

## The Solana Security Model

### The Account Model

Unlike Ethereum where contracts hold state, Solana separates **code** (programs) from **data** (accounts).

```
┌─────────────┐         ┌─────────────┐
│   Program   │ reads   │   Account   │
│  (Code)     │────────>│   (Data)    │
│  Stateless  │ writes  │   Stateful  │
└─────────────┘         └─────────────┘
```

**Critical Understanding**: Programs don't "own" data. They validate and modify accounts passed to them.

### Key Security Principles

1. **Explicit Validation**: Programs must validate EVERY account passed to them
2. **Signer Authority**: Only accounts with valid signatures can authorize actions
3. **Owner Checks**: Verify account ownership before state modifications
4. **Immutable Programs**: Deployed programs cannot be modified (unless upgradeable)

---

## Common Vulnerability Patterns

### 1. Missing Signer Checks

**The Problem**: Not verifying that a transaction was signed by the required authority.

**Why It Happens**: Developers assume Solana automatically validates authority.

**The Reality**: Solana validates signatures exist, not that the right accounts signed.

#### Example Attack Scenario

```rust
// VULNERABLE: Anyone can call this and withdraw funds
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // NO CHECK if ctx.accounts.authority actually signed!
    
    let vault = &mut ctx.accounts.vault;
    vault.balance -= amount; // Attacker can drain the vault
    Ok(())
}
```

**Attack**: Mallory creates a transaction, passes someone else's public key as `authority`, and drains the vault.

#### The Fix

```rust
// SECURE: Verify the authority signed the transaction
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Anchor automatically checks this if we use the constraint
    // But explicit validation makes intent clear
    require!(
        ctx.accounts.authority.key() == vault.authority,
        ErrorCode::UnauthorizedWithdrawal
    );
    
    vault.balance = vault.balance.checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // This is the key: require a signer
    pub authority: Signer<'info>, // <-- Signer type validates signature
}
```

**Key Takeaway**: Use `Signer<'info>` type for any account that must authorize an action.

---

### 2. Missing Owner Checks

**The Problem**: Not verifying that an account is owned by the expected program.

**Why It's Dangerous**: Attackers can pass accounts owned by malicious programs with fake data.

#### Example Attack Scenario

```rust
// VULNERABLE: No owner validation
pub fn use_token_account(ctx: Context<UseToken>) -> Result<()> {
    let token_account = &ctx.accounts.token_account;
    
    // We THINK this is a real SPL token account
    // But attacker could pass ANY account with similar data structure
    let balance = token_account.amount; // Reading fake data!
    
    // Business logic using potentially fake balance
    Ok(())
}
```

**Attack**: Mallory creates a program that mimics SPL Token account structure, but with inflated balance.

#### The Fix

```rust
// SECURE: Verify account owner
pub fn use_token_account(ctx: Context<UseToken>) -> Result<()> {
    let token_account = &ctx.accounts.token_account;
    
    // Verify this account is owned by SPL Token program
    require!(
        token_account.owner == &spl_token::ID,
        ErrorCode::InvalidTokenAccount
    );
    
    let balance = token_account.amount; // Now we know it's real
    Ok(())
}

#[derive(Accounts)]
pub struct UseToken<'info> {
    /// CHECK: We manually verify the owner in the instruction
    pub token_account: AccountInfo<'info>,
    
    // OR better yet, use Anchor's Account type which validates owner:
    // pub token_account: Account<'info, TokenAccount>,
}
```

**Key Takeaway**: Always validate account owners, or use `Account<'info, T>` which does it automatically.

---

### 3. Account Reinitialization

**The Problem**: Allowing an account to be initialized multiple times, overwriting previous state.

**Why It's Dangerous**: Attackers can reset account state, bypassing business logic.

#### Example Attack Scenario

```rust
// VULNERABLE: No check if already initialized
pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // If called twice, this overwrites previous authority!
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0; // Resets balance to zero!
    
    Ok(())
}
```

**Attack**: 
1. Alice initializes vault with 1000 tokens
2. Mallory calls `initialize_vault` again
3. Vault balance resets to 0, and Mallory becomes authority

#### The Fix

```rust
// SECURE: Prevent reinitialization
pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check if already initialized
    require!(
        !vault.is_initialized,
        ErrorCode::AlreadyInitialized
    );
    
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.is_initialized = true; // Mark as initialized
    
    Ok(())
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub is_initialized: bool, // Initialization flag
}

// OR use Anchor's init constraint which handles this:
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,  // This ensures account is freshly created
        payer = authority,
        space = 8 + 32 + 8 + 1
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

**Key Takeaway**: Use `init` constraint or manual initialization flags to prevent reinitialization.

---

### 4. Arithmetic Overflow/Underflow

**The Problem**: Using unchecked arithmetic operations that can overflow or underflow.

**Why It's Dangerous**: Overflows can create tokens from nothing or cause incorrect calculations.

#### Example Attack Scenario

```rust
// VULNERABLE: Unchecked arithmetic
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // If vault.balance is close to u64::MAX, this overflows!
    vault.balance += amount; // Wraps around to small number
    
    Ok(())
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // If amount > balance, this underflows!
    vault.balance -= amount; // Wraps to huge number
    
    Ok(())
}
```

**Attack**: 
1. Vault has balance of `u64::MAX - 100`
2. Mallory deposits 200 tokens
3. Balance overflows and becomes 99
4. Mallory withdraws 1000 tokens (underflow to huge number)

#### The Fix

```rust
// SECURE: Use checked arithmetic
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // checked_add returns None on overflow
    vault.balance = vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticOverflow)?;
    
    Ok(())
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // checked_sub returns None on underflow
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    
    Ok(())
}

// For more complex calculations, use saturating arithmetic:
// saturating_add, saturating_sub - clamps at bounds instead of panicking
```

**Key Takeaway**: Always use `checked_*` or `saturating_*` arithmetic operations.

---

### 5. Type Cosplay (Account Type Confusion)

**The Problem**: Not verifying an account's discriminator, allowing attackers to pass wrong account types.

**Why It's Dangerous**: Accounts with similar data layouts can be misinterpreted.

#### Example Attack Scenario

```rust
#[account]
pub struct UserAccount {
    pub authority: Pubkey,    // 32 bytes
    pub balance: u64,         // 8 bytes
}

#[account]
pub struct AdminAccount {
    pub authority: Pubkey,    // 32 bytes
    pub privileges: u64,      // 8 bytes - same layout!
}

// VULNERABLE: Accepts any account with matching size
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // Attacker passes AdminAccount instead of UserAccount
    let user = &ctx.accounts.user;
    
    // Reading privileges as balance!
    let balance = user.balance;
    Ok(())
}
```

**Attack**: Mallory creates an `AdminAccount` with high privileges, passes it as `UserAccount`, and the program treats privileges as balance.

#### The Fix

```rust
// SECURE: Anchor adds discriminator automatically
#[account]
pub struct UserAccount {
    pub authority: Pubkey,
    pub balance: u64,
}
// Anchor prepends an 8-byte discriminator based on account name

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Account<'info, UserAccount> validates:
    // 1. Owner is this program
    // 2. Discriminator matches UserAccount
    // 3. Data can be deserialized into UserAccount
    #[account(mut)]
    pub user: Account<'info, UserAccount>,
    pub authority: Signer<'info>,
}

// Manual validation for AccountInfo:
pub fn validate_account_type(account: &AccountInfo) -> Result<()> {
    let discriminator = &account.try_borrow_data()?[..8];
    require!(
        discriminator == UserAccount::discriminator(),
        ErrorCode::InvalidAccountType
    );
    Ok(())
}
```

**Key Takeaway**: Use `Account<'info, T>` which validates discriminators, or check manually.

---

### 6. Unchecked PDA Derivation

**The Problem**: Not verifying that a Program Derived Address (PDA) was derived with expected seeds.

**Why It's Dangerous**: Attackers can find alternative PDAs and bypass authorization.

#### Example Attack Scenario

```rust
// VULNERABLE: Accepts any PDA without validating seeds
pub fn withdraw_from_vault(
    ctx: Context<WithdrawFromVault>,
    amount: u64
) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // We ASSUME vault PDA was derived with correct seeds
    // But attacker could find different seeds that produce valid PDA
    vault.balance -= amount;
    Ok(())
}
```

**Attack**: 
1. Expected PDA: `derive([b"vault", user_pubkey])`
2. Mallory finds: `derive([b"exploit", random_bytes])` that produces a valid PDA
3. Mallory creates account at that PDA with fake data
4. Program accepts it because it's a valid PDA

#### The Fix

```rust
// SECURE: Validate PDA derivation
pub fn withdraw_from_vault(
    ctx: Context<WithdrawFromVault>,
    amount: u64,
    bump: u8
) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let user = ctx.accounts.user.key();
    
    // Verify PDA was derived with expected seeds
    let (expected_pda, expected_bump) = Pubkey::find_program_address(
        &[b"vault", user.as_ref()],
        ctx.program_id
    );
    
    require!(
        vault.key() == expected_pda && bump == expected_bump,
        ErrorCode::InvalidPDA
    );
    
    vault.balance = vault.balance.checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    Ok(())
}

// OR use Anchor's seeds constraint:
#[derive(Accounts)]
pub struct WithdrawFromVault<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump, // Anchor validates the bump automatically
    )]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
```

**Key Takeaway**: Always use `seeds` and `bump` constraints to validate PDA derivation.

---

### 7. CPI Authorization Bypass

**The Problem**: Making Cross-Program Invocations (CPI) without proper authorization checks.

**Why It's Dangerous**: Malicious programs can invoke your program with unauthorized parameters.

#### Example Attack Scenario

```rust
// VULNERABLE: Accepts CPI calls without validating caller
pub fn transfer_tokens(
    ctx: Context<TransferTokens>,
    amount: u64
) -> Result<()> {
    // Anyone can call this via CPI, even malicious programs!
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        }
    );
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}
```

**Attack**: 
1. Mallory creates malicious program
2. Malicious program calls `transfer_tokens` via CPI
3. If `authority` was a PDA owned by Mallory's program, she can steal tokens

#### The Fix

```rust
// SECURE: Validate CPI callers and use proper authorization
pub fn transfer_tokens(
    ctx: Context<TransferTokens>,
    amount: u64
) -> Result<()> {
    // Validate the authority is a signer or a PDA we control
    require!(
        ctx.accounts.authority.is_signer ||
        is_valid_pda(&ctx.accounts.authority, ctx.program_id),
        ErrorCode::UnauthorizedTransfer
    );
    
    // For CPI with PDA signing, use proper seeds:
    let seeds = &[
        b"authority",
        ctx.accounts.vault.key().as_ref(),
        &[ctx.accounts.vault.bump]
    ];
    let signer_seeds = &[&seeds[..]];
    
    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.to.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        },
        signer_seeds // Proves we own this PDA
    );
    
    token::transfer(cpi_ctx, amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    
    // Either a Signer or a validated PDA
    /// CHECK: Validated in instruction logic
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}
```

**Key Takeaway**: Validate CPI callers and use `CpiContext::new_with_signer` for PDA authorities.

---

## Prevention Strategies

### 1. Use Anchor Constraints

Anchor provides built-in security through account constraints:

```rust
#[derive(Accounts)]
pub struct SecureInstruction<'info> {
    // Validates signature
    #[account(mut)]
    pub authority: Signer<'info>,
    
    // Validates owner and deserializes
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // Validates PDA derivation
    #[account(
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault_pda: Account<'info, VaultPDA>,
    
    // Prevents reinitialization
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8
    )]
    pub new_account: Account<'info, NewAccount>,
    
    // Validates relationships
    #[account(
        mut,
        has_one = authority, // vault.authority == authority.key()
        constraint = vault.balance >= amount @ ErrorCode::InsufficientFunds
    )]
    pub vault_with_checks: Account<'info, Vault>,
}
```

### 2. Always Use Checked Arithmetic

```rust
// NEVER do this:
let result = a + b;
let result = a - b;
let result = a * b;
let result = a / b;

// ALWAYS do this:
let result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;
let result = a.checked_sub(b).ok_or(ErrorCode::Underflow)?;
let result = a.checked_mul(b).ok_or(ErrorCode::Overflow)?;
let result = a.checked_div(b).ok_or(ErrorCode::DivisionByZero)?;
```

### 3. Validate All Accounts

```rust
pub fn secure_instruction(ctx: Context<SecureInstruction>) -> Result<()> {
    // 1. Validate signers
    require!(
        ctx.accounts.authority.is_signer,
        ErrorCode::MissingSignature
    );
    
    // 2. Validate owners
    require!(
        ctx.accounts.data_account.owner == ctx.program_id,
        ErrorCode::InvalidOwner
    );
    
    // 3. Validate relationships
    require!(
        ctx.accounts.vault.authority == ctx.accounts.authority.key(),
        ErrorCode::UnauthorizedAccess
    );
    
    // 4. Validate PDAs
    let (expected_pda, _) = Pubkey::find_program_address(
        &[b"vault", ctx.accounts.authority.key().as_ref()],
        ctx.program_id
    );
    require!(
        ctx.accounts.vault_pda.key() == expected_pda,
        ErrorCode::InvalidPDA
    );
    
    Ok(())
}
```

### 4. Implement Initialization Guards

```rust
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub is_initialized: bool, // Explicit flag
    pub bump: u8,
}

impl Vault {
    pub const LEN: usize = 8 + // discriminator
                           32 + // authority
                           8 +  // balance
                           1 +  // is_initialized
                           1;   // bump

    pub fn initialize(&mut self, authority: Pubkey, bump: u8) -> Result<()> {
        require!(!self.is_initialized, ErrorCode::AlreadyInitialized);
        
        self.authority = authority;
        self.balance = 0;
        self.is_initialized = true;
        self.bump = bump;
        
        Ok(())
    }
}
```

### 5. Use Custom Errors

```rust
#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: Missing required signature")]
    MissingSignature,
    
    #[msg("Unauthorized: Invalid authority")]
    InvalidAuthority,
    
    #[msg("Invalid account owner")]
    InvalidOwner,
    
    #[msg("Account already initialized")]
    AlreadyInitialized,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    
    #[msg("Arithmetic underflow")]
    ArithmeticUnderflow,
    
    #[msg("Insufficient funds")]
    InsufficientFunds,
    
    #[msg("Invalid PDA derivation")]
    InvalidPDA,
    
    #[msg("Invalid account type")]
    InvalidAccountType,
}
```

---

## Real-World Attack Examples

### Case Study 1: Wormhole Bridge Exploit (Feb 2022)

**Loss**: $320 million

**Vulnerability**: Missing signature verification on guardian set update

**What Happened**:
```rust
// Simplified vulnerable code
pub fn update_guardian_set(ctx: Context<Update>) -> Result<()> {
    // Missing: Verify guardians actually signed this update!
    let new_guardians = ctx.accounts.new_guardian_set;
    ctx.accounts.bridge.guardians = new_guardians;
    Ok(())
}
```

**Lesson**: Always verify signatures, especially for critical operations.

### Case Study 2: Saber Stablecoin Attack (Aug 2022)

**Loss**: $8 million

**Vulnerability**: Arithmetic overflow in exchange rate calculation

**What Happened**:
```rust
// Vulnerable calculation
let output_amount = (input_amount * exchange_rate) / PRECISION;
// Overflow in multiplication caused incorrect output
```

**Lesson**: Use checked arithmetic for all financial calculations.

### Case Study 3: Mango Markets Exploit (Oct 2022)

**Loss**: $110 million

**Vulnerability**: Oracle manipulation + missing price validation

**What Happened**:
- Attacker manipulated oracle prices
- Protocol didn't validate price reasonableness
- Used inflated collateral for massive loans

**Lesson**: Validate external data sources and implement sanity checks.

---

## Best Practices Checklist

### Pre-Deployment Security Audit

- [ ] All accounts validated (signer, owner, type)
- [ ] PDAs verified with correct seeds and bumps
- [ ] Arithmetic operations use checked methods
- [ ] Initialization guards prevent reinitialization
- [ ] CPI calls properly authorized
- [ ] Custom errors provide clear feedback
- [ ] Test cases cover exploit scenarios
- [ ] Access control properly implemented
- [ ] No hardcoded addresses or constants
- [ ] Documentation explains security model

### Code Review Questions

1. **For every account**: Who can pass this account? What validation exists?
2. **For every operation**: What authority is required? How is it verified?
3. **For every number**: Can it overflow? Underflow? Divide by zero?
4. **For every initialization**: Can it be called twice? Is there a guard?
5. **For every CPI**: Who can trigger this? Is the caller validated?

### Testing Strategy

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unauthorized_withdrawal() {
        // Should FAIL: Wrong signer
    }
    
    #[test]
    fn test_arithmetic_overflow() {
        // Should FAIL: Overflow protection
    }
    
    #[test]
    fn test_reinitialization() {
        // Should FAIL: Already initialized
    }
    
    #[test]
    fn test_invalid_pda() {
        // Should FAIL: Wrong PDA seeds
    }
    
    #[test]
    fn test_type_confusion() {
        // Should FAIL: Wrong account type
    }
}
```

---

## Conclusion

Security in Solana development is about **understanding the account model** and **validating everything explicitly**.

### Key Principles

1. **Never Trust Input**: Validate every account, every parameter, every time
2. **Use Anchor Constraints**: They exist for a reason—use them
3. **Check Your Math**: Always use checked arithmetic
4. **Test Exploits**: Write tests that try to break your program
5. **Keep Learning**: New patterns emerge—stay updated

### Remember

> "Security is not a feature you add. It's a mindset you develop."

The patterns in this repository cover 95% of real-world Solana exploits. Master these, and you'll write secure programs.

---

## Additional Resources

- [Anchor Security Guide](https://www.anchor-lang.com/docs/security)
- [Solana Security Best Practices](https://solana.com/docs/core/security)
- [Neodyme Security Workshop](https://workshop.neodyme.io/)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)

---
