use anchor_lang::prelude::*;

declare_id!("Vuln11111111111111111111111111111111111111");

#[program]
pub mod vulnerable_signer {
    use super::*;

    /// VULNERABILITY: Missing Signer Check
    /// 
    /// This instruction allows anyone to withdraw from the vault because it doesn't
    /// verify that the `authority` account actually signed the transaction.
    /// 
    /// ATTACK SCENARIO:
    /// 1. Alice creates a vault and deposits 1000 tokens
    /// 2. Mallory creates a transaction calling `withdraw`
    /// 3. Mallory passes Alice's public key as the `authority` parameter
    /// 4. The instruction doesn't check if Alice signed, so it succeeds
    /// 5. Mallory drains Alice's vault without permission
    /// 
    /// WHY THIS IS DANGEROUS:
    /// - Solana validates that signatures exist on a transaction
    /// - But it doesn't validate which accounts signed
    /// - Programs must explicitly check if required accounts are signers
    /// 
    /// REAL-WORLD IMPACT:
    /// - Wormhole Bridge hack (Feb 2022): $320M stolen due to missing signature checks
    /// - Multiple DeFi protocols have lost funds to this vulnerability
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // CRITICAL VULNERABILITY: No check if authority signed!
        // We're trusting that the caller passed the correct authority
        // But we're not verifying they have permission to act as that authority
        
        // This check only verifies the authority matches what's stored
        // It does NOT verify that authority actually signed the transaction
        require!(
            vault.authority == ctx.accounts.authority.key(),
            ErrorCode::InvalidAuthority
        );

        // Perform the withdrawal without signature verification
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;

        msg!("Withdrawn {} tokens from vault", amount);
        Ok(())
    }

    /// Initialize a new vault
    /// This function is secure - included for context
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        msg!("Initialized vault with authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit tokens into the vault
    /// This function is secure - included for context
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        msg!("Deposited {} tokens to vault", amount);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT VALIDATION STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// VULNERABILITY: This should be `Signer<'info>` not `AccountInfo<'info>`
    /// 
    /// Using AccountInfo means we accept any account, regardless of whether
    /// it signed the transaction. This is the root cause of the vulnerability.
    /// 
    /// WHAT AN ATTACKER DOES:
    /// - Creates a transaction with their own signature
    /// - Passes the victim's public key as `authority`
    /// - Program accepts it because AccountInfo doesn't verify signatures
    /// CHECK: This account should be a Signer but isn't - VULNERABILITY!
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>, // This is correct - signer required for init
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // Anyone can deposit, so no signer check needed here
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[account]
pub struct Vault {
    /// The authority that can withdraw from this vault
    pub authority: Pubkey,
    /// Current token balance in the vault
    pub balance: u64,
}

impl Vault {
    pub const LEN: usize = 32 + // authority
                           8;   // balance
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("The provided authority does not match the vault authority")]
    InvalidAuthority,
    
    #[msg("Insufficient funds in vault for withdrawal")]
    InsufficientFunds,
    
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
}

// ============================================================================
// EXPLOITATION EXAMPLE (FOR TESTING)
// ============================================================================

#[cfg(test)]
mod exploit_test {
    use super::*;
    
    /// This test demonstrates how an attacker can exploit the missing signer check
    /// 
    /// ATTACK FLOW:
    /// 1. Alice initializes a vault and deposits 1000 tokens
    /// 2. Mallory (attacker) creates her own transaction
    /// 3. Mallory calls withdraw() and passes Alice's pubkey as authority
    /// 4. Program checks if Alice's pubkey matches vault.authority - it does!
    /// 5. Program does NOT check if Alice actually signed - she didn't!
    /// 6. Withdrawal succeeds and Mallory steals Alice's funds
    #[test]
    fn test_exploit_missing_signer() {
        // Setup: Alice's vault with 1000 tokens
        // Exploit: Mallory withdraws without Alice's signature
        // Result: Theft succeeds because no signature verification
        
        // This is a pseudo-test showing the attack logic
        // In a real test, Mallory's transaction would succeed despite
        // Alice never signing anything
    }
}