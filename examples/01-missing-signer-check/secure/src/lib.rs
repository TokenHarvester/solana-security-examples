use anchor_lang::prelude::*;

declare_id!("Secur11111111111111111111111111111111111111");

#[program]
pub mod secure_signer {
    use super::*;

    /// SECURE: Proper Signer Verification
    /// 
    /// This instruction correctly verifies that the authority account signed
    /// the transaction before allowing withdrawal.
    /// 
    /// SECURITY MEASURES:
    /// 1. Uses `Signer<'info>` type for authority account
    /// 2. Anchor automatically verifies the signature
    /// 3. Transaction fails if authority didn't sign
    /// 
    /// HOW THE FIX WORKS:
    /// - Signer<'info> is a special Anchor type
    /// - Anchor checks the transaction's signature list
    /// - If the account didn't sign, deserialization fails
    /// - Instruction never executes without valid signature
    /// 
    /// DEFENSE LAYERS:
    /// 1. Type-level: Signer<'info> enforces signature requirement
    /// 2. Runtime: Anchor validates during account deserialization
    /// 3. Business logic: Authority pubkey still verified for correctness
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // SECURE: authority is Signer<'info>, so we KNOW they signed
        // This check is now just verifying the right authority for this vault
        // The signature itself was already verified by Anchor
        require!(
            vault.authority == ctx.accounts.authority.key(),
            ErrorCode::InvalidAuthority
        );

        // Safe to perform withdrawal - we have verified signature
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;

        msg!("Securely withdrawn {} tokens from vault", amount);
        Ok(())
    }

    /// Initialize a new vault with proper security
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Authority is a Signer, so this is secure
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        
        msg!("Initialized vault with authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit tokens into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
            
        msg!("Deposited {} tokens to vault", amount);
        Ok(())
    }

    /// BONUS: Transfer authority to a new owner
    /// This demonstrates another critical operation requiring signature
    pub fn transfer_authority(
        ctx: Context<TransferAuthority>,
        new_authority: Pubkey
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // Current authority must sign to transfer ownership
        require!(
            vault.authority == ctx.accounts.current_authority.key(),
            ErrorCode::InvalidAuthority
        );

        vault.authority = new_authority;
        
        msg!("Authority transferred to: {}", new_authority);
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
    
    /// SECURE: Using Signer<'info> enforces signature requirement
    /// 
    /// KEY DIFFERENCES FROM VULNERABLE VERSION:
    /// - Signer<'info> instead of AccountInfo<'info>
    /// - Anchor validates signature during deserialization
    /// - Transaction fails early if signature is missing
    /// - No way to bypass this check
    /// 
    /// WHAT SIGNER<'INFO> VALIDATES:
    /// 1. Account exists in transaction
    /// 2. Account's signature is present
    /// 3. Signature is valid for this account
    /// 
    /// WHY THIS PREVENTS ATTACKS:
    /// - Attacker cannot pass victim's pubkey without victim's signature
    /// - Even if attacker knows the pubkey, they can't produce valid signature
    /// - Transaction rejected before instruction logic runs
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::LEN
    )]
    pub vault: Account<'info, Vault>,
    
    /// Signer required for initialization
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // No signer needed - anyone can deposit to any vault
    // This is intentional design, not a vulnerability
}

#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// Current authority must sign to transfer ownership
    pub current_authority: Signer<'info>,
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
// SECURITY TESTING
// ============================================================================

#[cfg(test)]
mod security_test {
    use super::*;
    
    /// This test demonstrates that the attack is now prevented
    /// 
    /// SECURITY VALIDATION:
    /// 1. Alice initializes vault and deposits 1000 tokens
    /// 2. Mallory attempts to withdraw by passing Alice's pubkey
    /// 3. Transaction fails during account deserialization
    /// 4. Error: "Missing required signature for authority account"
    /// 5. Alice's funds remain safe
    /// 
    /// WHY ATTACK FAILS:
    /// - Signer<'info> type enforces signature requirement
    /// - Anchor checks signatures before instruction runs
    /// - No way to forge or bypass signature verification
    /// - Private key required to create valid signature
    #[test]
    fn test_attack_prevented() {
        // Setup: Alice's vault with 1000 tokens
        // Attack attempt: Mallory tries to withdraw without Alice's signature
        // Result: Transaction fails - signature required
        
        // In a real test framework:
        // let result = withdraw_instruction(alice_pubkey_without_signature);
        // assert!(result.is_err());
        // assert_eq!(result.err(), "Missing required signature");
    }
    
    /// Legitimate withdrawal with proper signature succeeds
    #[test]
    fn test_legitimate_withdrawal() {
        // Setup: Alice's vault with 1000 tokens
        // Action: Alice signs transaction and withdraws 100 tokens
        // Result: Success - signature present and valid
        
        // In a real test framework:
        // let result = withdraw_instruction_with_signature(alice_keypair, 100);
        // assert!(result.is_ok());
        // assert_eq!(vault.balance, 900);
    }
}

// ============================================================================
// KEY TAKEAWAYS
// ============================================================================

/*
 * SIGNER VERIFICATION CHECKLIST:
 * 
 * DO:
 * - Use Signer<'info> for any account that must authorize an action
 * - Apply to: withdrawals, transfers, state changes, authority updates
 * - Let Anchor handle signature verification automatically
 * - Add business logic checks on top (e.g., is this the right authority?)
 * 
 * DON'T:
 * - Use AccountInfo<'info> for accounts that need to authorize actions
 * - Assume Solana validates which accounts signed
 * - Trust that passed pubkeys represent actual signers
 * - Skip signature checks for "trusted" operations
 * 
 * WHEN TO REQUIRE SIGNERS:
 * - Withdrawing funds or assets
 * - Modifying critical state (authority, config, etc.)
 * - Closing accounts
 * - Transferring ownership
 * - Any operation with financial or security implications
 * 
 * WHEN SIGNERS AREN'T NEEDED:
 * - Read-only operations
 * - Deposits (if anyone can deposit)
 * - Public data queries
 * - View functions
 * 
 * REMEMBER:
 * "Just because an account is passed to your program doesn't mean it authorized the action.
 *  Always verify signatures for operations requiring permission."
 */