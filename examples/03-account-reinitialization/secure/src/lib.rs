use anchor_lang::prelude::*;

declare_id!("Secur33333333333333333333333333333333333333");

#[program]
pub mod secure_reinit {
    use super::*;

    /// SECURE: Proper Initialization Protection
    /// 
    /// Uses Anchor's 'init' constraint to prevent reinitialization.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Can only run once due to 'init' constraint
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.is_initialized = true; // Extra safety flag
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,  // ✅ Ensures account is newly created
        payer = authority,
        space = 8 + Vault::LEN
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub is_initialized: bool, // ✅ Additional protection
}

impl Vault {
    pub const LEN: usize = 32 + 8 + 1;
    
    /// Manual check for legacy accounts
    pub fn ensure_not_initialized(&self) -> Result<()> {
        require!(!self.is_initialized, ErrorCode::AlreadyInitialized);
        Ok(())
    }
}