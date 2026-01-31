use anchor_lang::prelude::*;

declare_id!("Vuln33333333333333333333333333333333333333");

#[program]
pub mod vulnerable_reinit {
    use super::*;

    /// VULNERABILITY: No Reinitialization Protection
    /// 
    /// Allows an account to be "initialized" multiple times, resetting its state.
    /// 
    /// ATTACK: After Alice deposits 1000 tokens, Mallory calls initialize again,
    /// resetting balance to 0 and changing authority to herself.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ❌ NO CHECK if already initialized!
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0; // RESETS existing balance!
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)] // ❌ Should use 'init' constraint
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}