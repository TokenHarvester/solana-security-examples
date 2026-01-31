use anchor_lang::prelude::*;

declare_id!("Secur66666666666666666666666666666666666666");

#[program]
pub mod secure_pda {
    use super::*;

    /// SECURE: PDA Validation with Seeds
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Anchor validated PDA was derived with correct seeds
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
            
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()], // Validates seeds
        bump, // Validates bump
    )]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8, // Store bump for future use
}