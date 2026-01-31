use anchor_lang::prelude::*;

declare_id!("Secur55555555555555555555555555555555555555");

#[program]
pub mod secure_type {
    use super::*;

    /// SECURE: Automatic Discriminator Validation
    pub fn process_user(ctx: Context<ProcessUser>) -> Result<()> {
        // Anchor validated discriminator during deserialization
        let user = &ctx.accounts.user_account;
        
        msg!("Processing user with balance: {}", user.balance);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessUser<'info> {
    /// Account<'info, UserAccount> validates:
    /// 1. Owner is this program
    /// 2. Discriminator matches UserAccount
    /// 3. Data deserializes correctly
    pub user_account: Account<'info, UserAccount>,
}

#[account]
pub struct UserAccount {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
pub struct AdminAccount {
    pub authority: Pubkey,
    pub privileges: u64,
}

// Anchor adds 8-byte discriminator to each account:
// UserAccount:  [discriminator][authority][balance]
// AdminAccount: [discriminator][authority][privileges]
// Discriminators are DIFFERENT, preventing confusion