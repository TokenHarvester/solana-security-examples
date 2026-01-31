use anchor_lang::prelude::*;

declare_id!("Vuln55555555555555555555555555555555555555");

#[program]
pub mod vulnerable_type {
    use super::*;

    /// VULNERABILITY: No Discriminator Validation
    /// 
    /// ATTACK: UserAccount and AdminAccount have same memory layout.
    /// Attacker passes AdminAccount where UserAccount expected.
    /// Program reads privileges field as balance.
    pub fn process_user(ctx: Context<ProcessUser>) -> Result<()> {
        // No discriminator check!
        let account_data = ctx.accounts.user_account.try_borrow_data()?;
        
        // Manually deserialize without checking type
        let authority = Pubkey::try_from(&account_data[8..40])?;
        let balance = u64::from_le_bytes(account_data[40..48].try_into()?);
        
        msg!("Processing user with balance: {}", balance);
        Ok(())
    }
}

#[account]
pub struct UserAccount {
    pub authority: Pubkey,  // 32 bytes
    pub balance: u64,       // 8 bytes
}

#[account]
pub struct AdminAccount {
    pub authority: Pubkey,  // 32 bytes
    pub privileges: u64,    // 8 bytes - SAME LAYOUT!
}