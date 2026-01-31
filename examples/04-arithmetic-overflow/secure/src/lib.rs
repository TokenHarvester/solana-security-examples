use anchor_lang::prelude::*;

declare_id!("Secur44444444444444444444444444444444444444");

#[program]
pub mod secure_arithmetic {
    use super::*;

    /// SECURE: Checked Arithmetic Operations
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

    pub fn calculate_reward(balance: u64, multiplier: u64) -> Result<u64> {
        // checked_mul prevents overflow in multiplication
        balance
            .checked_mul(multiplier)
            .ok_or(ErrorCode::ArithmeticOverflow.into())
    }

    /// BONUS: Saturating arithmetic (alternative approach)
    pub fn safe_add_saturating(a: u64, b: u64) -> u64 {
        // Caps at u64::MAX instead of wrapping
        a.saturating_add(b)
    }
}