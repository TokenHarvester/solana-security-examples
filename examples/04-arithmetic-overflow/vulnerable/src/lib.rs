use anchor_lang::prelude::*;

declare_id!("Vuln44444444444444444444444444444444444444");

#[program]
pub mod vulnerable_arithmetic {
    use super::*;

    /// VULNERABILITY: Unchecked Arithmetic
    /// 
    /// ATTACK 1 - Overflow:
    /// - Vault has balance = u64::MAX - 50
    /// - Attacker deposits 100
    /// - balance += 100 overflows to 49
    /// - Attacker withdraws large amount from "low" balance
    /// 
    /// ATTACK 2 - Underflow:
    /// - Vault has 100 tokens
    /// - Attacker withdraws 200
    /// - balance -= 200 underflows to ~u64::MAX
    /// - Vault shows massive fake balance
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance += amount; // Can overflow!
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount; // Can underflow!
        Ok(())
    }

    pub fn calculate_reward(balance: u64, multiplier: u64) -> u64 {
        balance * multiplier // Can overflow!
    }
}