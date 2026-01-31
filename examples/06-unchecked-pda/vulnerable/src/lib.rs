use anchor_lang::prelude::*;

declare_id!("Vuln66666666666666666666666666666666666666");

#[program]
pub mod vulnerable_pda {
    use super::*;

    /// VULNERABILITY: No PDA Validation
    /// 
    /// ATTACK: Expected PDA is derived from [b"vault", user.key()].
    /// Attacker finds different seeds that produce a PDA they control,
    /// then passes that PDA to this instruction.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Assumes vault is derived with correct seeds
        // But attacker could pass ANY PDA!
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>, // ❌ No seed validation
    pub user: Signer<'info>,
}