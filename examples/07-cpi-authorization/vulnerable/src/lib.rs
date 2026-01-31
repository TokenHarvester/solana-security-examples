use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer};

declare_id!("Vuln77777777777777777777777777777777777777");

#[program]
pub mod vulnerable_cpi {
    use super::*;

    /// VULNERABILITY: Unchecked CPI Authority
    /// 
    /// ATTACK: Malicious program creates PDA with authority over user tokens,
    /// then calls this via CPI to steal tokens.
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64
    ) -> Result<()> {
        // No validation of authority!
        // Accepts ANY authority passed via CPI
        
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.from.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            }
        );
        
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    /// CHECK: No validation!
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}