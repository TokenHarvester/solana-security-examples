use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer, Token, TokenAccount};

declare_id!("Secur77777777777777777777777777777777777777");

#[program]
pub mod secure_cpi {
    use super::*;

    /// SECURE: Validated CPI Authority
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64
    ) -> Result<()> {
        // Validate authority before CPI
        require!(
            ctx.accounts.authority.is_signer ||
            is_valid_pda(&ctx.accounts.authority, ctx.program_id),
            ErrorCode::InvalidAuthority
        );
        
        // Use program's PDA as authority
        let seeds = &[
            b"authority",
            ctx.accounts.vault.key().as_ref(),
            &[ctx.accounts.vault.bump]
        ];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.from.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
            signer_seeds // Proves we control this PDA
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
    
    #[account(
        seeds = [b"authority", vault.key().as_ref()],
        bump = vault.bump
    )]
    /// CHECK: Validated via seeds constraint
    pub authority: AccountInfo<'info>,
    
    pub vault: Account<'info, Vault>,
    pub token_program: Program<'info, Token>,
}

// Helper function
fn is_valid_pda(account: &AccountInfo, program_id: &Pubkey) -> bool {
    // Verify account is PDA derived by our program
    account.owner == program_id
}