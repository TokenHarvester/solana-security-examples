use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Vuln22222222222222222222222222222222222222");

#[program]
pub mod vulnerable_owner {
    use super::*;

    /// VULNERABILITY: Missing Owner Validation
    /// 
    /// This instruction accepts any account that claims to be a token account
    /// without verifying it's actually owned by the SPL Token program.
    /// 
    /// ATTACK SCENARIO:
    /// 1. Protocol uses token balances for lending decisions
    /// 2. Attacker creates malicious program mimicking SPL Token structure
    /// 3. Attacker's program returns inflated balance (e.g., 1 billion tokens)
    /// 4. This program reads that fake balance without validation
    /// 5. Attacker gets massive loan based on fake collateral
    /// 
    /// WHY THIS IS DANGEROUS:
    /// - Any program can store data matching SPL Token structure
    /// - Reading data without owner validation means trusting arbitrary programs
    /// - Attackers create "token accounts" with fake balances
    /// - Financial protocols rely on accurate token balances
    /// 
    /// REAL-WORLD IMPACT:
    /// - Cashio hack (Mar 2022): $52M stolen using fake token account
    /// - Multiple lending protocols exploited this way
    /// - Type of attack known as "Account Ownership Confusion"
    pub fn process_collateral(
        ctx: Context<ProcessCollateral>,
        loan_amount: u64
    ) -> Result<()> {
        // CRITICAL VULNERABILITY: No owner check!
        // We're trusting this is a real SPL Token account
        let token_account = &ctx.accounts.user_token_account;
        
        // Reading data from potentially malicious account
        // Deserialize the account data into TokenAccount structure
        let token_data = TokenAccount::try_deserialize(
            &mut &token_account.data.borrow()[..]
        )?;
        
        let collateral_balance = token_data.amount;
        
        // Business logic uses unvalidated balance!
        // If token_account is fake, collateral_balance is fake
        let max_loan = collateral_balance
            .checked_mul(80)  // 80% LTV
            .and_then(|v| v.checked_div(100))
            .ok_or(ErrorCode::ArithmeticOverflow)?;
            
        require!(
            loan_amount <= max_loan,
            ErrorCode::InsufficientCollateral
        );
        
        msg!("Processing loan of {} with collateral {}", 
             loan_amount, collateral_balance);
        
        // Loan approved based on potentially fake collateral!
        Ok(())
    }

    /// Another vulnerable pattern: Accepting any account for state updates
    pub fn update_user_state(ctx: Context<UpdateState>) -> Result<()> {
        // No validation of account owner
        let user_state = &ctx.accounts.user_state;
        
        // Attacker can pass account owned by their malicious program
        // That account could return any data they want
        msg!("State updated");
        Ok(())
    }
}

// ============================================================================
// ACCOUNT VALIDATION STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct ProcessCollateral<'info> {
    /// VULNERABILITY: Using AccountInfo instead of Account<'info, TokenAccount>
    /// 
    /// AccountInfo provides NO validation:
    /// - Doesn't check who owns the account
    /// - Doesn't verify account discriminator
    /// - Doesn't deserialize safely
    /// 
    /// WHAT ATTACKER DOES:
    /// 1. Creates malicious program
    /// 2. Malicious program stores data mimicking TokenAccount
    /// 3. Malicious program returns fake balance (e.g., u64::MAX)
    /// 4. Attacker passes their malicious account here
    /// 5. This program reads fake data as if it's real
    /// 
    /// CHECK: No owner validation - VULNERABILITY!
    pub user_token_account: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateState<'info> {
    /// No owner validation on state account
    /// CHECK: Should validate this is owned by our program!
    pub user_state: AccountInfo<'info>,
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient collateral for loan amount")]
    InsufficientCollateral,
    
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
}

// ============================================================================
// EXPLOITATION EXAMPLE
// ============================================================================

/*
 * ATTACK WALKTHROUGH:
 * 
 * Step 1: Attacker creates malicious "token" program
 * 
 * #[program]
 * mod fake_token {
 *     pub fn initialize_fake_account(ctx: Context<Init>) -> Result<()> {
 *         let fake = &mut ctx.accounts.fake_account;
 *         // Store fake TokenAccount data
 *         fake.mint = USDC_MINT;
 *         fake.owner = attacker.key();
 *         fake.amount = 1_000_000_000_000; // 1 trillion tokens!
 *         Ok(())
 *     }
 * }
 * 
 * Step 2: Attacker calls process_collateral
 * - Passes fake account owned by malicious program
 * - Vulnerable program reads fake balance
 * - Gets approved for massive loan
 * 
 * Step 3: Profit
 * - Attacker borrows real tokens against fake collateral
 * - Never repays (has no real collateral)
 * - Protocol loses funds
 */

#[cfg(test)]
mod exploit_test {
    use super::*;
    
    /// Demonstrates owner check bypass attack
    #[test]
    fn test_fake_token_account_exploit() {
        // 1. Attacker creates account owned by malicious program
        // 2. Account contains fake TokenAccount data with huge balance
        // 3. Attacker passes this to process_collateral
        // 4. Vulnerable program accepts fake balance
        // 5. Attacker gets loan they don't deserve
        
        // In real exploit:
        // - Malicious account owner != SPL Token program
        // - But vulnerable program never checks
        // - Reads fake data as if legitimate
    }
}

/*
 * KEY INSIGHT:
 * 
 * Solana programs can store ANYTHING in accounts they own.
 * Just because data LOOKS like a TokenAccount doesn't mean it IS one.
 * 
 * You MUST verify the account is owned by the expected program:
 * - TokenAccount should be owned by SPL Token program
 * - Your program's state should be owned by your program
 * - System accounts should be owned by System program
 * 
 * Without owner validation, attackers can pass malicious accounts
 * that your program will trust as legitimate.
 */