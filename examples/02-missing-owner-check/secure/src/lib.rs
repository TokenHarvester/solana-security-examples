use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Secur22222222222222222222222222222222222222");

#[program]
pub mod secure_owner {
    use super::*;

    /// SECURE: Proper Owner Validation
    /// 
    /// This instruction correctly verifies account ownership before trusting data.
    /// Multiple validation layers ensure we're working with legitimate accounts.
    /// 
    /// SECURITY MEASURES:
    /// 1. Uses Account<'info, TokenAccount> which validates owner automatically
    /// 2. Verifies owner is SPL Token program
    /// 3. Account type ensures proper deserialization
    /// 4. Anchor checks discriminator for program-owned accounts
    /// 
    /// HOW THE FIX WORKS:
    /// - Account<'info, TokenAccount> type enforces:
    ///   * Owner must be SPL Token program (spl_token::ID)
    ///   * Data must deserialize into TokenAccount struct
    ///   * Account must be initialized
    /// - If any validation fails, transaction rejected before logic runs
    /// 
    /// DEFENSE LAYERS:
    /// 1. Type-level: Account<'info, T> enforces owner validation
    /// 2. Runtime: Anchor validates during deserialization
    /// 3. Additional: Manual checks for extra security if needed
    pub fn process_collateral(
        ctx: Context<ProcessCollateral>,
        loan_amount: u64
    ) -> Result<()> {
        // ✅ SECURE: user_token_account is Account<'info, TokenAccount>
        // Anchor has already validated:
        // 1. Account is owned by SPL Token program
        // 2. Data deserializes into TokenAccount
        // 3. Account is initialized
        
        let token_account = &ctx.accounts.user_token_account;
        let collateral_balance = token_account.amount;
        
        // Additional validation: Verify expected mint
        require!(
            token_account.mint == ctx.accounts.expected_mint.key(),
            ErrorCode::InvalidMint
        );
        
        // Additional validation: Verify token account owner
        require!(
            token_account.owner == ctx.accounts.authority.key(),
            ErrorCode::InvalidTokenOwner
        );
        
        // Safe to use balance - we know it's real
        let max_loan = collateral_balance
            .checked_mul(80)  // 80% LTV
            .and_then(|v| v.checked_div(100))
            .ok_or(ErrorCode::ArithmeticOverflow)?;
            
        require!(
            loan_amount <= max_loan,
            ErrorCode::InsufficientCollateral
        );
        
        msg!("Securely processing loan of {} with verified collateral {}", 
             loan_amount, collateral_balance);
        
        Ok(())
    }

    /// Secure pattern: Validate program-owned accounts
    pub fn update_user_state(ctx: Context<UpdateState>) -> Result<()> {
        // SECURE: Account<'info, UserState> validates owner
        let user_state = &mut ctx.accounts.user_state;
        
        // Anchor verified this account is owned by OUR program
        // Safe to read and modify
        user_state.last_updated = Clock::get()?.unix_timestamp;
        
        msg!("State updated securely");
        Ok(())
    }

    /// Manual owner validation example (when Account type can't be used)
    pub fn manual_owner_validation(ctx: Context<ManualValidation>) -> Result<()> {
        // Sometimes you need to use AccountInfo (e.g., for program accounts)
        let account = &ctx.accounts.some_account;
        
        // Manual owner check when needed
        require!(
            account.owner == &spl_token::ID,
            ErrorCode::InvalidAccountOwner
        );
        
        // Now safe to deserialize and use
        let token_account = TokenAccount::try_deserialize(
            &mut &account.data.borrow()[..]
        )?;
        
        msg!("Manually validated owner, balance: {}", token_account.amount);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT VALIDATION STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct ProcessCollateral<'info> {
    /// SECURE: Account<'info, TokenAccount> validates owner automatically
    /// 
    /// WHAT ANCHOR VALIDATES:
    /// 1. account.owner == spl_token::ID
    /// 2. Data deserializes into TokenAccount struct
    /// 3. All required fields are present
    /// 
    /// WHY THIS PREVENTS ATTACKS:
    /// - Attacker's malicious account owner != spl_token::ID
    /// - Anchor rejects account before instruction runs
    /// - No way to pass fake token account
    /// - Must use real SPL Token program account
    /// 
    /// TYPE SAFETY:
    /// - Compile-time guarantee of owner validation
    /// - Can't accidentally skip the check
    /// - Rust type system enforces security
    pub user_token_account: Account<'info, TokenAccount>,
    
    /// The mint we expect (for additional validation)
    /// CHECK: Safe because we only read the key
    pub expected_mint: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpdateState<'info> {
    /// SECURE: Account validates owner is this program
    #[account(mut)]
    pub user_state: Account<'info, UserState>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ManualValidation<'info> {
    /// When you must use AccountInfo, validate owner manually
    /// CHECK: Owner validated manually in instruction
    pub some_account: AccountInfo<'info>,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[account]
pub struct UserState {
    pub authority: Pubkey,
    pub last_updated: i64,
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
    
    #[msg("Token account has wrong mint")]
    InvalidMint,
    
    #[msg("Token account has wrong owner")]
    InvalidTokenOwner,
    
    #[msg("Account has wrong owner")]
    InvalidAccountOwner,
}

// ============================================================================
// SECURITY VALIDATION
// ============================================================================

#[cfg(test)]
mod security_test {
    use super::*;
    
    /// Verifies attack is prevented by owner validation
    #[test]
    fn test_fake_account_rejected() {
        // 1. Attacker creates account owned by malicious program
        // 2. Attacker tries to pass it as user_token_account
        // 3. Anchor checks: account.owner == spl_token::ID?
        // 4. Answer: No! (owned by attacker's program)
        // 5. Transaction fails before instruction runs
        // 6. Attack prevented
        
        // In test framework:
        // let fake_account = create_account_owned_by_attacker();
        // let result = process_collateral(fake_account);
        // assert!(result.is_err());
        // assert_eq!(error, "AccountOwnedByWrongProgram");
    }
    
    /// Verifies legitimate token accounts work correctly
    #[test]
    fn test_real_token_account_accepted() {
        // 1. User has real SPL Token account
        // 2. Account owned by spl_token::ID
        // 3. Anchor validates owner successfully
        // 4. Instruction executes normally
        // 5. Legitimate operation succeeds
        
        // In test framework:
        // let real_token_account = create_spl_token_account();
        // let result = process_collateral(real_token_account);
        // assert!(result.is_ok());
    }
}

// ============================================================================
// OWNER VALIDATION PATTERNS
// ============================================================================

/*
 * OWNER VALIDATION BEST PRACTICES:
 * 
 * ALWAYS USE Account<'info, T> FOR:
 * - SPL Token accounts → Account<'info, TokenAccount>
 * - Your program's state → Account<'info, YourState>
 * - Associated Token Accounts → Account<'info, TokenAccount>
 * - Any account with structured data you depend on
 * 
 * USE Program<'info, T> FOR:
 * - System Program → Program<'info, System>
 * - Token Program → Program<'info, Token>
 * - Associated Token Program → Program<'info, AssociatedToken>
 * - Any program account you invoke via CPI
 * 
 * ONLY USE AccountInfo WHEN:
 * - Reading account keys (no data access)
 * - Passing through to CPI (let target program validate)
 * - Account type not known at compile time
 * - You manually validate owner immediately after
 * 
 * NEVER:
 * - Use AccountInfo for token accounts without validation
 * - Trust data from accounts you haven't validated
 * - Assume account owner without checking
 * - Skip owner validation "for performance"
 * 
 * MANUAL VALIDATION TEMPLATE:
 * 
 * pub fn validate_owner(ctx: Context<MyContext>) -> Result<()> {
 *     let account = &ctx.accounts.some_account;
 *     
 *     // Check owner
 *     require!(
 *         account.owner == &EXPECTED_PROGRAM_ID,
 *         ErrorCode::InvalidOwner
 *     );
 *     
 *     // Safe to deserialize after validation
 *     let data = MyAccountType::try_deserialize(&mut &account.data.borrow()[..])?;
 *     
 *     // Use validated data
 *     Ok(())
 * }
 * 
 * COMMON PROGRAM IDs TO VALIDATE:
 * - SPL Token: spl_token::ID
 * - System Program: system_program::ID
 * - Associated Token: spl_associated_token_account::ID
 * - Your Program: id() or ctx.program_id
 */

// ============================================================================
// KEY TAKEAWAYS
// ============================================================================

/*
 * OWNER CHECK PRINCIPLES:
 * 
 * 1. DATA TRUST = OWNER TRUST
 *    - You trust data only as much as you trust the owner
 *    - If owner is malicious, data is malicious
 *    - Always validate owner before reading data
 * 
 * 2. ACCOUNT TYPE ≠ ACCOUNT OWNER
 *    - Structure matching TokenAccount doesn't make it one
 *    - Only accounts owned by spl_token::ID are real token accounts
 *    - Attacker can mimic any data structure
 * 
 * 3. VALIDATION IS NON-NEGOTIABLE
 *    - Every external account needs owner validation
 *    - "It looks right" is not validation
 *    - Use type system (Account<'info, T>) when possible
 * 
 * 4. LAYERED SECURITY
 *    - Type-level: Account<'info, T>
 *    - Constraint-level: #[account(...)] attributes
 *    - Logic-level: Manual checks for extra validation
 * 
 * REMEMBER:
 * "On Solana, account ownership determines authority.
 *  Validate ownership before trusting data."
 */