// Test file for Vulnerable Version: Missing Owner Check
// This test demonstrates that the exploit WORKS

use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;
use solana_program_test::*;
use solana_sdk::{signature::Keypair, signer::Signer};

#[tokio::test]
async fn test_fake_token_account_accepted() {
    println!("\n=== EXPLOIT: Fake Token Account ===\n");
    
    // Setup
    let victim = Keypair::new();
    let attacker = Keypair::new();
    
    // Step 1: Attacker creates malicious program
    println!("1. Attacker creates malicious program that mimics SPL Token");
    
    // Step 2: Attacker creates fake token account
    println!("2. Attacker creates account owned by malicious program");
    println!("   - Account structure matches TokenAccount");
    println!("   - Fake balance: 1,000,000,000 tokens");
    println!("   - Owner: attacker's malicious program (NOT spl_token::ID)");
    
    let fake_token_account = create_fake_token_account(&attacker, 1_000_000_000).await;
    
    // Step 3: Attacker uses fake account for loan
    println!("\n3. Attacker requests loan using fake collateral");
    let loan_amount = 800_000_000; // 80% of fake balance
    
    let result = process_collateral(fake_token_account, loan_amount).await;
    
    // In vulnerable version: SUCCEEDS
    assert!(result.is_ok(), "Exploit should work on vulnerable version");
    println!("\n EXPLOIT SUCCESSFUL!");
    println!("   ✗ Program accepted fake token account");
    println!("   ✗ Program read fake balance as real");
    println!("   ✗ Attacker got massive loan with zero real collateral");
    
    println!("\n VULNERABILITY: No owner validation");
}