// Test file for Secure Version: Missing Owner Check
// This test demonstrates that the exploit is PREVENTED

#[tokio::test]
async fn test_fake_token_account_rejected() {
    println!("\n=== SECURITY: Fake Account Rejection ===\n");
    
    let attacker = Keypair::new();
    
    // Attacker creates fake token account
    println!("1. Attacker creates fake token account");
    let fake_token_account = create_fake_token_account(&attacker, 1_000_000_000).await;
    
    // Attempt to use fake account
    println!("2. Attacker attempts to use fake collateral");
    let result = process_collateral(fake_token_account, 800_000_000).await;
    
    // In secure version: FAILS
    assert!(result.is_err(), "Fake account should be rejected");
    println!("\n ATTACK PREVENTED!");
    println!("   ✓ Anchor validated account owner");
    println!("   ✓ Owner != spl_token::ID");
    println!("   ✓ Transaction rejected before reading data");
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Invalid account owner"));
    
    println!("\n SECURITY: Account<'info, TokenAccount> validates owner");
}

#[tokio::test]
async fn test_real_token_account_accepted() {
    println!("\n=== Testing Real Token Account ===\n");
    
    // Create REAL SPL Token account
    let real_token_account = create_real_token_account(1000).await;
    
    // Should work fine
    let result = process_collateral(real_token_account, 800).await;
    assert!(result.is_ok(), "Real token account should work");
    
    println!("Legitimate token accounts work correctly");
}