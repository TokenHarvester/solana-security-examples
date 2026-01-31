#[tokio::test]
async fn test_malicious_cpi_exploit() {
    println!("\n=== EXPLOIT: CPI Authorization Bypass ===\n");
    
    // Create malicious program with fake authority
    let malicious_authority = create_malicious_pda().await;
    
    println!("1. Attacker creates malicious PDA authority");
    println!("   Authority: {}", malicious_authority);
    
    // Attempt CPI with malicious authority
    println!("\n2. Calling transfer via CPI with malicious authority");
    let result = transfer_tokens_cpi(
        malicious_authority,
        victim_tokens,
        attacker_tokens,
        1000,
    ).await;
    
    // Vulnerable: accepts any authority
    assert!(result.is_ok());
    
    println!("\n EXPLOIT SUCCESSFUL!");
    println!("   ✗ CPI accepted malicious authority");
    println!("   ✗ Transferred 1000 tokens");
    println!("   ✗ Tokens stolen via unauthorized CPI");
    
    println!("\n No CPI authority validation");
}

#[tokio::test]
async fn test_cpi_authority_validation() {
    println!("\n=== SECURITY: CPI Authority Validation ===\n");
    
    let malicious_authority = create_malicious_pda().await;
    
    println!("1. Attempting CPI with malicious authority");
    let result = transfer_tokens_cpi(
        malicious_authority,
        victim_tokens,
        attacker_tokens,
        1000,
    ).await;
    
    // Secure: rejects unauthorized authority
    assert!(result.is_err());
    
    println!("\n  UNAUTHORIZED CPI BLOCKED!");
    println!("   ✓ Authority validation failed");
    println!("   ✓ PDA not owned by this program");
    println!("   ✓ Transaction rejected");
    
    // Legitimate CPI works
    println!("\n2. Using legitimate PDA authority");
    let legitimate_authority = get_program_pda().await;
    let result = transfer_tokens_cpi(
        legitimate_authority,
        from_tokens,
        to_tokens,
        100,
    ).await;
    assert!(result.is_ok());
    
    println!("\n CPI authority properly validated");
}