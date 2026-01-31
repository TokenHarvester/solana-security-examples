#[tokio::test]
async fn test_invalid_pda_exploit() {
    println!("\n=== EXPLOIT: Invalid PDA ===\n");
    
    let user = Keypair::new();
    
    // Find correct PDA
    let (correct_pda, _) = Pubkey::find_program_address(
        &[b"vault", user.pubkey().as_ref()],
        &program_id(),
    );
    
    // Attacker finds different PDA they control
    let (attacker_pda, _) = Pubkey::find_program_address(
        &[b"exploit", b"malicious"],
        &program_id(),
    );
    
    println!("1. Correct PDA: {}", correct_pda);
    println!("2. Attacker's PDA: {}", attacker_pda);
    
    // Try to use wrong PDA
    println!("\n3. Using attacker's PDA instead of correct one");
    let result = withdraw_from_pda(attacker_pda, 1000).await;
    
    // Vulnerable: accepts any PDA
    assert!(result.is_ok());
    
    println!("\n  EXPLOIT SUCCESSFUL!");
    println!("   ✗ Program accepted wrong PDA");
    println!("   ✗ No seed validation");
    
    println!("\n Attacker bypassed authorization with wrong PDA");
}

#[tokio::test]
async fn test_pda_validation() {
    println!("\n=== SECURITY: PDA Validation ===\n");
    
    let user = Keypair::new();
    
    let (correct_pda, _) = Pubkey::find_program_address(
        &[b"vault", user.pubkey().as_ref()],
        &program_id(),
    );
    
    let (wrong_pda, _) = Pubkey::find_program_address(
        &[b"exploit", b"malicious"],
        &program_id(),
    );
    
    // Try wrong PDA
    println!("1. Attempting to use incorrectly derived PDA");
    let result = withdraw_from_pda(wrong_pda, 1000).await;
    
    // Secure: rejects wrong PDA
    assert!(result.is_err());
    
    println!("\n  INVALID PDA REJECTED!");
    println!("   ✓ Seeds constraint validated derivation");
    println!("   ✓ PDA not derived with expected seeds");
    
    // Correct PDA works
    println!("\n2. Using correctly derived PDA");
    let result = withdraw_from_pda(correct_pda, 100).await;
    assert!(result.is_ok());
    
    println!("\n seeds and bump constraints validate PDAs");
}