// Test file for Secure Version: Arithmetic Overflow
// This test demonstrates that the exploit is PREVENTED

#[tokio::test]
async fn test_overflow_prevented() {
    println!("\n=== SECURITY: Overflow Prevention ===\n");
    
    let vault = Keypair::new();
    initialize_vault(&vault).await.unwrap();
    
    let near_max = u64::MAX - 100;
    set_balance(&vault, near_max).await;
    println!("1. Vault balance near maximum: {}", near_max);
    
    println!("\n2.  Attempting deposit that would overflow");
    let result = deposit(&vault, 200).await;
    
    // In secure version: FAILS
    assert!(result.is_err(), "Overflow should be prevented");
    
    println!("\n  OVERFLOW PREVENTED!");
    println!("   ✓ checked_add detected overflow");
    println!("   ✓ Transaction rejected");
    println!("   ✓ Error: Arithmetic overflow");
    
    let balance = get_balance(&vault).await;
    assert_eq!(balance, near_max, "Balance should be unchanged");
    
    println!("\n checked_add prevents overflow");
}

#[tokio::test]
async fn test_underflow_prevented() {
    println!("\n=== SECURITY: Underflow Prevention ===\n");
    
    let vault = Keypair::new();
    initialize_vault(&vault).await.unwrap();
    deposit(&vault, 100).await.unwrap();
    
    println!("1. Vault balance: 100 tokens");
    
    println!("\n2. Attempting withdrawal that would underflow");
    let result = withdraw(&vault, 200).await;
    
    // In secure version: FAILS
    assert!(result.is_err(), "Underflow should be prevented");
    
    println!("\n  UNDERFLOW PREVENTED!");
    println!("   ✓ checked_sub detected underflow");
    println!("   ✓ Transaction rejected");
    println!("   ✓ Error: Insufficient funds");
    
    let balance = get_balance(&vault).await;
    assert_eq!(balance, 100, "Balance should be unchanged");
    
    println!("\n checked_sub prevents underflow");
}