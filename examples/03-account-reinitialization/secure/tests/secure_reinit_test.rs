// Test file for Secure Version: Account Reinitialization
// This test demonstrates that the exploit is PREVENTED

#[tokio::test]
async fn test_reinitialization_prevented() {
    println!("\n=== SECURITY: Reinitialization Prevention ===\n");
    
    let alice = Keypair::new();
    let mallory = Keypair::new();
    let vault = Keypair::new();
    
    // Alice initializes and deposits
    println!("1. Alice initializes vault and deposits");
    initialize_vault(&vault, &alice).await.unwrap();
    deposit(&vault, 1000).await.unwrap();
    
    // Mallory attempts reinitialization
    println!("\n2. Mallory attempts reinitialization");
    let result = initialize_vault(&vault, &mallory).await;
    
    // In secure version: FAILS
    assert!(result.is_err(), "Reinitialization should be prevented");
    
    println!("\n   ATTACK PREVENTED!");
    println!("   ✓ 'init' constraint prevents reuse");
    println!("   ✓ Account already exists");
    println!("   ✓ Transaction rejected");
    
    // Verify Alice's funds are safe
    let balance = get_vault_balance(&vault).await;
    let authority = get_vault_authority(&vault).await;
    
    println!("\n   Balance unchanged: {}", balance);
    println!("   Authority unchanged: {}", authority);
    
    assert_eq!(balance, 1000);
    assert_eq!(authority, alice.pubkey());
    
    println!("\n 'init' constraint protects against reinitialization");
}