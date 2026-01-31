#[tokio::test]
async fn test_type_confusion_exploit() {
    println!("\n=== EXPLOIT: Type Cosplay ===\n");
    
    // Create AdminAccount
    let admin_account = create_admin_account(999).await;
    println!("1. Created AdminAccount");
    println!("   privileges: 999");
    
    // Try to use as UserAccount in vulnerable version
    println!("\n2. Passing AdminAccount as UserAccount");
    let result = process_user(admin_account).await;
    
    // Vulnerable: accepts wrong type
    assert!(result.is_ok());
    
    println!("\n   EXPLOIT SUCCESSFUL!");
    println!("   ✗ Program accepted wrong account type");
    println!("   ✗ Read privileges (999) as balance");
    
    println!("\n Type confusion allowed data misinterpretation");
}

#[tokio::test]
async fn test_type_validation() {
    println!("\n=== SECURITY: Type Validation ===\n");
    
    let admin_account = create_admin_account(999).await;
    
    println!("1. Attempting to use AdminAccount as UserAccount");
    let result = process_user(admin_account).await;
    
    // Secure: rejects wrong type
    assert!(result.is_err());
    
    println!("\n   TYPE MISMATCH DETECTED!");
    println!("   ✓ Discriminator validation failed");
    println!("   ✓ Expected: UserAccount discriminator");
    println!("   ✓ Found: AdminAccount discriminator");
    
    println!("\n Account<'info, T> validates discriminators");
}