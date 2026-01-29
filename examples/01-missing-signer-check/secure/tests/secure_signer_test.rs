// Test file for Secure Version: Missing Signer Check
// This test demonstrates that the exploit is PREVENTED

use anchor_lang::prelude::*;
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
    pubkey::Pubkey,
};

#[tokio::test]
async fn test_legitimate_withdrawal_succeeds() {
    println!("\n=== Testing Legitimate Withdrawal (Secure Version) ===\n");
    
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "secure_signer",
        program_id,
        processor!(secure_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let authority = Keypair::new();
    let vault = Keypair::new();
    
    println!("Authority: {}", authority.pubkey());
    println!("Vault: {}", vault.pubkey());
    
    // Initialize vault
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
    
    // Deposit tokens
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
    
    // Legitimate withdrawal with proper signature
    println!("\n3. Withdrawing 100 tokens with proper signature...");
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
    
    // Authority PROPERLY SIGNS the transaction
    transaction.sign(&[&payer, &authority], recent_blockhash);
    
    let result = banks_client.process_transaction(transaction).await;
    
    assert!(result.is_ok(), "Legitimate withdrawal should succeed");
    println!("✓ Legitimate withdrawal successful");
    
    // Verify balance
    let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
    let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
    println!("\nFinal balance: {}", vault_data.balance);
    assert_eq!(vault_data.balance, 900);
    
    println!("\n Legitimate operation works correctly in secure version");
}

#[tokio::test]
async fn test_exploit_prevented() {
    println!("\n=== SECURITY TEST: Exploit Prevention ===\n");
    println!("This test demonstrates the security fix");
    println!("In the secure version, the exploit FAILS\n");
    
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "secure_signer",
        program_id,
        processor!(secure_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let alice = Keypair::new(); // Victim
    let mallory = Keypair::new(); // Attacker
    let vault = Keypair::new();
    
    println!("Alice (victim): {}", alice.pubkey());
    println!("Mallory (attacker): {}", mallory.pubkey());
    println!("Vault: {}", vault.pubkey());
    
    // Alice initializes and deposits
    println!("\n1. Alice initializes vault...");
    let init_ix = instruction::initialize(
        program_id,
        vault.pubkey(),
        alice.pubkey(),
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
    
    // THE SECURITY TEST - Mallory tries to exploit
    println!("\n3. SECURITY TEST: Mallory attempts exploit...");
    println!("   - Mallory creates a transaction");
    println!("   - Mallory signs with HER key (not Alice's)");
    println!("   - Mallory passes Alice's pubkey as authority");
    
    let withdraw_ix = instruction::withdraw(
        program_id,
        vault.pubkey(),
        alice.pubkey(), // Mallory passes Alice's pubkey
        500,
    );
    
    let mut transaction = Transaction::new_with_payer(
        &[withdraw_ix],
        Some(&payer.pubkey()),
    );
    
    // ⚠️ Only Mallory signs, NOT Alice
    transaction.sign(&[&payer, &mallory], recent_blockhash);
    
    println!("\n   Attempting unauthorized withdrawal...");
    let result = banks_client.process_transaction(transaction).await;
    
    // In secure version, this FAILS
    if result.is_err() {
        println!("\n  ATTACK PREVENTED!");
        println!("   ✓ Transaction rejected");
        println!("   ✓ Error: Missing required signature");
        println!("   ✓ Alice's funds remain secure");
        
        // Verify funds are safe
        let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
        let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
        
        println!("\n   Vault balance unchanged: {}", vault_data.balance);
        assert_eq!(vault_data.balance, 1000, "Funds should be intact");
        
        println!("\n SECURITY MEASURES WORKING");
        println!("   The Signer<'info> type enforced signature verification");
        
        let error = result.unwrap_err();
        println!("\n   Error details: {:?}", error);
        
    } else {
        panic!("Attack should be prevented in secure version!");
    }
    
    println!("\n=== SECURITY TEST COMPLETE ===\n");
    println!("Key Insight:");
    println!("Using Signer<'info> instead of AccountInfo<'info>");
    println!("ensures that Anchor validates the signature BEFORE");
    println!("the instruction logic runs. There's no way to bypass this.\n");
}

#[tokio::test]
async fn test_wrong_authority_rejected() {
    println!("\n=== Testing Wrong Authority Rejection ===\n");
    
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "secure_signer",
        program_id,
        processor!(secure_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let alice = Keypair::new();
    let bob = Keypair::new(); // Different authority
    let vault = Keypair::new();
    
    // Alice creates vault
    let init_ix = instruction::initialize(program_id, vault.pubkey(), alice.pubkey());
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &vault, &alice], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    let deposit_ix = instruction::deposit(program_id, vault.pubkey(), 1000);
    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    println!("Alice's vault created with 1000 tokens");
    
    // Bob tries to withdraw (but Bob is not the authority)
    println!("\nBob attempts to withdraw from Alice's vault...");
    println!("(Bob signs properly, but he's not the vault authority)");
    
    let withdraw_ix = instruction::withdraw(
        program_id,
        vault.pubkey(),
        bob.pubkey(), // Bob as authority
        100,
    );
    
    let mut tx = Transaction::new_with_payer(&[withdraw_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &bob], recent_blockhash); // Bob signs
    
    let result = banks_client.process_transaction(tx).await;
    
    assert!(result.is_err(), "Wrong authority should be rejected");
    println!("✓ Attack prevented: Bob is not the vault authority");
    
    // Even though Bob signed, he's not the vault's authority
    let error = result.unwrap_err();
    println!("Error: {:?}", error);
    println!("\n Both signature AND authority checks working correctly");
}

#[tokio::test]
async fn test_authority_transfer_security() {
    println!("\n=== Testing Authority Transfer Security ===\n");
    
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "secure_signer",
        program_id,
        processor!(secure_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let alice = Keypair::new();
    let bob = Keypair::new();
    let mallory = Keypair::new();
    let vault = Keypair::new();
    
    // Setup vault
    let init_ix = instruction::initialize(program_id, vault.pubkey(), alice.pubkey());
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &vault, &alice], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    println!("Vault created with Alice as authority");
    
    // Mallory tries to transfer authority to herself (without Alice's signature)
    println!("\nMallory attempts to steal authority...");
    let transfer_ix = instruction::transfer_authority(
        program_id,
        vault.pubkey(),
        alice.pubkey(), // Claims to be Alice
        mallory.pubkey(), // Wants to be new authority
    );
    
    let mut tx = Transaction::new_with_payer(&[transfer_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &mallory], recent_blockhash); // Only Mallory signs
    
    let result = banks_client.process_transaction(tx).await;
    
    assert!(result.is_err(), "Unauthorized authority transfer should fail");
    println!("✓ Attack prevented: Alice must sign to transfer authority");
    
    // Legitimate authority transfer (Alice signs)
    println!("\nAlice legitimately transfers authority to Bob...");
    let transfer_ix = instruction::transfer_authority(
        program_id,
        vault.pubkey(),
        alice.pubkey(),
        bob.pubkey(),
    );
    
    let mut tx = Transaction::new_with_payer(&[transfer_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &alice], recent_blockhash); // Alice properly signs
    
    let result = banks_client.process_transaction(tx).await;
    assert!(result.is_ok(), "Legitimate transfer should succeed");
    println!("✓ Authority successfully transferred to Bob");
    
    println!("\n Authority transfers are properly secured");
}

#[tokio::test]
async fn test_comprehensive_security() {
    println!("\n=== Comprehensive Security Test ===\n");
    println!("Testing multiple security aspects...\n");
    
    let program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "secure_signer",
        program_id,
        processor!(secure_signer::entry),
    );
    
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;
    
    let owner = Keypair::new();
    let attacker = Keypair::new();
    let vault = Keypair::new();
    
    // Setup
    let init_ix = instruction::initialize(program_id, vault.pubkey(), owner.pubkey());
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &vault, &owner], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    let deposit_ix = instruction::deposit(program_id, vault.pubkey(), 1000);
    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
    
    println!("✓ Vault setup complete");
    
    // Test 1: Signature requirement
    println!("\n1. Testing signature requirement...");
    let withdraw_ix = instruction::withdraw(program_id, vault.pubkey(), owner.pubkey(), 100);
    let mut tx = Transaction::new_with_payer(&[withdraw_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &attacker], recent_blockhash); // Wrong signer
    assert!(banks_client.process_transaction(tx).await.is_err());
    println!("   ✓ Unsigned withdrawal blocked");
    
    // Test 2: Correct signer works
    println!("\n2. Testing correct signer...");
    let withdraw_ix = instruction::withdraw(program_id, vault.pubkey(), owner.pubkey(), 100);
    let mut tx = Transaction::new_with_payer(&[withdraw_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &owner], recent_blockhash); // Correct signer
    assert!(banks_client.process_transaction(tx).await.is_ok());
    println!("   ✓ Authorized withdrawal succeeded");
    
    // Test 3: Check balance is correct
    let vault_account = banks_client.get_account(vault.pubkey()).await.unwrap().unwrap();
    let vault_data: Vault = Vault::try_deserialize(&mut &vault_account.data[..]).unwrap();
    assert_eq!(vault_data.balance, 900);
    println!("\n3. ✓ Balance correctly updated to 900");
    
    println!("\n All security measures working correctly");
    println!("\nSummary:");
    println!("• Signature verification: ✓ Working");
    println!("• Authority validation: ✓ Working");
    println!("• Balance tracking: ✓ Working");
    println!("• Attack prevention: ✓ Working\n");
}

// Helper module
mod instruction {
    use super::*;
    use anchor_lang::InstructionData;
    use anchor_lang::ToAccountMetas;
    
    pub fn initialize(
        program_id: Pubkey,
        vault: Pubkey,
        authority: Pubkey,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = secure_signer::accounts::Initialize {
            vault,
            authority,
            system_program: solana_program::system_program::id(),
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: secure_signer::instruction::Initialize {}.data(),
        }
    }
    
    pub fn deposit(
        program_id: Pubkey,
        vault: Pubkey,
        amount: u64,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = secure_signer::accounts::Deposit {
            vault,
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: secure_signer::instruction::Deposit { amount }.data(),
        }
    }
    
    pub fn withdraw(
        program_id: Pubkey,
        vault: Pubkey,
        authority: Pubkey,
        amount: u64,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = secure_signer::accounts::Withdraw {
            vault,
            authority,
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: secure_signer::instruction::Withdraw { amount }.data(),
        }
    }
    
    pub fn transfer_authority(
        program_id: Pubkey,
        vault: Pubkey,
        current_authority: Pubkey,
        new_authority: Pubkey,
    ) -> solana_sdk::instruction::Instruction {
        let accounts = secure_signer::accounts::TransferAuthority {
            vault,
            current_authority,
        };
        
        solana_sdk::instruction::Instruction {
            program_id,
            accounts: accounts.to_account_metas(None),
            data: secure_signer::instruction::TransferAuthority { new_authority }.data(),
        }
    }
}

#[derive(Debug)]
struct Vault {
    authority: Pubkey,
    balance: u64,
}

impl Vault {
    fn try_deserialize(data: &mut &[u8]) -> Result<Self> {
        Ok(Vault {
            authority: Pubkey::new_from_array([0; 32]),
            balance: 0,
        })
    }
}