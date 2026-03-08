use dashmap::DashMap;
use zero_types::{Account, Amount, Hash, Nonce, PubKey};

/// In-memory account state table.
///
/// Maps PubKey -> Account. This is the entire state of the network.
/// At 48 bytes per account, 100M accounts = 4.8 GB.
///
/// Uses DashMap for concurrent reads (balance lookups) with
/// single-writer semantics for state transitions (consensus execution).
pub struct AccountStore {
    accounts: DashMap<PubKey, Account>,
}

impl AccountStore {
    pub fn new() -> Self {
        Self {
            accounts: DashMap::new(),
        }
    }

    /// Pre-allocate capacity for expected number of accounts.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            accounts: DashMap::with_capacity(capacity),
        }
    }

    /// Get a copy of an account's state. Returns None if account doesn't exist.
    pub fn get(&self, key: &PubKey) -> Option<Account> {
        self.accounts.get(key).map(|r| r.clone())
    }

    /// Get balance for an account. Returns 0 for unknown accounts.
    pub fn balance(&self, key: &PubKey) -> Amount {
        self.accounts.get(key).map(|r| r.balance).unwrap_or(0)
    }

    /// Get nonce for an account. Returns 0 for unknown accounts.
    pub fn nonce(&self, key: &PubKey) -> Nonce {
        self.accounts.get(key).map(|r| r.nonce).unwrap_or(0)
    }

    /// Insert or update an account. Used during state transitions.
    pub fn set(&self, key: PubKey, account: Account) {
        self.accounts.insert(key, account);
    }

    /// Get or create an account (returns empty account for new keys).
    pub fn get_or_default(&self, key: &PubKey) -> Account {
        self.accounts
            .get(key)
            .map(|r| r.clone())
            .unwrap_or(Account::empty())
    }

    /// Apply a debit: decrease balance, increment nonce, update head hash.
    /// Returns the updated account. Caller must verify balance sufficiency first.
    pub fn debit(&self, key: &PubKey, amount: Amount, fee: Amount, new_head: Hash) -> Account {
        let mut entry = self.accounts.entry(*key).or_insert(Account::empty());
        entry.balance = entry.balance.saturating_sub(amount + fee);
        entry.nonce += 1;
        entry.head = new_head;
        entry.clone()
    }

    /// Apply a credit: increase balance, update head hash.
    /// Returns the updated account.
    pub fn credit(&self, key: &PubKey, amount: Amount, new_head: Hash) -> Account {
        let mut entry = self.accounts.entry(*key).or_insert(Account::empty());
        entry.balance = entry.balance.saturating_add(amount);
        entry.head = new_head;
        entry.clone()
    }

    /// Mint Z tokens to an account (bridge-in). Like credit but no head update.
    pub fn mint(&self, key: &PubKey, amount: Amount) {
        let mut entry = self.accounts.entry(*key).or_insert(Account::empty());
        entry.balance = entry.balance.saturating_add(amount);
    }

    /// Burn Z tokens from an account (bridge-out). Like debit but no nonce change.
    pub fn burn(&self, key: &PubKey, amount: Amount) -> bool {
        if let Some(mut entry) = self.accounts.get_mut(key) {
            if entry.balance >= amount {
                entry.balance -= amount;
                return true;
            }
        }
        false
    }

    /// Total number of accounts.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Total Z supply across all accounts.
    pub fn total_supply(&self) -> u64 {
        self.accounts.iter().map(|r| r.balance as u64).sum()
    }

    /// Iterate all accounts (snapshot support). Returns (pubkey, account) pairs.
    pub fn iter_accounts(&self) -> Vec<(PubKey, Account)> {
        self.accounts
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect()
    }
}

impl Default for AccountStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account_has_zero_balance() {
        let store = AccountStore::new();
        let key = [1u8; 32];
        assert_eq!(store.balance(&key), 0);
        assert_eq!(store.nonce(&key), 0);
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn mint_and_debit() {
        let store = AccountStore::new();
        let key = [1u8; 32];
        store.mint(&key, 1000);
        assert_eq!(store.balance(&key), 1000);

        let head = [0xAA; 32];
        store.debit(&key, 100, 1, head);
        assert_eq!(store.balance(&key), 899); // 1000 - 100 - 1
        assert_eq!(store.nonce(&key), 1);
    }

    #[test]
    fn credit() {
        let store = AccountStore::new();
        let key = [2u8; 32];
        let head = [0xBB; 32];
        store.credit(&key, 500, head);
        assert_eq!(store.balance(&key), 500);
        assert_eq!(store.get(&key).unwrap().head, head);
    }

    #[test]
    fn burn_insufficient() {
        let store = AccountStore::new();
        let key = [3u8; 32];
        store.mint(&key, 100);
        assert!(!store.burn(&key, 200));
        assert_eq!(store.balance(&key), 100); // unchanged
    }

    #[test]
    fn burn_sufficient() {
        let store = AccountStore::new();
        let key = [3u8; 32];
        store.mint(&key, 200);
        assert!(store.burn(&key, 150));
        assert_eq!(store.balance(&key), 50);
    }

    #[test]
    fn total_supply() {
        let store = AccountStore::new();
        store.mint(&[1u8; 32], 100);
        store.mint(&[2u8; 32], 200);
        store.mint(&[3u8; 32], 300);
        assert_eq!(store.total_supply(), 600);
    }
}
