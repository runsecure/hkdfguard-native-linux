//! Provider 5: Ephemeral Memory-Only KEK.
//!
//! Generates a fresh, cryptographically random 256-bit HMAC KEK per service the
//! first time it is requested, keeps it in memory for the lifetime of the
//! process, and never persists it. Used only when the policy names it.
//!
//! Consequence (logged as a warning when the chain serves a call from it,
//! in `provider::walk_chain`): a process restart makes every DEK wrapped
//! under an ephemeral KEK permanently unrecoverable.
//!
//! ## How the key is protected
//!
//! The key exists only in this process's memory, so this provider protects
//! that memory as far as a library can:
//!
//! - **The process is hardened before the first key is created** (core
//!   dumps off, and on Linux non-dumpable, which also stops same-user
//!   `ptrace` and `/proc/<pid>/mem` -- see `hkdfguard_harden_process`).
//!   Creating a key fails if that can't be done. It is re-applied on every
//!   key creation, since the kernel clears the non-dumpable flag when the
//!   process changes credentials.
//! - **The keys live in dedicated pages**, mapped once and never
//!   moved or freed: locked into RAM where `RLIMIT_MEMLOCK` allows it (so
//!   they are never written to swap), and excluded from core dumps. Only
//!   the service-name index lives on the ordinary heap, and service names
//!   are not secret.
//! - **Copies are wiped:** each call's copy of the key zeroes itself on
//!   drop (see `provider::software_prf` for what HMAC itself leaves).
//!
//! Root, or a process with `CAP_SYS_PTRACE`, can still read the key: no
//! software-only key is protected from them.
//!
//! An ephemeral key can only ever be used by the process that created it,
//! so the `hkdfguard` CLI turns this provider off for itself
//! ([`refuse_in_this_process`]): a key it created would be gone when it
//! exits, and nothing it wrapped could ever be unwrapped. Nor does a key
//! spread to a child: on Linux 4.14 and later the keys' page is marked
//! `MADV_WIPEONFORK`, so a child created with `fork()` sees zeroes there.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, PrfOutput, ProviderType, KEK_LEN}; // the traits/types this module implements
use std::collections::HashMap; // service name -> slot index
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock}; // guards the store so concurrent calls don't race
use zeroize::Zeroizing;

const KEY_LEN: usize = KEK_LEN; // one HMAC-SHA-256 key

static PROCESS_KEYS: OnceLock<Arc<Mutex<KeyStore>>> = OnceLock::new();

/// Set by [`refuse_in_this_process`].
static REFUSED: AtomicBool = AtomicBool::new(false);

/// Makes this provider refuse every `load_kek` in this process from now on
/// (see the module docs). `kek_exists` still answers "no", so a policy that
/// lists a persistent provider ahead of this one keeps working.
pub fn refuse_in_this_process() {
    REFUSED.store(true, Ordering::SeqCst);
}

/// One page of anonymous memory holding up to `len / KEY_LEN` keys. Mapped once, never moved and never unmapped, so no copy of a
/// key is ever left behind by a reallocation.
struct KeyPage {
    base: *mut u8,
    len: usize,
}

// SAFETY: a `KeyPage` is only ever reached through the store's mutex.
unsafe impl Send for KeyPage {}

impl KeyPage {
    fn new() -> Result<Self> {
        // SAFETY: sysconf takes only a name constant.
        let len = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096).max(KEY_LEN);
        // SAFETY: an anonymous private mapping with no address hint; the
        // result is checked against MAP_FAILED before use.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(Error::Provider(format!(
                "could not map memory for ephemeral keys (mmap): {}",
                std::io::Error::last_os_error()
            )));
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `base..base+len` is the mapping just created.
            if unsafe { libc::madvise(base, len, libc::MADV_DONTDUMP) } != 0 {
                crate::provider::log_once(
                    log::Level::Warn,
                    format!(
                        "hkdfguard: could not exclude ephemeral key memory from core dumps (madvise: {}); \
                         core dumps are disabled for the process instead",
                        std::io::Error::last_os_error()
                    ),
                );
            }
            // A forked child gets this page zero-filled rather than a copy of
            // every ephemeral KEK, so a key never spreads to a second process
            // that may later run less trusted code. Linux 4.14 and later.
            // SAFETY: as above.
            if unsafe { libc::madvise(base, len, libc::MADV_WIPEONFORK) } != 0 {
                crate::provider::log_once(
                    log::Level::Warn,
                    format!(
                        "hkdfguard: could not keep ephemeral key memory out of forked child processes \
                         (madvise MADV_WIPEONFORK: {}; Linux 4.14 or later is needed); a child forked \
                         from this process inherits a copy of its ephemeral keys",
                        std::io::Error::last_os_error()
                    ),
                );
            }
        }
        // SAFETY: as above.
        if unsafe { libc::mlock(base, len) } != 0 {
            crate::provider::log_once(
                log::Level::Warn,
                format!(
                    "hkdfguard: could not lock ephemeral key memory into RAM (mlock: {}); it could be written \
                     to swap. Raise RLIMIT_MEMLOCK (e.g. LimitMEMLOCK= in the systemd unit) to allow it",
                    std::io::Error::last_os_error()
                ),
            );
        }
        Ok(KeyPage { base: base.cast(), len })
    }

    fn slots(&self) -> usize {
        self.len / KEY_LEN
    }

    fn slot(&mut self, i: usize) -> &mut [u8; KEY_LEN] {
        assert!(i < self.slots());
        // SAFETY: `i` is in range, the page is readable and writable for
        // the life of the process, and `&mut self` (behind the store's
        // mutex) makes this the only reference.
        unsafe { &mut *self.base.add(i * KEY_LEN).cast::<[u8; KEY_LEN]>() }
    }
}

/// Every ephemeral key in this process.
#[derive(Default)]
struct KeyStore {
    index: HashMap<String, usize>, // service name -> slot number across `pages`
    pages: Vec<KeyPage>,
    used: usize,
}

impl KeyStore {
    fn slot(&mut self, n: usize) -> &mut [u8; KEY_LEN] {
        let per_page = self.pages[0].slots();
        self.pages[n / per_page].slot(n % per_page)
    }

    fn load(&mut self, service: &str) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let n = *self.index.get(service)?;
        Some(Zeroizing::new(*self.slot(n)))
    }

    /// Generates and stores a key for `service`, which has none yet.
    fn create(&mut self, service: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        // A key is only ever created in a hardened process.
        if crate::harden_process_impl(0) != crate::status::OK {
            return Err(Error::Provider(
                "refusing to create an ephemeral key: the process could not be hardened \
                 (core dumps off, non-dumpable) to protect it -- see the message above"
                    .into(),
            ));
        }
        crate::provider::log_once(
            log::Level::Warn,
            "hkdfguard: this process now holds an ephemeral KEK, so core dumps are disabled and it is \
             marked non-dumpable (debuggers can no longer attach)"
                .to_string(),
        );

        if self.pages.is_empty() || self.used == self.pages.len() * self.pages[0].slots() {
            self.pages.push(KeyPage::new()?);
        }
        let n = self.used;
        // Generated straight into its slot: no other copy is ever made.
        getrandom::fill(&mut self.slot(n)[..]).map_err(|_| Error::Provider("the OS random number generator failed".into()))?;
        let key = Zeroizing::new(*self.slot(n));
        self.used += 1;
        self.index.insert(service.to_string(), n);
        Ok(key)
    }
}

// Holds one HMAC key per service name, entirely in process
// memory. Nothing here is ever written to disk.
pub struct EphemeralProvider {
    keys: Arc<Mutex<KeyStore>>,
}

impl EphemeralProvider {
    pub fn new() -> Self {
        let keys = PROCESS_KEYS.get_or_init(|| Arc::new(Mutex::new(KeyStore::default()))).clone();
        EphemeralProvider { keys }
    }
}

impl Default for EphemeralProvider {
    fn default() -> Self {
        Self::new() // `Default` just delegates to the same constructor
    }
}

// The handle type this provider hands back from `load_kek`; holds a copy
// of the service's key (zeroed on drop) for the duration of one call.
struct EphemeralHandle {
    key_id: Vec<u8>,                // diagnostic-only tag, embedded in the wrapped payload
    key: Zeroizing<[u8; KEY_LEN]>, // the actual key material for this service
}

impl KekHandle for EphemeralHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id // just hand back the borrowed bytes
    }

    fn prf(&self, inputs: &[&[u8]]) -> Result<Vec<PrfOutput>> {
        Ok(crate::provider::software_prf(&self.key, inputs))
    }
}

impl KekProvider for EphemeralProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ephemeral // tags every payload wrapped by this provider with `5`
    }

    fn probe(&self) -> bool {
        // Always available: this is the final, guaranteed fallback.
        true
    }

    fn kek_exists(&self, service: &str) -> Result<bool> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| Error::Provider("ephemeral key map lock poisoned".into()))?;
        Ok(keys.index.contains_key(service))
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        if REFUSED.load(Ordering::SeqCst) {
            return Err(Error::Provider(
                "ephemeral keys exist only inside the process that creates them, so a key created here would \
                 be gone when this command exits and could never unwrap anything for the application. Wrap \
                 DEKs from the application itself (e.g. hkdfguard_generate_and_wrap_dek), or configure a \
                 persistent provider"
                    .into(),
            ));
        }
        let mut keys = self
            .keys
            .lock() // acquire the mutex; blocks if another call is using the store right now
            .map_err(|_| Error::Provider("ephemeral key map lock poisoned".into()))?; // a prior panic while holding the lock would poison it

        let key = match keys.load(service) {
            Some(existing) => existing,
            None if !create_if_missing => {
                return Err(Error::KeyNotProvisioned("no ephemeral KEK created yet for this service"));
            }
            None => keys.create(service)?, // a brand-new random key, only since none exists yet
        }; // lock released once this block ends, before returning

        // key_id is a stable-per-process, non-secret tag derived from the
        // service name only for human-readable diagnostics; it carries no
        // key material and is not used for lookup (the service string is).
        let key_id = format!("ephemeral:{service}").into_bytes();

        Ok(Box::new(EphemeralHandle { key_id, key })) // box it up as the trait-object handle the caller expects
    }
}

#[cfg(test)]
mod tests {
    use super::*; // bring `EphemeralProvider`, `KekHandle`, etc. into scope
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn probe_and_provider_type() {
        let provider = EphemeralProvider::new();
        assert!(provider.probe());
        assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        let default_provider = EphemeralProvider::default();
        assert!(default_provider.probe());
    }

    #[test]
    fn kek_exists_is_false_until_created_then_true_and_load_kek_declines_without_create() {
        let provider = EphemeralProvider::new();
        // A service name unique to this test, since PROCESS_KEYS is shared
        // process-wide across every EphemeralProvider instance/test.
        let service = "com.company.kek-exists-test";

        assert!(!provider.kek_exists(service).unwrap());
        match provider.load_kek(service, false) {
            Err(Error::KeyNotProvisioned(_)) => {}
            Err(other) => panic!("expected KeyNotProvisioned, got {other:?}"),
            Ok(_) => panic!("expected KeyNotProvisioned, got Ok"),
        }

        provider.load_kek(service, true).unwrap(); // now actually create it

        assert!(provider.kek_exists(service).unwrap());
        provider.load_kek(service, false).unwrap(); // now loads fine without creating
    }

    /// One PRF output, for comparing keys.
    fn prf_of(handle: &dyn KekHandle, input: &[u8]) -> [u8; 32] {
        *handle.prf(&[input]).unwrap()[0]
    }

    #[test]
    fn prf_is_hmac_sha256_under_the_stored_key() {
        let provider = EphemeralProvider::new();
        let service = "com.company.prf-test";
        let handle = provider.load_kek(service, true).unwrap();
        let key = PROCESS_KEYS.get().unwrap().lock().unwrap().load(service).unwrap();
        let outputs = handle.prf(&[b"one", b"two"]).unwrap();
        assert_eq!(outputs.len(), 2, "one output per input, in order");
        assert_eq!(*outputs[0], *crate::provider::software_prf(&key, &[b"one"])[0]);
        assert_eq!(*outputs[1], *crate::provider::software_prf(&key, &[b"two"])[0]);
        assert_ne!(*outputs[0], *outputs[1]);
    }

    #[test]
    fn key_id_format() {
        let provider = EphemeralProvider::new();
        let handle = provider.load_kek("com.company.orders", true).unwrap();
        assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");
    }

    #[test]
    fn same_service_returns_same_key_within_process() {
        let provider = EphemeralProvider::new();
        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first call creates the key
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second call must reuse it
        assert_eq!(prf_of(&*h1, b"input"), prf_of(&*h2, b"input")); // same underlying key -> same PRF output
    }

    #[test]
    fn different_services_have_different_keys() {
        let provider = EphemeralProvider::new();
        let h1 = provider.load_kek("com.company.orders", true).unwrap();
        let h2 = provider.load_kek("com.company.billing", true).unwrap(); // a different service name
        assert_ne!(prf_of(&*h1, b"input"), prf_of(&*h2, b"input")); // different services must never share a KEK
    }

    #[test]
    fn keys_beyond_one_page_stay_distinct_and_stable() {
        let provider = EphemeralProvider::new();
        // More than one page's worth, so the store has to map a second page.
        let services: Vec<String> = (0..300).map(|i| format!("com.company.paging-test-{i}")).collect();
        let first: Vec<_> = services.iter().map(|s| prf_of(&*provider.load_kek(s, true).unwrap(), b"input")).collect();
        let again: Vec<_> = services.iter().map(|s| prf_of(&*provider.load_kek(s, false).unwrap(), b"input")).collect();
        assert_eq!(first, again, "every key must survive the store growing");
        let distinct: std::collections::HashSet<_> = first.iter().collect();
        assert_eq!(distinct.len(), services.len());
    }

    #[test]
    fn concurrent_access_is_thread_safe() {
        let provider = Arc::new(EphemeralProvider::new());
        let mut handles = Vec::new();

        for i in 0..8 {
            let p = Arc::clone(&provider);
            handles.push(thread::spawn(move || {
                let service = if i % 2 == 0 { "service.a" } else { "service.b" };
                prf_of(&*p.load_kek(service, true).unwrap(), b"input")
            }));
        }

        let outputs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Every thread for one service saw the same key, and the two services' keys differ.
        assert!(outputs.iter().step_by(2).all(|o| *o == outputs[0]));
        assert!(outputs.iter().skip(1).step_by(2).all(|o| *o == outputs[1]));
        assert_ne!(outputs[0], outputs[1]);
    }
}
