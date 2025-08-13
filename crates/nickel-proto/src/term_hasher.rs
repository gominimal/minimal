//! Fast hashing of concrete nickel records.

use nickel_lang_core::term::{SharedTerm, Term};
use std::collections::HashMap;

use fxhash::FxHasher;
use std::hash::{Hash, Hasher};

/// TermHasher rapidly computes hashes for [SharedTerm] objects.
///
/// TermHasher must outlive all SharedTerm objects it computes hashes for,
/// otherwise results may be incorrect.
pub struct TermHasher {
    seen: HashMap<*const Term, u64>,
}

impl Default for TermHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl TermHasher {
    pub fn new() -> Self {
        Self {
            seen: HashMap::with_capacity(2048),
        }
    }

    pub fn hash(&mut self, st: &SharedTerm) -> u64 {
        // SAFETY: The pointer is used as an integer to key caching of the hash value.
        // Invalidation of any underlying Rc will not lead to UD because the pointer
        // is never dereferenced.
        let underlying_ptr = unsafe {
            let spooky: std::rc::Rc<Term> = std::mem::transmute(st.clone());
            std::rc::Rc::as_ptr(&spooky)
        };

        if let Some(known_val) = self.seen.get(&underlying_ptr) {
            return *known_val;
        }

        let mut hash = FxHasher::default();
        match st.as_ref() {
            Term::Bool(b) => hash.write_u8(if *b { 1 } else { 0 }),
            Term::Num(n) => n.hash(&mut hash),
            Term::Str(s) => hash.write(s.as_bytes()),
            Term::Enum(i) => hash.write(i.label().as_bytes()),
            Term::Array(a, _attrs) => a.iter().for_each(|t| hash.write_u64(self.hash(&t.term))),

            Term::Record(r) => {
                r.fields.iter().for_each(|(ident_and_loc, field)| {
                    hash.write(ident_and_loc.label().as_bytes());
                    hash.write_u64(self.hash(&field.value.as_ref().unwrap().term));
                });
            }

            _ => panic!("unexpected Term variant: {:#?}", st.as_ref()),
        }

        let hash = hash.finish();
        self.seen.insert(underlying_ptr, hash);
        hash
    }
}
