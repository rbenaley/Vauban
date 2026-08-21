//! Per-request string intern so Topcoat 0.6 `#[memoize]` can key on `Copy` ids.
//!
//! 0.6 hashes memo arguments by borrow for the whole call: `&str` trips HRTB
//! (`AsyncFnOnce` is not general enough) and `String` cannot be moved in the
//! body. Interning behind [`Cx::with`] keeps request-scoped dedup.

use std::sync::Mutex;

use topcoat::context::{Cx, try_request_context};

/// Inserted on every request by the root security layer.
#[derive(Default)]
pub struct StringIntern {
    slots: Mutex<Vec<String>>,
}

impl StringIntern {
    fn insert(&self, s: &str) -> usize {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((i, _)) = slots.iter().enumerate().find(|(_, v)| v.as_str() == s) {
            return i;
        }
        let i = slots.len();
        slots.push(s.to_owned());
        i
    }

    fn get(&self, id: usize) -> String {
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .get(id)
            .cloned()
            .expect("string intern id must come from intern()")
    }
}

/// Intern `s` for this request. Panics if the root layer did not register
/// [`StringIntern`] (every portal router must).
pub fn intern(cx: &Cx, s: &str) -> usize {
    try_request_context::<StringIntern>(cx)
        .expect("StringIntern missing from request context")
        .insert(s)
}

/// Resolve an id from [`intern`].
pub fn interned(cx: &Cx, id: usize) -> String {
    try_request_context::<StringIntern>(cx)
        .expect("StringIntern missing from request context")
        .get(id)
}
