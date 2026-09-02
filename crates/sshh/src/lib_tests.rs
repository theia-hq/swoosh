use super::*;

#[test]
fn host_seed_derivation_is_byte_frozen() {
    // The host-key seed is a byte-frozen KDF: a client pins the resulting host key in its `known_hosts`, so
    // the derivation MUST reproduce these exact bytes forever. These vectors were captured from the
    // derivation's prior home before it moved into this crate; a mismatch means the host key silently
    // changed under every already-pinned client.
    assert_eq!(
        host_seed(&[0u8; 32]),
        [
            151, 138, 105, 169, 13, 104, 41, 191, 14, 92, 218, 56, 119, 215, 55, 71, 101, 199, 251,
            237, 109, 231, 230, 255, 113, 225, 147, 158, 213, 47, 167, 116
        ],
        "the all-zero secret must derive its frozen host seed"
    );
    let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        host_seed(&secret),
        [
            122, 160, 229, 137, 134, 125, 49, 136, 50, 153, 71, 185, 13, 248, 208, 94, 143, 160,
            225, 86, 61, 41, 106, 190, 227, 244, 37, 162, 103, 244, 91, 5
        ],
        "a non-trivial secret must derive its frozen host seed"
    );
}

#[test]
fn geometry_maps_cols_rows_and_floors_zero_at_one() {
    // A client (cols, rows) maps to the (rows, cols) order `Size::new` takes; a normal geometry passes
    // through untouched.
    assert_eq!(
        clamp_geometry(120, 40),
        (40, 120),
        "returns (rows, cols) from (cols, rows)"
    );
    // A zero dimension (an unset field defaults to 0) is degenerate for a pty, so each floors at 1: a
    // window-change carrying a 0 must never resize the pty to a 0-row/0-col grid that misrenders.
    assert_eq!(clamp_geometry(0, 40), (40, 1), "0 cols floors to 1");
    assert_eq!(clamp_geometry(120, 0), (1, 120), "0 rows floors to 1");
    assert_eq!(clamp_geometry(0, 0), (1, 1), "both floor to 1");
}

#[test]
fn shell_slots_are_capped_and_released() {
    // Reserve the whole ceiling; the next reservation is refused (the fork-bomb guard).
    let mut slots: Vec<ShellSlot> = Vec::new();
    for _ in 0..MAX_LIVE_SHELLS {
        match ShellSlot::acquire() {
            Some(slot) => slots.push(slot),
            None => panic!("reservations under the cap must succeed"),
        }
    }
    assert!(
        ShellSlot::acquire().is_none(),
        "at the cap, a new shell is refused"
    );
    // Releasing one frees exactly one slot, then the cap holds again.
    slots.pop();
    match ShellSlot::acquire() {
        Some(freed) => {
            assert!(
                ShellSlot::acquire().is_none(),
                "still capped after taking the freed slot"
            );
            drop(freed);
        }
        None => panic!("a released slot must reopen"),
    }
    drop(slots);
    assert_eq!(
        LIVE_SHELLS.load(Ordering::Acquire),
        0,
        "every slot released"
    );
}
