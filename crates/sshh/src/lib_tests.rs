use super::*;

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
