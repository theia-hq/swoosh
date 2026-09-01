use super::*;

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
