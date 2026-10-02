//! `swoosh root forget <dir>`: six checks, each a refusal that writes nothing, then `root.key` goes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::RefCell;
use core::time::Duration;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use keystore::{KeyFile, Passphrase, Protection};
use swoosh::home::Home;
use swoosh::passphrase::{Asked, Choice, Prompt};
use swoosh::root::{Disk, Place, RealDisk};
use swoosh::testkit::{Counting, TestRoot};
use zeroize::Zeroizing;

use super::ForgetCmd;
use crate::commands::invite::invite_tests::{
    LAPTOP, OWN, PASS, copy, device_of, held, holds, live, records, scratch, snapshot,
};

/// Check 4 as a test steers it: a file in the home is on one disk, every other file on another, and the
/// copy's files are dataless or in memory as asked. The inode is the file's own, so a swap shows.
struct FakeDisk {
    home: PathBuf,
    dataless: bool,
    in_memory: bool,
    read: RefCell<Vec<PathBuf>>,
}

impl FakeDisk {
    fn new(home: &Home) -> Self {
        Self {
            home: home.dir().to_path_buf(),
            dataless: false,
            in_memory: false,
            read: RefCell::default(),
        }
    }
}

impl Disk for FakeDisk {
    fn place(&self, path: &Path) -> std::io::Result<Place> {
        self.read.borrow_mut().push(path.to_path_buf());
        let metadata = std::fs::metadata(path)?;
        let in_home = path.starts_with(&self.home);
        Ok(Place {
            dev: if in_home { 1 } else { 2 },
            ino: metadata.ino(),
            dataless: !in_home && self.dataless,
            in_memory: !in_home && self.in_memory,
        })
    }
}

/// A prompt with nobody at a terminal.
struct NoTerminal;

impl Prompt for NoTerminal {
    fn terminal(&self) -> bool {
        false
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        eyre::bail!("no terminal")
    }

    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        eyre::bail!("no terminal")
    }

    fn say(&mut self, _line: &str) {}
}

/// A prompt that runs `meanwhile` while the command waits at it, then answers [`PASS`].
struct Meanwhile<F: FnMut()>(F);

impl<F: FnMut()> Prompt for Meanwhile<F> {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        (self.0)();
        Ok(Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap())
    }

    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        eyre::bail!("nothing is chosen here")
    }

    fn say(&mut self, _line: &str) {}
}

/// A home that keeps `ROOT`, and a copy of it beside, holding the same list: ready to forget.
async fn kept(tag: &str) -> (Home, PathBuf) {
    let home = scratch(tag);
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    holds(&home, &rows, Vec::new()).await;
    let dir = home.dir().with_extension("stick");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &records(1, &rows, Vec::new()));
    (home, dir)
}

/// Run `swoosh root forget <dir>` on `home`: the result, and stderr.
async fn forget(
    home: &Home,
    dir: &Path,
    prompt: &mut impl Prompt,
    disk: &impl Disk,
) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = ForgetCmd {
        dir: dir.to_path_buf(),
    }
    .forget(home, prompt, disk, &mut err)
    .await;
    (result, String::from_utf8(err).unwrap())
}

fn refusal(result: eyre::Result<()>) -> String {
    format!("{:#}", result.expect_err("a refusal"))
}

/// Check 1: with nobody at a terminal, nothing is read or removed. Red when it deletes anyway.
#[tokio::test]
async fn root_forget_without_a_terminal_refuses() {
    let (home, dir) = kept("forget-tty").await;
    let (result, _) = forget(&home, &dir, &mut NoTerminal, &FakeDisk::new(&home)).await;
    assert_eq!(
        refusal(result),
        "this removes your root from this machine, so it needs a terminal: over swoosh ssh, add -t after --"
    );
    assert!(home.root_key().exists());
}

/// Check 2: no root on this machine. Red when it goes on.
#[tokio::test]
async fn root_forget_with_no_root_here_refuses() {
    let home = scratch("forget-device");
    device_of(&home, &live(OWN, "desk")).await;
    let dir = home.dir().with_extension("stick");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &records(1, &[live(OWN, "desk")], Vec::new()));
    let (result, _) = forget(
        &home,
        &dir,
        &mut Counting::refusing(),
        &FakeDisk::new(&home),
    )
    .await;
    assert_eq!(refusal(result), "your root is not on this machine.");
}

/// Check 3: `<dir>` as named, never a search. Red when a copy is looked for elsewhere.
#[tokio::test]
async fn root_forget_of_a_dir_with_no_copy_names_root_backup() {
    let (home, dir) = kept("forget-no-copy").await;
    let empty = dir.with_extension("empty");
    let _ = std::fs::remove_dir_all(&empty);
    std::fs::create_dir(&empty).unwrap();
    let (result, _) = forget(
        &home,
        &empty,
        &mut Counting::refusing(),
        &FakeDisk::new(&home),
    )
    .await;
    let shown = empty.display();
    assert_eq!(
        refusal(result),
        format!("{shown} holds no copy of your root; make one first: swoosh root backup {shown}")
    );
    assert!(home.root_key().exists());
}

/// Check 4: a copy on the home's own disk dies with it. Here both are under the system temp dir, one disk.
/// Red when check 4 is skipped.
#[tokio::test]
async fn root_forget_refuses_a_copy_on_the_homes_filesystem() {
    let (home, dir) = kept("forget-same-disk").await;
    let mut prompt = Counting::new([PASS]);
    let (result, _) = forget(&home, &dir, &mut prompt, &RealDisk).await;
    let refusal = refusal(result);
    let shown = dir.display();
    assert!(
        refusal.starts_with(&format!(
            "{shown} is on the same disk as this machine's home, so it goes wherever this disk goes. Copy \
             your root to another disk first: swoosh root backup {shown}"
        )),
        "{refusal}"
    );
    assert_eq!(prompt.events(), 0, "refused before the passphrase");
    assert!(home.root_key().exists());
}

/// Check 4: a copy in memory is emptied at the next restart. Red when the in-memory read is skipped.
#[tokio::test]
async fn root_forget_refuses_a_copy_the_disk_says_is_in_memory() {
    let (home, dir) = kept("forget-memory-fake").await;
    let disk = FakeDisk {
        in_memory: true,
        ..FakeDisk::new(&home)
    };
    let (result, _) = forget(&home, &dir, &mut Counting::new([PASS]), &disk).await;
    assert_eq!(
        refusal(result),
        format!(
            "{} is kept in memory and is emptied when this machine restarts.",
            dir.display()
        )
    );
    assert!(home.root_key().exists());
}

/// Check 4 on Linux's own tmpfs. Red when the magic is not read.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn root_forget_refuses_a_copy_in_memory() {
    let shm = Path::new("/dev/shm");
    if !shm.is_dir() {
        return;
    }
    let (home, _) = kept("forget-memory").await;
    let dir = shm.join(format!("swoosh-forget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy(
        &dir,
        &records(1, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    let (result, _) = forget(&home, &dir, &mut Counting::new([PASS]), &RealDisk).await;
    assert!(refusal(result).contains("is kept in memory"));
    assert!(home.root_key().exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Check 4: both files dataless pass, even on the home's disk, because the cloud holds them. Red when the
/// disk is checked first.
#[tokio::test]
async fn root_forget_passes_a_dataless_copy() {
    let (home, dir) = kept("forget-dataless").await;
    // Dataless, and on the home's disk: the dataless pass comes first.
    struct SameDiskDataless(FakeDisk);
    impl Disk for SameDiskDataless {
        fn place(&self, path: &Path) -> std::io::Result<Place> {
            let place = self.0.place(path)?;
            Ok(Place { dev: 1, ..place })
        }
    }
    let disk = SameDiskDataless(FakeDisk {
        dataless: true,
        ..FakeDisk::new(&home)
    });
    let (result, err) = forget(&home, &dir, &mut Counting::new([PASS]), &disk).await;
    result.unwrap();
    assert!(!home.root_key().exists());
    assert!(
        err.contains(&format!(
            "Your root is now kept in {}, in the cloud; its passphrase is all that protects it there.",
            dir.display()
        )),
        "{err}"
    );
}

/// Check 4 reads where the copy is before check 5 reads the copy: a copy refused for its place is refused
/// with no prompt and no read of its key, even an unreadable one. Red when the key is read first.
#[tokio::test]
async fn root_forget_checks_the_place_before_it_reads_the_copy() {
    let (home, dir) = kept("forget-place-first").await;
    std::fs::write(dir.join("root.key"), b"not a key").unwrap();
    let mut prompt = Counting::new([PASS]);
    let (result, _) = forget(&home, &dir, &mut prompt, &RealDisk).await;
    assert!(
        refusal(result).contains("is on the same disk as this machine's home"),
        "the place refuses, not the unreadable key"
    );
    assert_eq!(prompt.events(), 0);
}

/// Check 5: a wrong passphrase, three times, deletes nothing. Red when check 5 is skipped.
#[tokio::test]
async fn root_forget_with_a_wrong_passphrase_deletes_nothing() {
    let (home, dir) = kept("forget-wrong").await;
    let before = snapshot(home.dir());
    let mut prompt = Counting::new(["wrong one", "wrong two", "wrong three"]);
    let (result, _) = forget(&home, &dir, &mut prompt, &FakeDisk::new(&home)).await;
    assert_eq!(
        refusal(result),
        format!(
            "that passphrase does not open the copy in {}; your root is still on this machine.",
            dir.display()
        )
    );
    assert_eq!(prompt.events(), 3);
    assert_eq!(
        prompt.said(),
        vec![
            format!(
                "that passphrase does not open the copy in {}.",
                dir.display()
            );
            2
        ]
    );
    assert!(snapshot(home.dir()) == before);
}

/// Check 5: a copy of another root is refused, naming both. Red when the files are compared by bytes only.
#[tokio::test]
async fn root_forget_refuses_another_root() {
    let (home, dir) = kept("forget-other").await;
    std::fs::remove_file(dir.join("root.key")).unwrap();
    let other = TestRoot::seeded(0x31);
    let mut seed = other.seed();
    let passphrase = Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap();
    KeyFile::root(dir.join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .unwrap();
    let (result, _) = forget(
        &home,
        &dir,
        &mut Counting::new([PASS]),
        &FakeDisk::new(&home),
    )
    .await;
    assert_eq!(
        refusal(result),
        format!(
            "the copy in {} is root:{}, and yours is root:{}; your root is still on this machine.",
            dir.display(),
            swoosh::credential::short(&other.node_id()),
            swoosh::credential::short(&TestRoot::seeded(0x21).node_id())
        )
    );
    assert!(home.root_key().exists());
}

/// Check 5: a copy locked again under another passphrase passes; the files need not match byte for byte.
/// Red when equal bytes are required.
#[tokio::test]
async fn root_forget_passes_a_relocked_copy() {
    let (home, dir) = kept("forget-relocked").await;
    let fresh = "a fresh passphrase for the stick";
    swoosh::root::lock(&home, Some(&dir), &mut Counting::new([PASS, fresh]))
        .await
        .unwrap();
    assert_ne!(
        std::fs::read(dir.join("root.key")).unwrap(),
        std::fs::read(home.root_key()).unwrap()
    );
    let (result, _) = forget(
        &home,
        &dir,
        &mut Counting::new([fresh]),
        &FakeDisk::new(&home),
    )
    .await;
    result.unwrap();
    assert!(!home.root_key().exists());
}

/// Check 6: a copy whose list is older is brought up to date, and says so, before the root goes. Red when
/// the root is deleted first.
#[tokio::test]
async fn root_forget_brings_an_older_copy_up_to_date_before_it_deletes() {
    let (home, dir) = kept("forget-older").await;
    held(
        &home,
        &records(2, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    let (result, err) = forget(
        &home,
        &dir,
        &mut Counting::new([PASS]),
        &FakeDisk::new(&home),
    )
    .await;
    result.unwrap();
    assert_eq!(
        std::fs::read(dir.join("devices")).unwrap(),
        std::fs::read(home.devices()).unwrap()
    );
    assert!(
        err.starts_with(&format!(
            "brought the copy in {} up to date with this machine's list of your devices.\n",
            dir.display()
        )),
        "{err}"
    );
    assert!(!home.root_key().exists());
}

/// Check 6 into a synced copy writes the list and stops: the update must reach the cloud, and the file be
/// evicted, before the root goes. Red when it deletes in the same run.
#[tokio::test]
async fn root_forget_into_a_synced_copy_writes_the_list_and_stops() {
    let (home, dir) = kept("forget-synced").await;
    held(
        &home,
        &records(2, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    let disk = FakeDisk {
        dataless: true,
        ..FakeDisk::new(&home)
    };
    let (result, err) = forget(&home, &dir, &mut Counting::new([PASS]), &disk).await;
    let shown = dir.display();
    assert_eq!(
        refusal(result),
        format!(
            "brought the copy in {shown} up to date; your root is still on this machine. {shown} is in a \
             synced folder: once the update reaches the cloud, choose Remove Download on {shown}, then run it \
             again: swoosh root forget {shown}"
        )
    );
    assert!(err.is_empty(), "one line, the refusal: {err}");
    assert!(home.root_key().exists(), "nothing deleted");
    assert_eq!(
        std::fs::read(dir.join("devices")).unwrap(),
        std::fs::read(home.devices()).unwrap()
    );
}

/// Under the lock, the copy's files are confirmed by device and inode: a key swapped while the command
/// waited at its prompt refuses. Red when the first read is trusted.
#[tokio::test]
async fn root_forget_confirms_the_copy_by_device_and_inode_under_the_lock() {
    let (home, dir) = kept("forget-swapped").await;
    let key = dir.join("root.key");
    let mut prompt = Meanwhile(|| {
        let swap = key.with_extension("swap");
        std::fs::copy(&key, &swap).unwrap();
        std::fs::rename(&swap, &key).unwrap();
    });
    let (result, _) = forget(&home, &dir, &mut prompt, &FakeDisk::new(&home)).await;
    assert!(refusal(result).starts_with(&format!(
        "the copy in {} changed while this ran",
        dir.display()
    )));
    assert!(home.root_key().exists());
}

/// `home.lock` is taken after the prompt: another change to the home completes while forget waits there.
/// Red when the lock is taken first.
#[tokio::test]
async fn root_forget_takes_the_home_lock_after_the_prompt() {
    let (home, dir) = kept("forget-lock-late").await;
    let other = home.clone();
    let mut took = false;
    let mut prompt = Meanwhile(|| {
        let (sent, got) = std::sync::mpsc::channel();
        let other = other.clone();
        std::thread::spawn(move || {
            let _ = sent.send(swoosh::home::HomeWrite::wait(&other).is_ok());
        });
        took = got.recv_timeout(Duration::from_secs(5)).unwrap_or(false);
    });
    let (result, _) = forget(&home, &dir, &mut prompt, &FakeDisk::new(&home)).await;
    result.unwrap();
    assert!(took, "home.lock was free while forget waited at its prompt");
}

/// A run killed after check 6's write and before the delete left the copy up to date and the root here:
/// running it again finishes. Red when that state is refused.
#[tokio::test]
async fn root_forget_killed_after_the_list_is_finished_by_running_it_again() {
    let (home, dir) = kept("forget-killed").await;
    held(
        &home,
        &records(2, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    // What check 6 wrote before the kill.
    std::fs::copy(home.devices(), dir.join("devices")).unwrap();
    let (result, err) = forget(
        &home,
        &dir,
        &mut Counting::new([PASS]),
        &FakeDisk::new(&home),
    )
    .await;
    result.unwrap();
    assert!(
        !err.contains("brought the copy"),
        "nothing left to bring: {err}"
    );
    assert!(!home.root_key().exists());
}

/// The success line says where the root is kept and that system backups still hold it, and never that no
/// copy is left on this machine. Red when it claims none is.
#[tokio::test]
async fn root_forget_success_line_never_says_no_copy_is_left() {
    let (home, dir) = kept("forget-line").await;
    let (result, err) = forget(
        &home,
        &dir,
        &mut Counting::new([PASS]),
        &FakeDisk::new(&home),
    )
    .await;
    result.unwrap();
    let shown = dir.display();
    assert_eq!(
        err,
        format!(
            "removed your root from this machine. Your root is now kept in {shown}. Keep it away from this \
             machine. Use it with --root {shown}. System backups made before now still hold it, locked \
             with its passphrase.\n"
        )
    );
    assert!(!err.contains("no copy"));
    assert!(matches!(
        swoosh::standing::Standing::read(&home).await.unwrap(),
        swoosh::standing::Standing::Device { .. }
    ));
}
