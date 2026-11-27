//! Keys, prompts and peers for tests, and the only place test code signs anything.
//!
//! A test that needs a signed badge, slip or document asks a [`TestRoot`] or a [`TestNode`] for it rather
//! than building a `nauthy::Identity` and minting with it. So signing stays in a few named places: the
//! product's own signers, and this module for tests.
//!
//! Compiled for the lib's own tests and under the `test-support` feature, which the package turns on for
//! itself as a dev-dependency, so the bin's unit tests and `tests/` reach it as `swoosh::testkit`. A plain
//! `cargo build` never compiles it.
//!
//! Keys are seeded by one byte, the secret being that byte 32 times, so a fixture names its key the same
//! way in every test and every run.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::ops::Deref;
use std::collections::VecDeque;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{Health, Passphrase};
use nauthy::{Cap, CapError, Identity, Link, Service, Signed, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use crate::contacts::DeviceLabel;
use crate::home::{Home, HomeWrite, ServeLock};
use crate::passphrase::{Asked, Choice, Prompt};
use crate::roster::{Member, RevokedDevice, RosterDoc};
use crate::serve::{Internet, Lan, ReachSource, Reachable};
use crate::sync::{Answer, Dial, ExchangeError};
use crate::touch::{Touch, TouchHere, Touched};

pub mod banner;
pub mod touch_id;

/// The four bytes that open every control frame this build writes, so a test that hand-builds a frame
/// names the tag the build speaks and never spells it out. A spelled-out tag goes stale at a version bump,
/// and the frame is then refused as another build's, which a test asserting only "refused" reads as green.
pub const CONTROL_MAGIC: [u8; 4] = crate::serve::CONTROL_MAGIC;

/// A control frame: [`CONTROL_MAGIC`], then `rest` (the tag, the length and any body), as written.
pub fn control_frame(rest: &[u8]) -> Vec<u8> {
    [CONTROL_MAGIC.as_slice(), rest].concat()
}

/// A control frame's seven-byte header: [`CONTROL_MAGIC`], the tag, then the declared length, big-endian.
pub const fn control_header(tag: u8, len: u16) -> [u8; 7] {
    let [i, d, c, v] = CONTROL_MAGIC;
    let [high, low] = len.to_be_bytes();
    [i, d, c, v, tag, high, low]
}

/// A test resident's reach: a bind of `127.0.0.1:51006` alone, which expands with no read of this host.
pub fn loopback_source() -> ReachSource {
    ReachSource::new(vec![LOOPBACK], Internet::On, Lan::Announced)
}

/// What [`loopback_source`] answers: on, announced, and loopback alone. For a status fixture.
pub fn loopback_reach() -> Reachable {
    loopback_source().reachable()
}

/// The loopback socket the reach fixtures bind.
const LOOPBACK: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51006));

/// A revoked device for an update: `node`, under the name `gone`, which any number of revoked devices may
/// share. For a test that needs only the key revoked; one that reads the name builds its own.
///
/// # Panics
///
/// Never: `gone` is a stored name.
#[expect(clippy::expect_used, reason = "a fixed name that parses")]
pub fn revoked(node: VerifyKey) -> RevokedDevice {
    RevokedDevice {
        node,
        label: DeviceLabel::stored("gone").expect("a stored name"),
    }
}

/// A held `home.lock` for a test's own setup writes: the lock of a scratch home of its own, so a fixture
/// writing a file never waits on, or holds up, the home under test.
///
/// # Panics
///
/// When the scratch home or its lock cannot be made.
#[expect(
    clippy::expect_used,
    reason = "a test fixture that cannot lock stops the test"
)]
pub fn lock() -> HomeWrite {
    static SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swoosh-lock-{}-{seq}", std::process::id()));
    let home = Home::resolve(Some(dir)).expect("a scratch home for the lock");
    HomeWrite::wait(&home).expect("take the scratch home's lock")
}

/// A gate admitting the devices of `root` and the cut built beside it, as `serve --admit` builds them for
/// this machine `own`, over a fresh empty home: what a test binds `control.serve` with, since its
/// revocations come only from the cut. The home is returned for its `revoked` file; the caller removes it.
///
/// # Panics
///
/// When the scratch home or the gate cannot be made.
#[expect(
    clippy::expect_used,
    reason = "a test fixture that cannot build the gate stops the test"
)]
pub async fn admitting(root: NodeId, own: NodeId) -> (nauthy::Gate, crate::gate::AnchorCut, Home) {
    static SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swoosh-admitting-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).expect("the scratch store dir");
    let home = Home::resolve(Some(dir)).expect("a scratch home for the gate");
    let (gate, cut) = crate::gate::anchored_admitting(
        &home,
        own,
        Some(root.verify_key().expect("a usable root key")),
        crate::serve::BoundTargets::default(),
    )
    .await
    .expect("the gate builds");
    (gate, cut, home)
}

/// Whether the `serve` gate of `home`, built as `serve` builds it for this machine `own`, admits the device
/// `peer` presenting `standing` to the service `demo`. The gate reads `revoked` and never the list, so this
/// asks what a dial is answered.
///
/// # Panics
///
/// When the gate cannot be built, or `standing` is not a link.
#[expect(
    clippy::expect_used,
    reason = "a test fixture that cannot build the gate stops the test"
)]
pub async fn serve_admits(home: &Home, own: NodeId, peer: VerifyKey, standing: &Link) -> bool {
    let (gate, _cut) = crate::gate::anchored(home, own, crate::serve::BoundTargets::default())
        .await
        .expect("build the serve gate");
    let cap = Cap::parse(standing.as_str()).expect("a standing is a link");
    let service: Service = "demo".parse().expect("a service name");
    matches!(
        gate.admit(
            nauthy::ProvenPeer::from_handshake(peer),
            Some(&cap),
            &service
        ),
        nauthy::Decision::Admit
    )
}

/// `serve.lock` held the way a running `serve` holds it: taken under the home's own `home.lock`, recording
/// this process and, under `--admit`, the root it admits. A test holds it to stand for a `serve` of `home`.
///
/// # Panics
///
/// When the lock is held already, or cannot be taken or written.
#[expect(
    clippy::expect_used,
    reason = "a test fixture that cannot lock stops the test"
)]
pub fn serving(home: &Home, admit: Option<NodeId>) -> ServeLock {
    let home_lock = HomeWrite::wait(home).expect("take home.lock");
    let held = ServeLock::take(&home_lock, home).expect("take serve.lock");
    held.record(&home_lock, admit).expect("record the serve");
    held
}

/// The key the seed `[7; 32]` binds plus a point of order 8: the torsioned twin of a real key, which
/// the holder of that key's secret can sign for. nauthy's and bifrost's own tests use these bytes.
pub const TORSIONED: [u8; 32] = [
    0x1f, 0x4f, 0x58, 0x0e, 0x73, 0xac, 0x20, 0x8f, 0x06, 0x76, 0x01, 0x90, 0xe9, 0xed, 0xc6, 0xf5,
    0x91, 0x67, 0x75, 0xda, 0xbd, 0x9c, 0x1c, 0xdc, 0xa3, 0x93, 0x17, 0x5c, 0x2d, 0x6d, 0x10, 0x83,
];

/// [`TORSIONED`] as key text, the way a person would paste it.
pub fn torsioned_text() -> String {
    format!(
        "ed01{}",
        data_encoding::BASE32_NOPAD
            .encode(&TORSIONED)
            .to_ascii_lowercase()
    )
}

/// When a test standing ends, in unix seconds: far enough out that no test outlives it.
pub const STANDING_UNTIL: u64 = 4_000_000_000;

/// A root's key: what signs device badges, a fleet's documents, and the slips a root holder issues.
pub struct TestRoot(Keys);

/// A device's or a server's own key: what signs the slips a node issues, and a badge it signs for itself.
pub struct TestNode(Keys);

impl TestRoot {
    /// The root whose secret is `byte`, 32 times.
    pub fn seeded(byte: u8) -> Self {
        Self(Keys::from_seed([byte; 32]))
    }

    /// The root whose secret is `seed`: a key a test read off disk, where the product wrote it.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Keys::from_seed(seed))
    }
}

impl TestNode {
    /// The node whose secret is `byte`, 32 times.
    pub fn seeded(byte: u8) -> Self {
        Self(Keys::from_seed([byte; 32]))
    }

    /// The node whose secret is `seed`: a key a test read off disk, where the product wrote it.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Keys::from_seed(seed))
    }
}

impl Deref for TestRoot {
    type Target = Keys;

    fn deref(&self) -> &Keys {
        &self.0
    }
}

impl Deref for TestNode {
    type Target = Keys;

    fn deref(&self) -> &Keys {
        &self.0
    }
}

/// One seeded key and everything a test signs with it. Reached through a [`TestRoot`] or a
/// [`TestNode`], which say which role the key plays in the test.
pub struct Keys {
    seed: [u8; 32],
    identity: Identity,
}

// Test code signs only through these methods: every signing call a test makes lands here.
#[allow(clippy::disallowed_methods)]
impl Keys {
    fn from_seed(seed: [u8; 32]) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "every 32 bytes are an ed25519 secret, so this cannot fail"
        )]
        let identity = Identity::from_secret(&seed).expect("32 bytes are an ed25519 secret");
        Self { seed, identity }
    }

    /// The secret, for a test that binds a transport or writes a key file under this same key.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// The public key: what a badge or slip signed here roots at.
    pub fn verify_key(&self) -> VerifyKey {
        self.identity.verifying_key()
    }

    /// The node id a transport bound under this key answers at.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_ed25519_secret(&self.seed)
    }

    /// The signing identity, for a product call that takes one (a roster write, say). A test signs
    /// through the methods here, never through this.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// A membership badge for `bound`, until `until`: the cap a gate reads as "one of my devices" when
    /// the dialer proves it is `bound`.
    pub fn member_badge(&self, bound: VerifyKey, until: SystemTime) -> Result<Cap, CapError> {
        self.identity.mint_member(bound, until)
    }

    /// A membership badge for `device`, until `until`, sealed and in the bare form a device stores
    /// and presents.
    pub fn device_badge(&self, device: NodeId, until: SystemTime) -> Result<Link, CapError> {
        #[expect(
            clippy::expect_used,
            reason = "a test key is a key its own secret binds, so it is a usable key"
        )]
        let device = device.verify_key().expect("a test key is a usable key");
        self.member_badge(device, until)?.seal()?.link()
    }

    /// A live device for an update: `node`, named `label`, carrying this root's sealed badge for it as its
    /// standing, with no ids and no renewal.
    pub fn member(&self, node: VerifyKey, label: DeviceLabel) -> Result<Member, CapError> {
        Ok(Member {
            node,
            label,
            until: STANDING_UNTIL,
            duration: 0,
            invite_until: 0,
            ids: Vec::new(),
            standing: self.standing(node)?,
        })
    }

    /// This root's sealed badge for `node`, bare: the standing an update carries for it.
    pub fn standing(&self, node: VerifyKey) -> Result<Link, CapError> {
        self.member_badge(
            node,
            SystemTime::UNIX_EPOCH + core::time::Duration::from_secs(STANDING_UNTIL),
        )?
        .seal()?
        .link()
    }

    /// A slip for `service`, until `until`, that anyone holding it may present or narrow.
    pub fn slip(&self, service: &Service, until: SystemTime) -> Result<Cap, CapError> {
        self.identity.mint(service, until)
    }

    /// A slip for `service`, until `until`, that grants only when the dialer proves it is `peer`. Sealed,
    /// as every bound slip is issued.
    pub fn bound_slip(
        &self,
        service: &Service,
        peer: VerifyKey,
        until: SystemTime,
    ) -> Result<Link, CapError> {
        self.identity
            .mint_bound(service, peer, until)?
            .seal()?
            .link()
    }

    /// A slip for `service`, until `until`, that grants any device the root `authority` vouches for.
    /// Sealed, as every fleet slip is issued.
    pub fn fleet_slip(
        &self,
        service: &Service,
        authority: VerifyKey,
        until: SystemTime,
    ) -> Result<Link, CapError> {
        self.identity
            .mint_authority_slip(service, authority, until)?
            .seal()?
            .link()
    }

    /// `bytes`, signed by this key.
    pub fn sign(&self, bytes: &[u8]) -> Signed {
        self.identity.sign_document(bytes)
    }

    /// `doc`, signed by this key: the bytes a root act cuts and every device serves.
    pub fn sign_update(&self, doc: &RosterDoc) -> Vec<u8> {
        self.sign(&doc.canonical_bytes()).encode()
    }
}

/// Device badges no mint here can sign, for a reader that must refuse them. Each was signed once, by
/// hand, by the root seeded [`ROOT_SEED`](hand_signed::ROOT_SEED) for the node seeded
/// [`DEVICE_SEED`](hand_signed::DEVICE_SEED), and is kept as its text. Each is a sealed membership badge
/// bound to that node, like one [`Keys::device_badge`] signs, except for its end date.
pub mod hand_signed {
    use nauthy::Link;

    /// The root that signed every badge here.
    pub const ROOT_SEED: u8 = 0x21;
    /// The node every badge here is bound to.
    pub const DEVICE_SEED: u8 = 0x11;

    /// A badge signed the way roots did before a badge carried its end date as a fact: the date lives
    /// only in its check (2100-01-01), so `Cap::expiry` reads `None`.
    pub fn without_end_date() -> Link {
        parse(WITHOUT_END_DATE)
    }

    /// A badge whose signed end date is past what the clock can hold, so `Cap::expiry` reads an error.
    pub fn unreadable_end_date() -> Link {
        parse(UNREADABLE_END_DATE)
    }

    fn parse(text: &str) -> Link {
        #[expect(
            clippy::expect_used,
            reason = "each text here is a link, checked by the testkit's own tests"
        )]
        text.parse().expect("a hand-signed badge is a link")
    }

    const WITHOUT_END_DATE: &str = "ed01rbfyqv7u5kqwcpdbkbg3gtkl5lzumul2byy54pg52tm3iia5tufq.ckmqecvmaefac5akbrrg65lomrpwizlwnfrwkcqbmqfdqzlegayteytgnrsw25dvmzxte23xn5yxi3tdgz2w2ztqmu2dg2ldmvzxm6denfqxo6dmgrtgky3sorthg3dyoe2dg4iyayraqcqgbaibearqaezcqcrgbibaqgysa4eakeqdbcaaqgqxbicquayiqaeaucakayqibluzuqhquba2aieaemrgbisauaqidmjaqcebbajagcecbanbicqfbibqraqibicquayyqmeauba2aiebkerebaabeifqk67j22xh2mu6rwlzxjnzbi66piekhsxwpzqxahcdjfmuhhbnj4nealxd2ly2ajegwkevrwpmm3ui4laauy6rtqkaeasmpwq44blbilzweqwwmcj2sfoxjpv425samojhh5xdaegl7zoavxf2f2asbg4qvygcqajciijearash43atdmnpnprgjgciqrdu5uj6ikrvb6xh4w6g2fujuiysgvt3re3vm7awnx574nflr7drqhltlxpd2o254o5mrkmezhcm2a724ca";

    const UNREADABLE_END_DATE: &str = "ed01rbfyqv7u5kqwcpdbkbg3gtkl5lzumul2byy54pg52tm3iia5tufq.ck7aecwraefauzlyobuxezltl5qxicqboqfayytpovxgix3emv3gsy3fbiawicrymvsdamjsmjtgyzlnor2wm3zsnn3w64lunzrtm5lnmzygknbtnfrwk43wpbsgsylxpbwdiztfmnzhizttnr4hcnbtoemamiqibidaqeasaiyaciqsbiiaraaicifsb77777777777777qcmrnbivquaqidmjaocafcibqraiidioaubikameiccakbufawih77777777777776aikaqnaecacgitaujakaiebweqibcbaqeqdbcbqqgqubicquayiqmeaubikammiicakaqnaecavcisaqaaseczpw4arhdawc5evu7eewkf4zwzfvzatltsllzvuoapwcbgs3j3pggsa2scnkknecq6w5ehdo5li62ghci3yhglq6mstgyvxlxnjxu54xsjy2daj26gwzop45b6v6ue7w74yz3mk7eu6sbc25adobrcapenu2driaereeesavqcob3tukcm4xzxcrte7ty6bpjy2wcqniqczybsk2hqsnggwiev44vjnypzfxem7cxxdh2lnoqhvfk7pjofr3h5lkgcosm3sibri4di";
}

/// The key the key file `file` holds, by its header for a sealed one: what a test compares a home's key to.
///
/// # Panics
///
/// When there is no key file, or it cannot be read.
#[allow(clippy::expect_used)]
pub fn stored_key(file: &keystore::KeyFile) -> NodeId {
    let stored = file
        .load()
        .expect("the key file reads")
        .expect("a key file is there");
    crate::identity::key_of(file, &stored).expect("the key file names a key")
}

/// What a [`Counting`] runs on a touch before it answers, as [`Counting::publishing`] sets it.
type Publish = Box<dyn FnMut(&Touch)>;

/// A [`Prompt`] that counts prompt events and the passphrases they read, answers from a script, and keeps
/// what it was told between tries.
///
/// A touch is scripted on its own: whether one may be asked here ([`at_this_mac`](Self::at_this_mac),
/// [`here`](Self::here)), how a `touch-id` lock reads, and how each touch ends
/// ([`touching`](Self::touching)). Unscripted, it asks for none, as a build with no enclave does. Every touch
/// asked for is kept, act and all ([`touches`](Self::touches)), and one with no answer left fails.
///
/// One event is one call to `unlock` or `choose`, whatever the terminal behind it would read: one round of
/// `choose` asks for the passphrase twice, and is still one event of two reads. A call with no answer left is
/// still an event: it refuses the way a missing terminal does, after being asked. So a test that scripts
/// nothing and reads a count of zero proves nothing was asked. A `choose` answer is held to the minimum as a
/// typed one is, and an empty one stands for a mismatched round.
pub struct Counting {
    answers: VecDeque<&'static str>,
    events: usize,
    reads: usize,
    said: Vec<String>,
    warned: Vec<String>,
    here: TouchHere,
    health: Option<Health>,
    touched: VecDeque<Touched>,
    touches: Vec<Touch>,
    publish: Option<Publish>,
}

impl Counting {
    /// A prompt that answers each event with the next of `answers`, in order.
    pub fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            events: 0,
            reads: 0,
            said: Vec::new(),
            warned: Vec::new(),
            here: TouchHere::NoEnclave,
            health: None,
            touched: VecDeque::new(),
            touches: Vec::new(),
            publish: None,
        }
    }

    /// At this Mac's own terminal, where every `touch-id` lock reads `health`.
    #[must_use]
    pub fn at_this_mac(self, health: Health) -> Self {
        Self {
            here: TouchHere::Here,
            health: Some(health),
            ..self
        }
    }

    /// Where a touch may or may not be asked, as `here` says.
    #[must_use]
    pub fn here(self, here: TouchHere) -> Self {
        Self { here, ..self }
    }

    /// Each touch asked for ends as the next of `touched`, in order.
    #[must_use]
    pub fn touching(self, touched: impl IntoIterator<Item = Touched>) -> Self {
        Self {
            touched: touched.into_iter().collect(),
            ..self
        }
    }

    /// Before each touch answers, `publish` runs on it, standing in for what the key store's act would leave
    /// on disk: a scripted touch writes nothing itself, so a test that reads the file after needs this.
    #[must_use]
    pub fn publishing(self, publish: impl FnMut(&Touch) + 'static) -> Self {
        Self {
            publish: Some(Box::new(publish)),
            ..self
        }
    }

    /// Every touch asked for, in order.
    pub fn touches(&self) -> &[Touch] {
        &self.touches
    }

    /// A prompt with no answers: every event refuses.
    pub fn refusing() -> Self {
        Self::new([])
    }

    /// How many prompt events there have been.
    pub fn events(&self) -> usize {
        self.events
    }

    /// How many passphrases the events read: one per `unlock`, two per `choose`.
    pub fn reads(&self) -> usize {
        self.reads
    }

    /// What the prompt was told between tries, in order, warnings included.
    pub fn said(&self) -> &[String] {
        &self.said
    }

    /// What the prompt was warned of, in order: the lines bound for stderr.
    pub fn warned(&self) -> &[String] {
        &self.warned
    }

    fn answer(&mut self, reads: usize) -> eyre::Result<Zeroizing<String>> {
        self.events += 1;
        self.reads += reads;
        let answer = self
            .answers
            .pop_front()
            .ok_or_else(|| eyre::eyre!("no scripted answer left"))?;
        Ok(Zeroizing::new(answer.to_owned()))
    }
}

impl Prompt for Counting {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        crate::passphrase::passphrase(self.answer(1)?)
    }

    /// Not the terminal's choosing round, which is tested through its own seam: an empty answer here is a
    /// mismatch, where at a terminal Enter makes a passphrase.
    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        // The terminal's round reads one entry for a short passphrase, which ends it before `again:`, and two
        // otherwise.
        let text = self.answer(0)?;
        if text.is_empty() {
            self.reads += 2;
            return Ok(Choice::Mismatch);
        }
        let choice = crate::passphrase::chosen(text)?;
        self.reads += match choice {
            Choice::Short => 1,
            Choice::Chosen(_) | Choice::Mismatch => 2,
        };
        Ok(choice)
    }

    fn say(&mut self, line: &str) {
        self.said.push(line.to_owned());
    }

    /// Kept beside what was said, in the same order, and apart in [`warned`](Self::warned), so a test reads
    /// the conversation whole and each channel on its own.
    fn warn(&mut self, line: &str) {
        self.said.push(line.to_owned());
        self.warned.push(line.to_owned());
    }

    fn touch_here(&self) -> TouchHere {
        self.here
    }

    /// The scripted reading, for a file that has a `touch-id` lock.
    fn health(&self, locked: &keystore::Locked) -> Option<Health> {
        locked
            .methods()
            .any(|method| method == keystore::Method::TouchId)
            .then_some(self.health)
            .flatten()
    }

    fn touch(&mut self, touch: Touch) -> Touched {
        if let Some(publish) = &mut self.publish {
            publish(&touch);
        }
        self.touches.push(touch);
        self.touched
            .pop_front()
            .unwrap_or_else(|| Touched::Failed(eyre::eyre!("no scripted touch left")))
    }
}

/// A [`Dial`] that runs each exchange in process: the dialer is `home`, and the device dialed answers from
/// its own home, over an in-memory stream. A key with no home here does not answer. Every dial is recorded.
pub struct Loopback {
    home: Home,
    devices: Vec<(NodeId, Home)>,
    dialed: std::sync::Mutex<Vec<NodeId>>,
}

impl Loopback {
    /// Exchanges from `home` with each of `devices`, by key.
    pub fn new(home: Home, devices: impl IntoIterator<Item = (NodeId, Home)>) -> Self {
        Self {
            home,
            devices: devices.into_iter().collect(),
            dialed: std::sync::Mutex::default(),
        }
    }

    /// Every key dialed so far, in order.
    pub fn dialed(&self) -> Vec<NodeId> {
        self.dialed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Loopback {
    /// Run one exchange with `peer`, this side offering `offered` (the update at a number, and its bytes)
    /// or, on `None`, the update the home holds.
    async fn run(
        &self,
        peer: NodeId,
        offered: Option<(crate::roster::Epoch, &[u8])>,
    ) -> Result<Answer, ExchangeError> {
        self.dialed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(peer);
        let Some((_, server)) = self.devices.iter().find(|(key, _)| *key == peer) else {
            return Err(eyre::eyre!("no device answers at that key").into());
        };
        let (near, far) = tokio::io::duplex(64 * 1024);
        let (near_read, near_write) = tokio::io::split(near);
        let (far_read, far_write) = tokio::io::split(far);
        let dialer = async {
            match offered {
                Some((number, bytes)) => {
                    crate::sync::offer(&self.home, number, bytes, near_read, near_write).await
                }
                None => crate::sync::exchange(&self.home, near_read, near_write).await,
            }
        };
        // Permits of this run alone, so whose key takes one does not matter.
        let receive = crate::sync::Receive::new();
        let caller = TestNode::seeded(0).verify_key();
        let (dialed, answered) = tokio::join!(
            dialer,
            crate::sync::answer(server, &receive, caller, far_read, far_write)
        );
        // A server that closes without answering is, to the dialer, one that did not answer.
        answered?;
        dialed
    }
}

impl Dial for Loopback {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        self.run(peer, None).await
    }

    async fn offer(
        &self,
        peer: NodeId,
        number: crate::roster::Epoch,
        bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.run(peer, Some((number, bytes))).await
    }
}

/// A [`Dial`] every device answers with the same [`Answer`], touching nothing. Every dial is counted.
pub struct Answering {
    answer: Option<Answer>,
    calls: core::sync::atomic::AtomicUsize,
}

impl Answering {
    /// Every device answers `answer`.
    pub fn with(answer: Answer) -> Self {
        Self {
            answer: Some(answer),
            calls: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// No device answers.
    pub fn nobody() -> Self {
        Self {
            answer: None,
            calls: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many exchanges were dialed.
    pub fn calls(&self) -> usize {
        self.calls.load(core::sync::atomic::Ordering::SeqCst)
    }
}

impl Dial for Answering {
    async fn exchange(&self, _peer: NodeId) -> Result<Answer, ExchangeError> {
        self.calls
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        self.answer
            .ok_or_else(|| eyre::eyre!("no device answers").into())
    }

    async fn offer(
        &self,
        peer: NodeId,
        _number: crate::roster::Epoch,
        _bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.exchange(peer).await
    }
}

/// A test double's stream write half: the writer it wraps, plus the [`bifrost::WriteEnd`] every
/// [`Session::Write`](bifrost::Session::Write) must carry.
///
/// An abort drops the writer, so a later write or shutdown fails with `BrokenPipe`. The far end never
/// reads the `ConnectionReset` a real transport gives: a whole in-memory pipe reads a clean end, and a
/// split `WriteHalf` ends nothing, since its read half still holds the pipe. A test that pins how an abort
/// reads at the peer needs a real transport, not this.
pub struct TestWrite<W> {
    writer: Option<W>,
    /// Fired by the far end once it has read the stream to its end, when the double has one to ask.
    read_to_end: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl<W> From<W> for TestWrite<W> {
    fn from(writer: W) -> Self {
        Self {
            writer: Some(writer),
            read_to_end: None,
        }
    }
}

impl<W> TestWrite<W> {
    /// `writer`, whose delivery is confirmed when the far end fires `read_to_end`, as a transport's is
    /// once the peer holds every byte and the end.
    pub fn read_by(writer: W, read_to_end: tokio::sync::oneshot::Receiver<()>) -> Self {
        Self {
            writer: Some(writer),
            read_to_end: Some(read_to_end),
        }
    }

    /// The live writer, or the `BrokenPipe` an aborted half answers every call with.
    // `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn live(&mut self) -> std::io::Result<&mut W> {
        self.writer
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TestWrite<W> {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        match self.get_mut().live() {
            Ok(writer) => core::pin::Pin::new(writer).poll_write(cx, buf),
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        match self.get_mut().live() {
            Ok(writer) => core::pin::Pin::new(writer).poll_flush(cx),
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        match self.get_mut().live() {
            Ok(writer) => core::pin::Pin::new(writer).poll_shutdown(cx),
            Err(error) => core::task::Poll::Ready(Err(error)),
        }
    }
}

impl<W> bifrost::WriteEnd for TestWrite<W> {
    fn abort(&mut self) {
        self.writer = None;
    }

    /// `ConnectionReset` after an abort. Otherwise the writer is dropped, which ends the stream, and the
    /// answer is the far end's: `Ok` once it has read to the end, `BrokenPipe` if it went first, pending
    /// while it reads on or holds the stream. A plain writer, with no far end to ask, is `Unsupported`.
    // `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn delivered(self) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        let Self {
            writer,
            read_to_end,
        } = self;
        let aborted = writer.is_none();
        drop(writer);
        async move {
            if aborted {
                return Err(std::io::ErrorKind::ConnectionReset.into());
            }
            match read_to_end {
                Some(read_to_end) => read_to_end
                    .await
                    .map_err(|_| std::io::ErrorKind::BrokenPipe.into()),
                None => Err(std::io::ErrorKind::Unsupported.into()),
            }
        }
    }
}

/// A peer that answers with text it chose, as both the transport that dials it and the session to it: the
/// double the tests drive a verb's real reach path with, to show that text reaches the line escaped.
///
/// The text is a cause or a refusal detail, the two places another machine's words ride into an error
/// chain. Each arm fails at one stage, so a test names the stage whose print it guards.
#[derive(Debug, Clone, Copy)]
pub enum HostilePeer {
    /// Every dial fails, with the text as its cause (the reason a peer gave for closing).
    Unreachable(&'static str),
    /// The dial lands and every stream is refused as it opens, with the text as the refusal's detail.
    RefusesStreams(&'static str),
    /// The dial lands and the stream opens; the gate reads the request and answers with a refusal whose
    /// detail is the text.
    RefusesAtTheGate(&'static str),
    /// The dial lands and the stream opens; the gate reads the request and ends the stream without an
    /// answer, as a host that dies mid-dial does.
    HangsUp,
}

impl HostilePeer {
    /// The peer's key, and the key this double binds as: one fixed key, since no test tells them apart.
    pub fn node_id() -> NodeId {
        NodeId::from_ed25519_secret(&[0x48; 32])
    }

    /// The refusal this peer sends, carrying its text.
    fn refusal(text: &'static str) -> bifrost::Refusal {
        bifrost::Refusal::Unavailable {
            detail: bifrost::RefusalDetail::bounded(text),
        }
    }
}

impl bifrost::Transport for HostilePeer {
    type Session = Self;

    fn node_id(&self) -> NodeId {
        Self::node_id()
    }

    fn local_addr(&self) -> bifrost::Addr {
        bifrost::Addr::from_node(Self::node_id())
    }

    fn bound_sockets(&self) -> Vec<core::net::SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, _addr: bifrost::Addr) -> Result<Self, bifrost::Error> {
        match *self {
            Self::Unreachable(text) => Err(bifrost::Error::Connect(text.into())),
            Self::RefusesStreams(_) | Self::RefusesAtTheGate(_) | Self::HangsUp => Ok(*self),
        }
    }

    async fn accept(&self) -> Result<Self, bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn close(&self) {}
}

impl bifrost::Session for HostilePeer {
    /// Swallows the request, so the gate's answer is what the dialer reads next.
    type Write = TestWrite<tokio::io::Sink>;
    /// The gate's answer, written whole before the stream opens, then the end of the stream.
    type Read = tokio::io::DuplexStream;

    fn peer(&self) -> NodeId {
        Self::node_id()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        match *self {
            Self::Unreachable(_) => Err(bifrost::Error::Closed),
            Self::RefusesStreams(text) => Err(bifrost::Error::Refused(Self::refusal(text))),
            Self::RefusesAtTheGate(text) => {
                // Room for the whole frame: a detail is bounded well under this.
                let (mut gate, read) = tokio::io::duplex(4096);
                tightbeam::protocol::Response::Refused(Self::refusal(text))
                    .write(&mut gate)
                    .await
                    .map_err(|error| bifrost::Error::Stream(error.into()))?;
                Ok((tokio::io::sink().into(), read))
            }
            Self::HangsUp => Ok((tokio::io::sink().into(), tokio::io::duplex(1).1)),
        }
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    /// Open until dropped, so an owner holding it reuses it rather than redialing a closed session.
    async fn wait_closed(&self) {
        core::future::pending::<()>().await;
    }

    /// A double that carries nothing has nothing to end.
    fn close(&self) {}

    /// No transport under it, so no path: the default `conn_info`'s, once.
    fn path_changes(&self) -> bifrost::PathChanges {
        bifrost::PathChanges::fixed(bifrost::Path::Unknown)
    }
}

/// What a [`ScriptedPeer`]'s gate does with one stream it is asked to open, in the order the streams open.
#[derive(Debug, Clone)]
pub enum Script {
    /// Read the request, then refuse it.
    Refuse(bifrost::Refusal),
    /// Read the request, admit it, then send a list of services naming these, and end the stream. On
    /// `control.serve` it answers as the route does: only a list request, with `Done` before the list, and
    /// any other request `BadRequest`; a stream that ends before its request goes unanswered.
    Lists(Vec<&'static str>),
    /// Read the request and never answer, holding the stream open.
    Silent,
    /// Read the request, admit it, then hold the stream open and say nothing more.
    Holds,
    /// Read the request, admit it, end its own side of the stream at once, and never read what follows.
    Ends,
    /// Read the request, admit it, send these bytes, then hold the stream open and say nothing more.
    Says(Vec<u8>),
    /// Read the request, admit it, then read the stream to its end, keeping what it read, and end.
    Reads,
    /// Read the request, admit it, then read the stream to its end, keeping what it read, and hold its
    /// own side open, saying nothing more.
    ReadsThenHolds,
    /// Read the request, admit it and end its own side at once, then after the pause read the stream to
    /// its end, keeping what it read only while no session was closed: a close discards what the
    /// peer has not taken, as a transport's close does.
    EndsThenReads(core::time::Duration),
}

/// A peer whose gate follows a script, one [`Script`] per stream, recording every request it reads: the
/// double a test drives a refused dial and its follow-up with, to see what each stream asked and
/// presented. Dials always land; a stream past the end of the script is refused `NotAdmitted`.
#[derive(Debug, Clone)]
pub struct ScriptedPeer {
    key: NodeId,
    state: std::sync::Arc<std::sync::Mutex<Scripted>>,
    /// Whether the host has cut its sessions, for every session's `wait_closed`.
    cut: std::sync::Arc<tokio::sync::watch::Sender<bool>>,
    /// Whether the host has cut this session alone: each dial gets one of its own.
    cut_one: std::sync::Arc<tokio::sync::watch::Sender<bool>>,
    /// This session's own path report, which a test may change mid-run, as a transport's selection
    /// moves: each dial gets one of its own.
    path: std::sync::Arc<tokio::sync::watch::Sender<bifrost::ConnInfo>>,
}

/// What a [`ScriptedPeer`] has left to answer, and what it has read.
#[derive(Debug, Default)]
struct Scripted {
    script: VecDeque<Script>,
    requests: Vec<tightbeam::protocol::Request>,
    dials: u32,
    /// Each dialed session's path report, in dial order.
    paths: Vec<std::sync::Arc<tokio::sync::watch::Sender<bifrost::ConnInfo>>>,
    /// Each dialed session's own cut, in dial order.
    cuts: Vec<std::sync::Arc<tokio::sync::watch::Sender<bool>>>,
    received: Vec<u8>,
    closes: u32,
}

impl ScriptedPeer {
    /// A peer at `key` whose gate answers `script`, stream by stream.
    pub fn new(key: NodeId, script: impl IntoIterator<Item = Script>) -> Self {
        Self {
            key,
            state: std::sync::Arc::new(std::sync::Mutex::new(Scripted {
                script: script.into_iter().collect(),
                ..Scripted::default()
            })),
            cut: std::sync::Arc::new(tokio::sync::watch::Sender::new(false)),
            cut_one: std::sync::Arc::new(tokio::sync::watch::Sender::new(false)),
            path: std::sync::Arc::new(
                tokio::sync::watch::Sender::new(bifrost::ConnInfo::default()),
            ),
        }
    }

    /// Set the path report of the session dialed `nth`, counting from 0, as a transport's path moves.
    ///
    /// # Panics
    ///
    /// Fewer than `nth + 1` sessions were dialed.
    pub fn set_path(&self, nth: usize, info: bifrost::ConnInfo) {
        let path = std::sync::Arc::clone(&self.lock().paths[nth]);
        path.send_replace(info);
    }

    /// Cut every session to it, as a host does on a revoke or an expiry: each session's `wait_closed`
    /// resolves. Its streams are left as they are, so only a watch on the session can see the cut.
    pub fn cut(&self) {
        self.cut.send_replace(true);
    }

    /// Cut the session dialed `nth`, counting from 0, and no other: its `wait_closed` resolves.
    ///
    /// # Panics
    ///
    /// Fewer than `nth + 1` sessions were dialed.
    pub fn cut_nth(&self, nth: usize) {
        self.lock().cuts[nth].send_replace(true);
    }

    /// Every request its gate has read, in order.
    pub fn requests(&self) -> Vec<tightbeam::protocol::Request> {
        self.lock().requests.clone()
    }

    /// What [`Script::Reads`] and [`Script::EndsThenReads`] streams have read after their requests, in
    /// order.
    pub fn received(&self) -> Vec<u8> {
        self.lock().received.clone()
    }

    /// How many times it was dialed.
    pub fn dials(&self) -> u32 {
        self.lock().dials
    }

    /// How many times a session to it was closed.
    pub fn closes(&self) -> u32 {
        self.lock().closes
    }

    /// The shared state. A poisoned lock means a test thread panicked holding it; its state is still the
    /// record of what happened, so it is read anyway.
    fn lock(&self) -> std::sync::MutexGuard<'_, Scripted> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read `from` to its end, keeping what it reads, and fire `read_to_end` there; with `closes`, only
    /// while no session has closed since that count, since a closed session's stream reaches no end.
    async fn keep_reading(
        &self,
        from: &mut tokio::io::DuplexStream,
        closes: Option<u32>,
        read_to_end: tokio::sync::oneshot::Sender<()>,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncReadExt as _;

        let mut chunk = [0; 4096];
        loop {
            let read = from.read(&mut chunk).await?;
            if read == 0 {
                if closes.is_none_or(|closes| self.lock().closes == closes) {
                    let _ = read_to_end.send(());
                }
                return Ok(());
            }
            let mut state = self.lock();
            if closes.is_some_and(|closes| state.closes != closes) {
                return Ok(());
            }
            state.received.extend_from_slice(&chunk[..read]);
        }
    }

    /// A list of services naming `names`, in the catalog's wire form: a count, then each name
    /// length-prefixed with its posture (gated).
    fn catalog(names: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(names.len()).unwrap_or(u32::MAX).to_be_bytes());
        for name in names {
            bytes.extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    /// The gate's side of one stream: read the request, record it, then answer as `script` says. It
    /// holds `read_to_end` for as long as it holds the stream, and fires it only once it has read the
    /// stream to its end, so the opener's delivery waits on that and fails once the gate lets go.
    async fn gate(
        self,
        script: Script,
        mut from: tokio::io::DuplexStream,
        mut to: tokio::io::DuplexStream,
        read_to_end: tokio::sync::oneshot::Sender<()>,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;

        let Ok(request) = tightbeam::protocol::Request::read(&mut from).await else {
            return Ok(());
        };
        let control = request.service == crate::serve::CONTROL_SERVE_SERVICE;
        self.lock().requests.push(request);
        match script {
            Script::Refuse(refusal) => {
                tightbeam::protocol::Response::Refused(refusal)
                    .write(&mut to)
                    .await
            }
            Script::Lists(names) => {
                use tokio::io::AsyncReadExt as _;

                use crate::serve::control::{Answer, Request};

                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                if control {
                    let mut asked = [0u8; 1];
                    if from.read_exact(&mut asked).await.is_err() {
                        return Ok(());
                    }
                    if Request::decode(asked[0]) != Some(Request::List) {
                        to.write_all(&[Answer::BadRequest.encode()]).await?;
                        return to.shutdown().await;
                    }
                    to.write_all(&[Answer::Done.encode()]).await?;
                }
                to.write_all(&Self::catalog(&names)).await?;
                to.shutdown().await
            }
            Script::Silent => {
                core::future::pending::<()>().await;
                Ok(())
            }
            Script::Holds => {
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                core::future::pending::<()>().await;
                Ok(())
            }
            Script::Ends => {
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                to.shutdown().await?;
                // Holding the reading half unread fills the stream, so the writer stalls rather than fails.
                let _unread = from;
                core::future::pending::<()>().await;
                Ok(())
            }
            Script::Says(bytes) => {
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                to.write_all(&bytes).await?;
                let _held = (from, to);
                core::future::pending::<()>().await;
                Ok(())
            }
            Script::Reads => {
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                self.keep_reading(&mut from, None, read_to_end).await?;
                to.shutdown().await
            }
            Script::ReadsThenHolds => {
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                self.keep_reading(&mut from, None, read_to_end).await?;
                let _held = to;
                core::future::pending::<()>().await;
                Ok(())
            }
            Script::EndsThenReads(pause) => {
                let closes = self.lock().closes;
                tightbeam::protocol::Response::Ok.write(&mut to).await?;
                to.shutdown().await?;
                tokio::time::sleep(pause).await;
                self.keep_reading(&mut from, Some(closes), read_to_end)
                    .await
            }
        }
    }
}

impl bifrost::Transport for ScriptedPeer {
    type Session = Self;

    fn node_id(&self) -> NodeId {
        self.key
    }

    fn local_addr(&self) -> bifrost::Addr {
        bifrost::Addr::from_node(self.key)
    }

    fn bound_sockets(&self) -> Vec<core::net::SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, _addr: bifrost::Addr) -> Result<Self, bifrost::Error> {
        let path =
            std::sync::Arc::new(tokio::sync::watch::Sender::new(bifrost::ConnInfo::default()));
        let cut_one = std::sync::Arc::new(tokio::sync::watch::Sender::new(false));
        let mut state = self.lock();
        state.dials += 1;
        state.paths.push(std::sync::Arc::clone(&path));
        state.cuts.push(std::sync::Arc::clone(&cut_one));
        Ok(Self {
            path,
            cut_one,
            ..self.clone()
        })
    }

    async fn accept(&self) -> Result<Self, bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn close(&self) {}
}

impl bifrost::Session for ScriptedPeer {
    type Write = TestWrite<tokio::io::DuplexStream>;
    type Read = tokio::io::DuplexStream;

    fn peer(&self) -> NodeId {
        self.key
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        let script = self
            .lock()
            .script
            .pop_front()
            .unwrap_or(Script::Refuse(bifrost::Refusal::NotAdmitted));
        let (write, from) = tokio::io::duplex(64 * 1024);
        let (to, read) = tokio::io::duplex(64 * 1024);
        let (read_to_end, delivered) = tokio::sync::oneshot::channel();
        let gate = self.clone();
        tokio::spawn(async move {
            if let Err(error) = gate.gate(script, from, to, read_to_end).await {
                tracing::debug!(%error, "the scripted gate's stream ended");
            }
        });
        Ok((TestWrite::read_by(write, delivered), read))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    /// Open until [`cut`](Self::cut), or [`cut_nth`](Self::cut_nth) for this session, so an owner
    /// holding it reuses it rather than redialing a closed session.
    async fn wait_closed(&self) {
        // The senders live as long as `self`, so the wait ends only at a cut.
        let (mut all, mut one) = (self.cut.subscribe(), self.cut_one.subscribe());
        tokio::select! {
            _ = all.wait_for(|cut| *cut) => {}
            _ = one.wait_for(|cut| *cut) => {}
        }
    }

    /// Counted, so a [`Script::EndsThenReads`] stream keeps nothing it reads after a close.
    fn close(&self) {
        self.lock().closes += 1;
    }

    /// The session's own report, as [`set_path`](Self::set_path) last left it.
    fn conn_info(&self) -> bifrost::ConnInfo {
        self.path.borrow().clone()
    }

    /// The path in force, then each one [`set_path`](Self::set_path) moves it to.
    fn path_changes(&self) -> bifrost::PathChanges {
        let moves = self.path.subscribe();
        bifrost::PathChanges::new(futures::stream::unfold(
            (moves, true),
            |(mut moves, first)| async move {
                if !first && moves.changed().await.is_err() {
                    return None;
                }
                let path = moves.borrow_and_update().path.clone();
                Some((path, (moves, false)))
            },
        ))
    }
}

#[cfg(test)]
#[path = "testkit_tests.rs"]
mod tests;

/// An [`Opens`](crate::serve::Opens) for a resident test that sends no Open: one that arrives is dropped
/// unanswered, its connection and control slot with it.
pub struct NoOpens;

impl crate::serve::Opens for NoOpens {
    async fn open<R, W>(
        &self,
        _open: crate::serve::control_codec::OpenRequest,
        _from_client: R,
        _to_client: W,
        _gone: crate::serve::ClientGone,
        _control: tokio::sync::SemaphorePermit<'_>,
    ) where
        R: tokio::io::AsyncBufRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
    }

    /// No Open is ever attached, so no reference names one.
    fn path(
        &self,
        _request: crate::serve::control_codec::PathRequest,
    ) -> crate::serve::control_codec::PathReply {
        crate::serve::control_codec::PathReply::Unavailable
    }

    async fn drive(&self) -> core::convert::Infallible {
        core::future::pending().await
    }
}
