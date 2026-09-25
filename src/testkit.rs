//! Keys and prompts for tests, and the only place test code signs anything.
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

use core::ops::Deref;
use std::collections::VecDeque;
use std::path::Path;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::Passphrase;
use nauthy::{Cap, CapError, Identity, Link, Service, Signed, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use crate::contacts::DeviceLabel;
use crate::passphrase::Prompt;
use crate::roster::{Member, RosterDoc};
use crate::state::State;

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
        self.member_badge(device.verify_key(), until)?
            .seal()?
            .link()
    }

    /// A live device for an update: `node`, named `label`, carrying this root's sealed badge for it as its
    /// standing, with no ids and no renewal.
    pub fn member(&self, node: VerifyKey, label: DeviceLabel) -> Result<Member, CapError> {
        Ok(Member {
            node,
            label,
            until: STANDING_UNTIL,
            duration: 0,
            ids: Vec::new(),
            standing: self.standing(node)?,
        })
    }

    /// This root's sealed badge for `node`, bare: the standing an update or `state` carries for it.
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

    /// `state`, signed by this key: the bytes a root's copy holds in its `state` file.
    pub fn sign_state(&self, state: &State) -> Vec<u8> {
        self.sign(&state.canonical_bytes()).encode()
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

/// A [`Prompt`] that counts prompt events and the passphrases they read, and answers from a script.
///
/// One event is one call to `unlock` or `choose`, whatever the terminal behind it would read: `choose`
/// asks for the passphrase twice, and is still one event of two reads. A call with no answer left is
/// still an event: it refuses the way a missing terminal does, after being asked. So a test that scripts
/// nothing and reads a count of zero proves nothing was asked.
pub struct Counting {
    answers: VecDeque<&'static str>,
    events: usize,
    reads: usize,
}

impl Counting {
    /// A prompt that answers each event with the next of `answers`, in order.
    pub fn new(answers: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            events: 0,
            reads: 0,
        }
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

    fn answer(&mut self, reads: usize) -> eyre::Result<Passphrase> {
        self.events += 1;
        self.reads += reads;
        let answer = self
            .answers
            .pop_front()
            .ok_or_else(|| eyre::eyre!("no scripted answer left"))?;
        crate::passphrase::passphrase(Zeroizing::new(answer.to_owned()))
    }
}

impl Prompt for Counting {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        self.answer(1)
    }

    fn choose(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        self.answer(2)
    }
}

#[cfg(test)]
#[path = "testkit_tests.rs"]
mod tests;
