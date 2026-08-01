//! Canonical bytes for the ask shown to a linked device.

use crate::daemon::proto::Ask;
use crate::provenance::SignAnchorKind;

use super::projection::{LinkAsk, LinkAskSubject, LinkCaller, LinkSecretAsk};

/// Length-prefixed concatenation of string fields.
///
/// Every part is written as its big-endian `u32` byte length followed by its
/// UTF-8 bytes, so no two different field tuples can produce the same buffer.
/// A bare concatenation would let `("ab", "c")` and `("a", "bc")` collide,
/// which is a request-substitution attack: the device shows one command and
/// signs another.
pub(crate) fn canonical_parts(parts: &[&str]) -> Vec<u8> {
    let mut writer = CanonicalWriter::default();
    for part in parts {
        writer.part(part);
    }
    writer.finish()
}

/// Canonical bytes for exactly the display-facing fields of an ask.
///
/// This is an explicit wire contract rather than a serde serialization. A
/// struct field reorder must not invalidate signatures from every enrolled
/// device, and resolution-only fields such as provider commands must not
/// silently become part of what the device is said to have approved.
///
/// **Adding a field to what the linked client displays means adding it here.**
/// A displayed field outside this hash is a field an attacker can vary while
/// the signature still verifies.
pub fn canonical_bytes(ask: &Ask) -> Vec<u8> {
    canonical_link_bytes(&LinkAsk::from(ask))
}

/// Canonical bytes computed from the exact projection sent to linked clients.
pub fn canonical_link_bytes(ask: &LinkAsk) -> Vec<u8> {
    let mut writer = CanonicalWriter::default();
    writer.part("secreq-link-ask-v1");
    writer.strings("command", &ask.command);

    match &ask.subject {
        LinkAskSubject::Wrap(wrap) => {
            writer.part("wrap");
            writer.field("wrap", &wrap.wrap);
            writer.field("cwd", &wrap.cwd);
            writer.bool("callers_truncated", wrap.callers_truncated);
            writer.callers(&wrap.callers);
            writer.count("secrets", wrap.secrets.len());
            for secret in &wrap.secrets {
                writer.secret(secret);
            }
            writer.bool("allow_remember", wrap.allow_remember);
        }
        LinkAskSubject::SshSign(ssh) => {
            writer.part("ssh_sign");
            writer.field("wrap", &ssh.wrap);
            writer.field("cwd", &ssh.cwd);
            writer.bool("callers_truncated", ssh.callers_truncated);
            writer.callers(&ssh.callers);
            writer.field("key_id", &ssh.info.key_id);
            writer.field("fingerprint", &ssh.info.fingerprint);
            writer.option("reason", ssh.info.reason.as_deref());
            match &ssh.info.anchor {
                Some(anchor) => {
                    writer.part("anchor_some");
                    writer.field("anchor_name", &anchor.name);
                    writer.number("anchor_pid", anchor.pid);
                    writer.field(
                        "anchor_kind",
                        match anchor.kind {
                            SignAnchorKind::Session => "session",
                            SignAnchorKind::ForwardedSsh => "forwarded_ssh",
                        },
                    );
                    writer.option("anchor_command", anchor.command.as_deref());
                }
                None => writer.part("anchor_none"),
            }
        }
        LinkAskSubject::ScopedAgent(agent) => {
            writer.part("scoped_agent");
            writer.field("scope", &agent.scope);
            writer.field("reference", &agent.reference);
            writer.option("guest_chain", agent.guest_chain.as_deref());
            match &agent.declared_by {
                Some(peer) => {
                    writer.part("declared_by_some");
                    writer.number("declared_by_pid", peer.pid);
                    writer.field("declared_by_name", &peer.name);
                    writer.option("declared_by_exe", peer.exe.as_deref());
                }
                None => writer.part("declared_by_none"),
            }
        }
    }

    writer.finish()
}

/// Lowercase hexadecimal SHA-256 of [`canonical_bytes`].
pub fn canonical_hash(ask: &Ask) -> String {
    crate::rules::sha256_hex(&canonical_bytes(ask))
}

/// Lowercase hexadecimal SHA-256 of [`canonical_link_bytes`].
pub fn canonical_link_hash(ask: &LinkAsk) -> String {
    crate::rules::sha256_hex(&canonical_link_bytes(ask))
}

#[derive(Default)]
struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn part(&mut self, part: &str) {
        let len = u32::try_from(part.len()).expect("a canonical field must fit in a u32");
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(part.as_bytes());
    }

    fn field(&mut self, name: &str, value: &str) {
        self.part(name);
        self.part(value);
    }

    fn number(&mut self, name: &str, value: impl ToString) {
        self.field(name, &value.to_string());
    }

    fn bool(&mut self, name: &str, value: bool) {
        self.field(name, if value { "true" } else { "false" });
    }

    fn option(&mut self, name: &str, value: Option<&str>) {
        self.part(name);
        match value {
            Some(value) => {
                self.part("some");
                self.part(value);
            }
            None => self.part("none"),
        }
    }

    fn count(&mut self, name: &str, count: usize) {
        self.number(name, count);
    }

    fn strings(&mut self, name: &str, values: &[String]) {
        self.count(name, values.len());
        for value in values {
            self.part(value);
        }
    }

    fn callers(&mut self, callers: &[LinkCaller]) {
        self.count("callers", callers.len());
        for caller in callers {
            self.number("caller_pid", caller.pid);
            self.field("caller_name", &caller.name);
            self.field("caller_command", &caller.command);
            self.option("caller_exe", caller.exe.as_deref());
        }
    }

    fn secret(&mut self, secret: &LinkSecretAsk) {
        self.field("secret_name", &secret.name);
        self.field("secret_provider", &secret.provider);
        self.field("secret_locator", &secret.locator);
        self.option("secret_description", secret.description.as_deref());
        self.option("secret_reason", secret.reason.as_deref());
        self.strings("secret_requested_by", &secret.requested_by);
        self.option("secret_declared_as", secret.declared_as.as_deref());
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::daemon::proto::{Ask, AskAnchor, AskSubject, DedupeKey, SecretAsk, WrapSubject};
    use crate::provenance::ProcessIdentity;

    use super::*;

    fn sample_ask() -> Ask {
        Ask {
            command: vec!["deploy".into(), "--production".into()],
            dedupe_key: DedupeKey {
                wrap: "deploy".into(),
                anchor: AskAnchor::Process(ProcessIdentity {
                    pid: 42,
                    start_time: 1_753_000_000,
                }),
                subject_digest: None,
            },
            subject: AskSubject::Wrap(WrapSubject {
                cwd: "/srv/app".into(),
                callers: Vec::new(),
                callers_truncated: false,
                secrets: vec![SecretAsk {
                    name: "DEPLOY_TOKEN".into(),
                    provider: "op".into(),
                    locator: "Production/Deploy/token".into(),
                    default: None,
                    description: None,
                    reason: Some("publish the release".into()),
                    requested_by: vec!["deploy --production".into()],
                    declared_as: Some("deploy-token".into()),
                    ttl: Default::default(),
                }],
                providers: HashMap::new(),
                allow_remember: true,
                nested_run: false,
                ignore_remembered: false,
            }),
        }
    }

    #[test]
    fn canonical_bytes_are_stable_for_the_same_ask() {
        let ask = sample_ask();

        assert_eq!(canonical_bytes(&ask), canonical_bytes(&ask));
    }

    #[test]
    fn fields_cannot_be_shifted_across_the_boundary() {
        // Length-prefixing is what stops ("ab", "c") hashing the same as
        // ("a", "bc"). Without it, a crafted wrap name could impersonate a
        // different command.
        let a = canonical_parts(&["ab", "c"]);
        let b = canonical_parts(&["a", "bc"]);

        assert_ne!(a, b);
    }

    #[test]
    fn a_changed_secret_name_changes_the_hash() {
        let mut ask = sample_ask();
        let before = canonical_hash(&ask);
        ask.wrap_mut().expect("a wrap ask").secrets[0].name = "OTHER_TOKEN".into();

        assert_ne!(before, canonical_hash(&ask));
    }

    #[test]
    fn rust_matches_the_shared_cross_language_v1_fixture() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            contract: String,
            cases: Vec<FixtureCase>,
        }

        #[derive(serde::Deserialize)]
        struct FixtureCase {
            name: String,
            ask: LinkAsk,
            sha256: String,
        }

        let fixture: Fixture =
            serde_json::from_str(include_str!("canonical-v1.fixture.json")).unwrap();
        assert_eq!(fixture.contract, "secreq-link-ask-v1");
        let actual: Vec<(&str, String)> = fixture
            .cases
            .iter()
            .map(|case| (case.name.as_str(), canonical_link_hash(&case.ask)))
            .collect();
        let expected: Vec<(&str, String)> = fixture
            .cases
            .iter()
            .map(|case| (case.name.as_str(), case.sha256.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn remember_capability_is_part_of_the_existing_v1_contract() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            cases: Vec<FixtureCase>,
        }

        #[derive(serde::Deserialize)]
        struct FixtureCase {
            ask: LinkAsk,
        }

        let fixture: Fixture =
            serde_json::from_str(include_str!("canonical-v1.fixture.json")).unwrap();
        let mut ask = fixture.cases.into_iter().next().unwrap().ask;
        let before = canonical_link_hash(&ask);
        let LinkAskSubject::Wrap(wrap) = &mut ask.subject else {
            panic!("first fixture must be a wrap ask");
        };
        wrap.allow_remember = !wrap.allow_remember;
        assert_ne!(before, canonical_link_hash(&ask));
    }
}
