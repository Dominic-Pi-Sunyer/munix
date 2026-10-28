//! Labels: where a value came from and how far it can be believed (integrity) or shared (confidentiality).

use crate::ids::ToolName;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Integrity score from 0 (worthless) to 100 (fully trusted). Construction clamps; deserializing rejects values
/// above 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Trust(u8);

impl Trust {
    pub const ZERO: Trust = Trust(0);
    pub const FULL: Trust = Trust(100);
    /// No web content scores above this.
    pub const WEB_CAP: Trust = Trust(95);
    /// Where an author the Gate has never seen starts.
    pub const UNKNOWN_AUTHOR: Trust = Trust(15);

    /// Clamps to 0-100.
    pub const fn new(n: u8) -> Trust {
        Trust(if n > 100 { 100 } else { n })
    }

    pub const fn value(self) -> u8 {
        self.0
    }

    /// The lower of two scores.
    pub fn min(self, other: Trust) -> Trust {
        Trust(self.0.min(other.0))
    }
}

impl From<u8> for Trust {
    fn from(n: u8) -> Self {
        Trust::new(n)
    }
}

impl fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Trust {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u8::deserialize(d)?;
        if n > 100 {
            Err(serde::de::Error::custom("trust must be 0-100"))
        } else {
            Ok(Trust(n))
        }
    }
}

/// Where a value came from. Web sources carry an opaque domain number, never the domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "SourceWire")]
pub enum Source {
    Prompt,
    UserData,
    Store,
    Web { domain: u32 },
    Tool { tool: ToolName },
    Memory,
    Reader,
    Vault,
}

/// serde ignores extra fields on the unit variants of an internally tagged enum, so `Source` and `Author` are read
/// through these flat shapes, which reject anything that does not belong to the variant.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct SourceWire {
    kind: SourceKind,
    #[serde(default)]
    domain: Option<u32>,
    #[serde(default)]
    tool: Option<ToolName>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    Prompt,
    UserData,
    Store,
    Web,
    Tool,
    Memory,
    Reader,
    Vault,
}

impl TryFrom<SourceWire> for Source {
    type Error = String;
    fn try_from(w: SourceWire) -> Result<Self, String> {
        let source = match (w.kind, w.domain, w.tool) {
            (SourceKind::Prompt, None, None) => Source::Prompt,
            (SourceKind::UserData, None, None) => Source::UserData,
            (SourceKind::Store, None, None) => Source::Store,
            (SourceKind::Web, Some(domain), None) => Source::Web { domain },
            (SourceKind::Tool, None, Some(tool)) => Source::Tool { tool },
            (SourceKind::Memory, None, None) => Source::Memory,
            (SourceKind::Reader, None, None) => Source::Reader,
            (SourceKind::Vault, None, None) => Source::Vault,
            _ => return Err("fields do not match the source kind".into()),
        };
        Ok(source)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct AuthorWire {
    kind: AuthorKind,
    #[serde(default)]
    id: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorKind {
    Operator,
    User,
    Account,
    Unknown,
}

impl TryFrom<AuthorWire> for Author {
    type Error = String;
    fn try_from(w: AuthorWire) -> Result<Self, String> {
        Ok(match (w.kind, w.id) {
            (AuthorKind::Operator, None) => Author::Operator,
            (AuthorKind::User, None) => Author::User,
            (AuthorKind::Account, Some(id)) => Author::Account { id },
            (AuthorKind::Unknown, None) => Author::Unknown,
            _ => return Err("fields do not match the author kind".into()),
        })
    }
}

/// What kind of page region a piece of content came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionType {
    OperatorLegal,
    OperatorContent,
    OperatorUi,
    ProductListing,
    Editorial,
    SearchSnippet,
    UgcPost,
    UgcReview,
    Profile,
    UgcComment,
    Ad,
    EmbeddedThirdParty,
    UserContent,
    Message,
    Unclassified,
    Hidden,
}

impl RegionType {
    /// The highest trust content of this type can have (design spec 5.2). Embedded third-party content is scored as
    /// its own origin elsewhere; here it gets the `unclassified` ceiling.
    pub fn ceiling(self) -> Trust {
        Trust(match self {
            RegionType::OperatorLegal => 90,
            RegionType::OperatorContent | RegionType::OperatorUi => 85,
            RegionType::ProductListing => 80,
            RegionType::Editorial => 75,
            RegionType::SearchSnippet => 50,
            RegionType::UgcPost => 40,
            RegionType::UgcReview | RegionType::Profile | RegionType::UgcComment => 30,
            RegionType::Ad => 10,
            RegionType::EmbeddedThirdParty | RegionType::Unclassified => 10,
            RegionType::UserContent => 90,
            RegionType::Message => 60,
            RegionType::Hidden => 0,
        })
    }

    /// True for content a stranger or an unknown party can write: user-generated posts, reviews, comments and
    /// profiles, messages from others, ads, search snippets, embedded third-party content, and anything unclassified
    /// or hidden. False for what the operator of the source (or the user) wrote itself: legal text, operator content
    /// and UI, product listings, editorial content and the user's own content.
    ///
    /// The Gate uses it for domain binding: a value that comes out of such content never binds a tier 3
    /// destination by trust alone (see `munix_gate::facts::Traced::binds`). `unclassified` and `hidden` count as
    /// third-party because unknown means untrusted (invariant 5).
    pub fn is_third_party(self) -> bool {
        match self {
            RegionType::UgcPost
            | RegionType::UgcReview
            | RegionType::UgcComment
            | RegionType::Profile
            | RegionType::Message
            | RegionType::Ad
            | RegionType::SearchSnippet
            | RegionType::EmbeddedThirdParty
            | RegionType::Unclassified
            | RegionType::Hidden => true,
            RegionType::OperatorLegal
            | RegionType::OperatorContent
            | RegionType::OperatorUi
            | RegionType::ProductListing
            | RegionType::Editorial
            | RegionType::UserContent => false,
        }
    }
}

/// Who wrote a piece of content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "AuthorWire")]
pub enum Author {
    Operator,
    User,
    Account { id: u32 },
    Unknown,
}

/// Where content may go: `public < internal < private < secret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidential {
    Public,
    Internal,
    Private,
    Secret,
}

/// How much a value could say: a few bits of a typed value, or anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Capacity {
    Typed { bits: u32 },
    FreeText,
}

/// The label every delivered region and every derived value carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub source: Source,
    pub region: RegionType,
    pub author: Author,
    pub trust: Trust,
    pub confidential: Confidential,
    pub capacity: Capacity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn trust_clamps_and_orders() {
        assert_eq!(Trust::new(0).value(), 0);
        assert_eq!(Trust::new(100).value(), 100);
        assert_eq!(Trust::new(101), Trust::FULL);
        assert_eq!(Trust::new(255), Trust::FULL);
        assert_eq!(Trust::from(250u8), Trust::FULL);
        assert!(Trust::new(10) < Trust::new(11));
        assert_eq!(Trust::new(40).min(Trust::new(30)), Trust::new(30));
        assert_eq!(Trust::new(30).min(Trust::new(40)), Trust::new(30));
        assert_eq!(Trust::WEB_CAP.value(), 95);
        assert_eq!(Trust::UNKNOWN_AUTHOR.value(), 15);
        assert_eq!(Trust::new(7).to_string(), "7");
    }

    #[test]
    fn trust_serde_rejects_out_of_range() {
        assert_eq!(
            serde_json::from_value::<Trust>(json!(60)).unwrap(),
            Trust::new(60)
        );
        assert_eq!(serde_json::to_value(Trust::new(60)).unwrap(), json!(60));
        assert!(serde_json::from_value::<Trust>(json!(101)).is_err());
        assert!(serde_json::from_value::<Trust>(json!(-1)).is_err());
        assert!(serde_json::from_value::<Trust>(json!(300)).is_err());
        assert!(serde_json::from_value::<Trust>(json!("60")).is_err());
    }

    #[test]
    fn ceilings_match_the_spec_table() {
        use RegionType::*;
        let table = [
            (OperatorLegal, 90),
            (OperatorContent, 85),
            (OperatorUi, 85),
            (ProductListing, 80),
            (Editorial, 75),
            (SearchSnippet, 50),
            (UgcPost, 40),
            (UgcReview, 30),
            (Profile, 30),
            (UgcComment, 30),
            (Ad, 10),
            (EmbeddedThirdParty, 10),
            (UserContent, 90),
            (Message, 60),
            (Unclassified, 10),
            (Hidden, 0),
        ];
        for (region, expected) in table {
            assert_eq!(region.ceiling().value(), expected, "{region:?}");
        }
        assert_eq!(EmbeddedThirdParty.ceiling(), Unclassified.ceiling());
    }

    #[test]
    fn third_party_regions_are_the_ones_strangers_can_write() {
        use RegionType::*;
        for r in [
            UgcPost,
            UgcReview,
            UgcComment,
            Profile,
            Message,
            Ad,
            SearchSnippet,
            EmbeddedThirdParty,
            Unclassified,
            Hidden,
        ] {
            assert!(r.is_third_party(), "{r:?}");
        }
        for r in [
            OperatorLegal,
            OperatorContent,
            OperatorUi,
            ProductListing,
            Editorial,
            UserContent,
        ] {
            assert!(!r.is_third_party(), "{r:?}");
        }
    }

    #[test]
    fn region_names_are_snake_case() {
        assert_eq!(
            serde_json::to_value(RegionType::OperatorLegal).unwrap(),
            json!("operator_legal")
        );
        assert_eq!(
            serde_json::to_value(RegionType::UgcReview).unwrap(),
            json!("ugc_review")
        );
        assert_eq!(
            serde_json::from_value::<RegionType>(json!("embedded_third_party")).unwrap(),
            RegionType::EmbeddedThirdParty
        );
        assert!(serde_json::from_value::<RegionType>(json!("UgcReview")).is_err());
        assert!(serde_json::from_value::<RegionType>(json!("made_up")).is_err());
    }

    #[test]
    fn confidential_order() {
        assert!(Confidential::Public < Confidential::Internal);
        assert!(Confidential::Internal < Confidential::Private);
        assert!(Confidential::Private < Confidential::Secret);
        assert_eq!(
            serde_json::to_value(Confidential::Secret).unwrap(),
            json!("secret")
        );
    }

    #[test]
    fn spec_label_example_round_trips() {
        let wire = json!({
            "source": {"kind": "web", "domain": 7},
            "region": "product_listing",
            "author": {"kind": "operator"},
            "trust": 78,
            "confidential": "public",
            "capacity": "free_text"
        });
        let label: Label = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(label.source, Source::Web { domain: 7 });
        assert_eq!(label.capacity, Capacity::FreeText);
        assert_eq!(serde_json::to_value(&label).unwrap(), wire);
    }

    #[test]
    fn sources_authors_capacity_wire_forms() {
        for (source, wire) in [
            (Source::Prompt, json!({"kind": "prompt"})),
            (Source::UserData, json!({"kind": "user_data"})),
            (Source::Store, json!({"kind": "store"})),
            (
                Source::Web { domain: 3 },
                json!({"kind": "web", "domain": 3}),
            ),
            (
                Source::Tool {
                    tool: "web.open".parse().unwrap(),
                },
                json!({"kind": "tool", "tool": "web.open"}),
            ),
            (Source::Memory, json!({"kind": "memory"})),
            (Source::Reader, json!({"kind": "reader"})),
            (Source::Vault, json!({"kind": "vault"})),
        ] {
            assert_eq!(serde_json::to_value(&source).unwrap(), wire);
            assert_eq!(serde_json::from_value::<Source>(wire).unwrap(), source);
        }
        for (author, wire) in [
            (Author::Operator, json!({"kind": "operator"})),
            (Author::User, json!({"kind": "user"})),
            (
                Author::Account { id: 9 },
                json!({"kind": "account", "id": 9}),
            ),
            (Author::Unknown, json!({"kind": "unknown"})),
        ] {
            assert_eq!(serde_json::to_value(author).unwrap(), wire);
            assert_eq!(serde_json::from_value::<Author>(wire).unwrap(), author);
        }
        assert_eq!(
            serde_json::to_value(Capacity::Typed { bits: 8 }).unwrap(),
            json!({"typed": {"bits": 8}})
        );
        assert_eq!(
            serde_json::from_value::<Capacity>(json!({"typed": {"bits": 8}})).unwrap(),
            Capacity::Typed { bits: 8 }
        );
        assert_eq!(
            serde_json::to_value(Capacity::FreeText).unwrap(),
            json!("free_text")
        );
    }

    #[test]
    fn unknown_fields_and_bad_values_rejected() {
        let good = json!({
            "source": {"kind": "prompt"}, "region": "message", "author": {"kind": "user"},
            "trust": 60, "confidential": "private", "capacity": {"typed": {"bits": 1}}
        });
        assert!(serde_json::from_value::<Label>(good.clone()).is_ok());
        let mut extra = good.clone();
        extra["boost"] = json!(1);
        assert!(serde_json::from_value::<Label>(extra).is_err());
        let mut high = good.clone();
        high["trust"] = json!(500);
        assert!(serde_json::from_value::<Label>(high).is_err());
        assert!(serde_json::from_value::<Source>(json!({"kind": "web"})).is_err());
        assert!(
            serde_json::from_value::<Source>(
                json!({"kind": "web", "domain": 1, "name": "evil.test"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<Source>(json!({"kind": "prompt", "x": 1})).is_err());
        assert!(
            serde_json::from_value::<Source>(json!({"kind": "tool", "tool": "Bad Name"})).is_err()
        );
        assert!(serde_json::from_value::<Author>(json!({"kind": "account", "id": -1})).is_err());
        assert!(serde_json::from_value::<Author>(json!({"kind": "account"})).is_err());
        assert!(serde_json::from_value::<Author>(json!({"kind": "operator", "id": 1})).is_err());
        assert!(serde_json::from_value::<Author>(json!({"kind": "user", "name": "x"})).is_err());
        assert!(
            serde_json::from_value::<Source>(
                json!({"kind": "web", "domain": 1, "tool": "web.open"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<Source>(json!({"kind": "prompt", "domain": 1})).is_err());
        assert!(serde_json::from_value::<Source>(json!({"kind": "tool"})).is_err());
        assert!(serde_json::from_value::<Source>(json!({"kind": "nonsense"})).is_err());
        assert!(serde_json::from_value::<Source>(json!({})).is_err());
        assert!(serde_json::from_value::<Capacity>(json!({"typed": {"bits": 1, "x": 2}})).is_err());
    }
}
