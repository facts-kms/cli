use clap::{error::ErrorKind, ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use fact_sdk::environment::{self, LedgerEntry, UserEnvironment};
use std::{
    env,
    error::Error,
    ffi::OsStr,
    fmt, fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode, Stdio},
    str::FromStr,
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub mod actor_exchange;

struct UserMessage(String);

const IDENTITY_EXPORT_SCHEMA: &str = "fact-identity-bundle-v0";

impl fmt::Debug for UserMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for UserMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UserMessage {}

fn user_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(UserMessage(message.into()))
}

fn user_facing_error(error: &(dyn Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<fact_sdk::Error>() {
        return sdk_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_store::Error>() {
        return store_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_canonical::MarkdownError>() {
        return markdown_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_canonical::Error>() {
        return canonical_json_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_schema::Error>() {
        return schema_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_crypto::Error>() {
        return crypto_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_search::Error>() {
        return search_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_commitment::Error>() {
        return commitment_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<fact_core::Error>() {
        return core_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return io_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        return format!("Fact could not read JSON input: {error}");
    }
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return remote_error_message(error);
    }
    if let Some(error) = error.downcast_ref::<hex::FromHexError>() {
        return format!("expected lowercase hexadecimal bytes: {error}");
    }
    if let Some(error) = error.downcast_ref::<toml::de::Error>() {
        return format!("Fact could not read its local configuration: {error}");
    }
    if let Some(error) = error.downcast_ref::<toml::ser::Error>() {
        return format!("Fact could not write its local configuration: {error}");
    }
    if let Some(error) = error.downcast_ref::<uuid::Error>() {
        return format!("that ID is not a valid UUID: {error}");
    }
    error.to_string()
}

fn sdk_error_message(error: &fact_sdk::Error) -> String {
    match error {
        fact_sdk::Error::Validation(message) => message.clone(),
        fact_sdk::Error::Schema(error) => schema_error_message(error),
        fact_sdk::Error::Canonical(error) => canonical_json_error_message(error),
        fact_sdk::Error::Markdown(error) => markdown_error_message(error),
        fact_sdk::Error::Crypto(error) => crypto_error_message(error),
        fact_sdk::Error::Store(error) => store_error_message(error),
        fact_sdk::Error::Search(error) => search_error_message(error),
        fact_sdk::Error::Sync(message) => message.clone(),
        fact_sdk::Error::Commitment(error) => commitment_error_message(error),
        fact_sdk::Error::Authorization(message) => message.clone(),
        fact_sdk::Error::ReadOnlyLedger => {
            "this ledger is read-only; use a local ledger where your identity has permission"
                .to_owned()
        }
        fact_sdk::Error::MissingObject(message) => format!("Fact could not find that object: {message}"),
        fact_sdk::Error::AmbiguousReference(reference) => format!(
            "that reference is ambiguous: {reference}. Use a full proposition or revision ID, or choose --pending/--latest when the command supports it"
        ),
        fact_sdk::Error::NotImplemented(feature) => {
            format!("this command is not implemented yet: {feature}")
        }
        fact_sdk::Error::Conflict(message) => message.clone(),
        fact_sdk::Error::Projected(message) => {
            format!("Fact could not read the local ledger state: {message}")
        }
        fact_sdk::Error::Io(error) => io_error_message(error),
        fact_sdk::Error::TomlDecode(error) => {
            format!("Fact could not read its local configuration: {error}")
        }
        fact_sdk::Error::TomlEncode(error) => {
            format!("Fact could not write its local configuration: {error}")
        }
        fact_sdk::Error::Json(error) => format!("Fact could not read JSON input: {error}"),
        fact_sdk::Error::Hex(error) => format!("expected lowercase hexadecimal bytes: {error}"),
        fact_sdk::Error::Uuid(error) => format!("that ID is not a valid UUID: {error}"),
        fact_sdk::Error::Message(message) => message.clone(),
    }
}

fn store_error_message(error: &fact_store::Error) -> String {
    match error {
        fact_store::Error::Canonical(error) => canonical_json_error_message(error),
        fact_store::Error::Sql(error) => format!("Fact could not read or write the local ledger database: {error}"),
        fact_store::Error::Duplicate => "that object already exists in the ledger".to_owned(),
        fact_store::Error::PayloadMismatch => {
            "the signed object payload does not match its canonical payload".to_owned()
        }
        fact_store::Error::HashMismatch => {
            "the object content hash does not match the stored object".to_owned()
        }
        fact_store::Error::InvalidUuid(field) => {
            format!("the object contains an invalid UUID field: {field}")
        }
        fact_store::Error::InvalidNamespace => "the ledger namespace is invalid".to_owned(),
        fact_store::Error::Schema(error) => schema_error_message(error),
        fact_store::Error::Cose(error) => crypto_error_message(error),
        fact_store::Error::Metadata => "the object contains invalid JSON metadata".to_owned(),
        fact_store::Error::MissingKey => {
            "the signing key for this object is not available in the ledger".to_owned()
        }
        fact_store::Error::InvalidSignature => "the object signature is invalid".to_owned(),
        fact_store::Error::MissingDependency => {
            "this object depends on ledger data that is not available locally; pull or import the missing data and try again".to_owned()
        }
        fact_store::Error::DependencyHashMismatch => {
            "a dependency hash does not match the stored dependency object".to_owned()
        }
        fact_store::Error::InvalidDependency => {
            "the object contains an invalid dependency record".to_owned()
        }
        fact_store::Error::MissingLedger => "the object belongs to a ledger that is not available locally".to_owned(),
        fact_store::Error::ProjectedMismatch => {
            "the local projected does not match the canonical object".to_owned()
        }
        fact_store::Error::StateProjected => {
            "the local ledger state projected is invalid; rebuild the local state and try again".to_owned()
        }
        fact_store::Error::InvalidPublicKey => {
            "the public key in this object is invalid".to_owned()
        }
        fact_store::Error::Unauthorized => {
            "your current identity does not have permission to do that in this ledger".to_owned()
        }
        fact_store::Error::TimeUncertain => {
            "Fact could not tell whether the required permission was valid at that time".to_owned()
        }
        fact_store::Error::InvalidLineage => {
            "that change does not fit the proposition's current history; choose the specific revision you meant and try again".to_owned()
        }
        fact_store::Error::PolicyRejected => {
            "the local ledger policy rejected that object".to_owned()
        }
        fact_store::Error::SearchIndex(message) => {
            format!("Fact could not read the local search index: {message}")
        }
        fact_store::Error::IndexedPropositionStale => {
            "the local proposition read index is stale; run `fact state rebuild` and try again"
                .to_owned()
        }
    }
}

fn canonical_json_error_message(error: &fact_canonical::Error) -> String {
    match error {
        fact_canonical::Error::Utf8 => "JSON input must be valid UTF-8 without a byte-order mark".to_owned(),
        fact_canonical::Error::Eof => "JSON input ended before the object was complete".to_owned(),
        fact_canonical::Error::Syntax(position) => {
            format!("JSON input is invalid near byte {position}")
        }
        fact_canonical::Error::Duplicate(key) => {
            format!("JSON input has the same object key more than once: {key}")
        }
        fact_canonical::Error::NonNfc => "JSON strings must use normalized Unicode text".to_owned(),
        fact_canonical::Error::Number => {
            "JSON numbers must be integers in canonical Fact objects".to_owned()
        }
        fact_canonical::Error::NotCanonical => {
            "JSON input is valid, but it is not in canonical Fact format; write it with sorted object keys and no extra whitespace".to_owned()
        }
    }
}

fn markdown_error_message(error: &fact_canonical::MarkdownError) -> String {
    match error {
        fact_canonical::MarkdownError::Utf8 => {
            "Markdown must be valid UTF-8 without a byte-order mark".to_owned()
        }
        fact_canonical::MarkdownError::NonCanonical => {
            "Markdown is not in canonical Fact format; use a single H1 title, normalized line endings, and a final newline".to_owned()
        }
        fact_canonical::MarkdownError::Whitespace => {
            "Markdown cannot contain tabs or trailing spaces".to_owned()
        }
        fact_canonical::MarkdownError::Unsupported => {
            "Markdown uses formatting that Fact does not support yet".to_owned()
        }
    }
}

fn schema_error_message(error: &fact_schema::Error) -> String {
    match error {
        fact_schema::Error::Canonical(error) => canonical_json_error_message(error),
        fact_schema::Error::NotObject => "Fact objects must be JSON objects".to_owned(),
        fact_schema::Error::Missing(field) => {
            format!("the Fact object is missing a required field: {field}")
        }
        fact_schema::Error::UnknownType => "the Fact object type is not recognized".to_owned(),
        fact_schema::Error::Version => {
            "the Fact object uses an unsupported schema version".to_owned()
        }
        fact_schema::Error::ForbiddenLedger => {
            "this kind of Fact object must not include a ledger ID".to_owned()
        }
        fact_schema::Error::MissingLedger => {
            "this kind of Fact object must include a ledger ID".to_owned()
        }
        fact_schema::Error::UnknownField => {
            "the Fact object has fields that are not part of the protocol".to_owned()
        }
        fact_schema::Error::WrongType(field) => {
            format!("the Fact object field has the wrong type: {field}")
        }
        fact_schema::Error::InvalidUuid(field) => {
            format!("the Fact object has an invalid UUID in field: {field}")
        }
        fact_schema::Error::InvalidTimestamp => {
            "the Fact object has an invalid timestamp".to_owned()
        }
        fact_schema::Error::MissingBodyField(field) => {
            format!("the Fact object body is missing a required field: {field}")
        }
        fact_schema::Error::InvalidBody(field) => {
            format!("the Fact object body has an invalid field: {field}")
        }
        fact_schema::Error::UnknownBodyField(field) => {
            format!("the Fact object body has an unknown field: {field}")
        }
    }
}

fn crypto_error_message(error: &fact_crypto::Error) -> String {
    match error {
        fact_crypto::Error::Seed => {
            "the signing seed is invalid; it must decode to exactly 32 bytes".to_owned()
        }
        fact_crypto::Error::Public => "the public signing key is invalid".to_owned(),
        fact_crypto::Error::Signature => "the object signature is invalid".to_owned(),
        fact_crypto::Error::MalformedCose => {
            "the signed object envelope is malformed and cannot be read".to_owned()
        }
        fact_crypto::Error::UnsupportedCose => {
            "the signed object envelope uses an unsupported format".to_owned()
        }
    }
}

fn search_error_message(error: &fact_search::Error) -> String {
    match error {
        fact_search::Error::Grammar => "the search score is not valid".to_owned(),
        fact_search::Error::Scale => "the search score is too precise".to_owned(),
        fact_search::Error::Range => "the search score is outside the allowed range".to_owned(),
        fact_search::Error::Sentinel => "this search profile requires a zero score".to_owned(),
        fact_search::Error::Markdown(error) => markdown_error_message(error),
        fact_search::Error::Sql(error) => {
            format!("Fact could not read or write the local search database: {error}")
        }
        fact_search::Error::FtsUnavailable => {
            "the local SQLite build does not support full-text search".to_owned()
        }
        fact_search::Error::StoredHash => {
            "the local search index contains an invalid object hash; rebuild the index and try again"
                .to_owned()
        }
        fact_search::Error::InvalidQuery => "the search query object is invalid".to_owned(),
        fact_search::Error::InvalidCursor => {
            "the search cursor is invalid or no longer matches this query".to_owned()
        }
    }
}

fn commitment_error_message(error: &fact_commitment::Error) -> String {
    match error {
        fact_commitment::Error::Duplicate => {
            "the object hash list contains the same hash more than once".to_owned()
        }
        fact_commitment::Error::Index => "the proof index is outside the hash list".to_owned(),
        fact_commitment::Error::InvalidProof => {
            "the commitment proof does not match the supplied hashes".to_owned()
        }
        fact_commitment::Error::Present => {
            "that object hash is already present in the commitment".to_owned()
        }
    }
}

fn io_error_message(error: &std::io::Error) -> String {
    match error.kind() {
        io::ErrorKind::NotFound => format!("file or directory not found: {error}"),
        io::ErrorKind::PermissionDenied => {
            format!("permission denied while reading or writing a file: {error}")
        }
        io::ErrorKind::AlreadyExists => format!("file already exists: {error}"),
        _ => format!("I/O failed: {error}"),
    }
}

fn core_error_message(error: &fact_core::Error) -> String {
    match error {
        fact_core::Error::InvalidHash => {
            "object hashes must be 64 lowercase hexadecimal characters".to_owned()
        }
        fact_core::Error::InvalidUuid(value) => format!("that ID is not a valid UUID: {value}"),
        fact_core::Error::InvalidTimestamp(value) => {
            format!("that timestamp is not valid: {value}")
        }
    }
}

fn remote_error_message(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return format!("the remote ledger did not respond before the request timed out: {error}");
    }
    if error.is_connect() {
        return format!("Fact could not connect to the remote ledger: {error}");
    }
    if error.is_decode() {
        return format!("Fact could not read the remote ledger response: {error}");
    }
    format!("remote ledger request failed: {error}")
}

#[derive(Clone, Copy)]
struct CapabilityInfo {
    name: &'static str,
    description: &'static str,
    privileged: bool,
}

const GRANTABLE_CAPABILITIES: &[CapabilityInfo] = &[
    CapabilityInfo {
        name: "propose",
        description: "create propositions",
        privileged: false,
    },
    CapabilityInfo {
        name: "deliberate",
        description: "join or participate in deliberations",
        privileged: false,
    },
    CapabilityInfo {
        name: "invite",
        description: "invite actors to deliberations",
        privileged: false,
    },
    CapabilityInfo {
        name: "comment",
        description: "comment on deliberations",
        privileged: false,
    },
    CapabilityInfo {
        name: "accept",
        description: "accept revisions as a participant",
        privileged: false,
    },
    CapabilityInfo {
        name: "reject",
        description: "reject revisions as a participant",
        privileged: false,
    },
    CapabilityInfo {
        name: "withdraw",
        description: "withdraw propositions while preserving history",
        privileged: false,
    },
    CapabilityInfo {
        name: "archive",
        description: "archive propositions while preserving history",
        privileged: false,
    },
    CapabilityInfo {
        name: "admin",
        description: "grant or revoke permissions",
        privileged: true,
    },
];

const PARTICIPATION_CAPABILITIES: &[&str] =
    &["propose", "deliberate", "comment", "accept", "reject"];

const ALLOWED_CAPABILITIES_TEXT: &str =
    "propose, deliberate, invite, comment, accept, reject, withdraw, archive, admin";

#[derive(Parser)]
#[command(
    name = "fact",
    version,
    about = "A simple, adaptable substrate for trusted knowledge",
    long_about = "A simple, adaptable substrate for trusted knowledge.",
    after_help = "More:\n  fact help --all       Show all commands grouped by topic\n  fact help COMMAND     Show help for one command",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(
        long,
        global = true,
        help = "Print results as JSON for scripts and other programs"
    )]
    json: bool,
    #[arg(
        long,
        global = true,
        conflicts_with = "no_pager",
        help = "Page long human output"
    )]
    pager: bool,
    #[arg(
        long,
        global = true,
        conflicts_with = "pager",
        help = "Never page output"
    )]
    no_pager: bool,
}
#[derive(Subcommand)]
enum Command {
    #[command(about = "Show help for Fact commands", display_order = 50)]
    Help {
        #[arg(value_name = "COMMAND", num_args = 0.., help = "The command whose detailed help you want")]
        command: Vec<String>,
        #[arg(
            long,
            conflicts_with = "command",
            help = "Show all commands grouped by topic"
        )]
        all: bool,
    },
    #[command(
        hide = true,
        about = "List grantable permission capabilities",
        display_order = 16
    )]
    Capabilities {
        #[arg(help = "Actor ID, short ref, directory alias, or display name to inspect")]
        actor: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Create or switch the active user for the current ledger",
        display_order = 15
    )]
    As {
        #[arg(
            value_name = "DISPLAY_NAME_OR_ALIAS",
            help = "Display name to register, or alias to switch to"
        )]
        name: Option<String>,
        #[arg(short = 'a', long, help = "Stable directory alias for the actor")]
        alias: Option<String>,
        #[arg(
            long = "self",
            conflicts_with = "no_create",
            help = "Register the current ledger identity in the directory"
        )]
        self_actor: bool,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Apply a FACT_HOME actor profile")]
        profile: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(long, help = "Source for this directory entry")]
        source: Option<String>,
        #[arg(long, help = "Who verified this directory entry")]
        verified_by: Option<String>,
        #[arg(
            long,
            value_name = "PATH",
            num_args = 0..=1,
            help = "Prepare a dedicated FACT_HOME for this actor"
        )]
        home: Option<Option<PathBuf>>,
        #[arg(long, requires = "home", help = "Print a shell-ready FACT_HOME export")]
        print_env: bool,
        #[arg(
            long,
            requires = "home",
            help = "Verify final status from the prepared actor FACT_HOME"
        )]
        use_home: bool,
        #[arg(
            long,
            value_name = "CAPABILITY",
            action = ArgAction::Append,
            help = "Capability to grant when creating a new actor; repeat for more. Allowed: propose, deliberate, invite, comment, accept, reject, withdraw, archive, admin"
        )]
        permission: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            conflicts_with_all = ["self_actor", "update_directory"],
            help = "Resolve and switch only; do not create or update state"
        )]
        no_create: bool,
        #[arg(
            long,
            help = "Update the directory entry when supplied metadata differs"
        )]
        update_directory: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Start a new local ledger for your facts", display_order = 60)]
    Init {
        #[arg(help = "A friendly name for the new ledger (default: default)")]
        name: Option<String>,
        #[arg(long, help = "Use a reusable local persona as the ledger admin")]
        persona: Option<String>,
    },
    #[command(
        hide = true,
        about = "Initialize a project-local Fact environment in .facts",
        display_order = 0
    )]
    Here {
        #[arg(
            long,
            help = "Directory where .facts should be created (default: current directory)"
        )]
        path: Option<PathBuf>,
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "default",
            help = "Also create a local ledger in .facts (default: default)"
        )]
        init: Option<String>,
        #[arg(
            long,
            requires = "init",
            help = "Use a reusable local persona as the ledger admin"
        )]
        persona: Option<String>,
        #[arg(
            long,
            requires = "init",
            help = "Create the ledger without activating it"
        )]
        no_switch: bool,
        #[arg(
            long,
            help = "Accept an existing .facts directory and create missing Fact files"
        )]
        force: bool,
        #[arg(long, help = "Print an export command for the created .facts path")]
        print_env: bool,
    },
    #[command(
        hide = true,
        about = "Create a new local ledger without switching to it",
        display_order = 0
    )]
    New {
        #[arg(help = "A friendly name for the new ledger (default: default)")]
        name: Option<String>,
        #[arg(long, help = "Use a reusable local persona as the ledger admin")]
        persona: Option<String>,
    },
    #[command(about = "Copy a shared ledger into a local mirror", display_order = 18)]
    Clone {
        #[arg(help = "A local bundle path or remote URL to copy")]
        source: Option<String>,
        #[arg(
            long,
            conflicts_with = "source",
            help = "The configured remote to copy"
        )]
        remote: Option<String>,
        #[arg(
            long = "from",
            conflicts_with_all = ["source", "remote"],
            help = "A remote descriptor to configure and clone from"
        )]
        descriptor: Option<PathBuf>,
        #[arg(long, help = "The ledger to copy when the source is remote")]
        ledger: Option<String>,
        #[arg(long, help = "A friendly local name for the cloned ledger")]
        name: Option<String>,
        #[arg(
            long = "as",
            help = "Create a writable clone as a local identity already recognized and granted in the remote ledger"
        )]
        actor: Option<String>,
    },
    #[command(
        hide = true,
        about = "Register an existing ledger database as a read-only ledger",
        display_order = 0
    )]
    From {
        #[arg(help = "An existing SQLite Fact ledger database")]
        database: PathBuf,
        #[arg(help = "A friendly name for the registered ledger")]
        name: Option<String>,
        #[arg(
            long,
            help = "The ledger to use when the database contains more than one ledger"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Switch the ledger used by everyday commands",
        display_order = 200
    )]
    Use {
        #[arg(help = "The friendly name of the local ledger to use")]
        name: String,
    },
    #[command(
        about = "Add a new proposition, optionally deciding it immediately",
        display_order = 100
    )]
    Propose {
        #[arg(help = "A Markdown file, - for standard input, or omit to open an editor")]
        file: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            help = "Accept or reject the proposition as part of creation"
        )]
        decision: Option<DecisionChoice>,
        #[arg(
            long,
            help = "Use this short Markdown text instead of a file or editor"
        )]
        message: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Inspect or repair a proposition's review process"
    )]
    Deliberate {
        #[arg(help = "A proposition ID or other reference understood by Fact")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(hide = true, about = "List review steps associated with a proposition")]
    Deliberations {
        #[arg(help = "A proposition reference to review")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(hide = true, about = "Show review details for a proposition")]
    ShowDeliberation {
        #[arg(help = "A review reference")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Add a comment to a proposition or its discussion",
        display_order = 20
    )]
    Comment {
        #[arg(help = "A proposition, revision, or discussion reference")]
        reference: String,
        #[arg(help = "A Markdown file, - for standard input, or omit to open an editor")]
        file: Option<PathBuf>,
        #[arg(
            long,
            help = "Use this short Markdown text instead of a file or editor"
        )]
        message: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "List comments attached to a proposition or revision",
        display_order = 21
    )]
    Comments {
        #[arg(help = "A proposition, revision, or discussion reference")]
        reference: Option<String>,
        #[arg(long, help = "Only show comments associated with this revision")]
        revision: Option<String>,
        #[arg(long, help = "Only show comments by the active actor")]
        mine: bool,
        #[arg(long, help = "Only show comments by this actor")]
        author: Option<String>,
        #[arg(long, help = "Only show comments that mention the active actor")]
        mentions_me: bool,
        #[arg(
            long,
            value_name = "WHEN",
            help = "Only show comments since a timestamp or duration such as 7d"
        )]
        since: Option<String>,
        #[arg(
            long,
            help = "Show unresolved comments when comment lifecycle state is available"
        )]
        unresolved: bool,
        #[arg(
            long,
            value_name = "TEXT",
            help = "Only show comments containing this text"
        )]
        text: Option<String>,
        #[arg(
            long,
            default_value_t = 50,
            help = "Maximum comments to show; use 0 to show none"
        )]
        limit: usize,
        #[arg(long, help = "Print full comment content instead of summaries")]
        content: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Show an overview of a proposition and its related state",
        display_order = 170
    )]
    Show {
        #[arg(help = "A proposition, revision, discussion, or comment reference")]
        reference: String,
        #[arg(
            long,
            default_value_t = 5,
            help = "Number of recent revisions to show; use 0 to hide revisions"
        )]
        revisions: usize,
        #[arg(
            long,
            default_value_t = 10,
            help = "Number of recent comments to show; use 0 to hide comments"
        )]
        comments: usize,
        #[arg(
            long,
            help = "Always include conflict data; conflicts are shown automatically when present"
        )]
        conflicts: bool,
        #[arg(
            long,
            help = "Always include pending-decision data; pending actions are shown automatically when present"
        )]
        pending: bool,
        #[arg(long, help = "Include active deliberation participants")]
        participants: bool,
        #[arg(long, help = "Include recent lifecycle/history entries")]
        history: bool,
        #[arg(long, help = "Include normally hidden or less relevant related state")]
        all: bool,
        #[arg(
            long,
            conflicts_with = "no_content",
            help = "Print effective revision content"
        )]
        content: bool,
        #[arg(
            long,
            conflicts_with = "content",
            help = "Do not print effective revision content"
        )]
        no_content: bool,
        #[arg(
            long,
            default_value_t = 100,
            help = "General cap for repeated subsections; use 0 for no limit"
        )]
        limit: usize,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "List proposition revision conflicts",
        display_order = 0
    )]
    Conflicts {
        #[arg(help = "A proposition or revision reference to inspect")]
        reference: Option<String>,
        #[arg(
            long,
            help = "Include resolved, non-current, or historical conflict groups when available"
        )]
        all: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Mark a proposition as accepted", display_order = 10)]
    Accept {
        #[arg(
            help = "A proposition reference; omit when Fact can identify one pending proposition"
        )]
        reference: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Mark a proposition as rejected", display_order = 130)]
    Reject {
        #[arg(
            help = "A proposition reference; omit when Fact can identify one pending proposition"
        )]
        reference: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Invite someone to join a proposition's discussion",
        display_order = 0
    )]
    Invite {
        #[arg(help = "The proposition or discussion to join")]
        reference: String,
        #[arg(help = "The person or actor to invite")]
        actor: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Review and act on discussion invitations",
        display_order = 0
    )]
    Invitations {
        #[command(subcommand)]
        command: Option<InvitationsCommand>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Join a discussion using an invitation",
        display_order = 0
    )]
    Join {
        #[arg(help = "The proposition, discussion, or invitation to join")]
        reference: String,
        #[arg(
            long,
            help = "The invitation ID or token when joining a proposition or discussion"
        )]
        invitation: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Leave a proposition's discussion",
        display_order = 0
    )]
    Leave {
        #[arg(help = "The proposition or discussion to leave")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Withdraw a proposition while keeping its history",
        display_order = 0
    )]
    Withdraw {
        #[arg(help = "The proposition to withdraw")]
        reference: String,
        #[arg(long, help = "A short explanation for the withdrawal")]
        reason: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Archive a proposition while keeping its history",
        display_order = 0
    )]
    Archive {
        #[arg(help = "The proposition to archive")]
        reference: String,
        #[arg(long, help = "A short explanation for the archival")]
        reason: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Display the current effective text of a proposition",
        display_order = 80
    )]
    Open {
        #[arg(help = "The proposition or revision to open")]
        reference: String,
        #[arg(
            long,
            conflicts_with = "latest",
            help = "Open the first pending revision"
        )]
        pending: bool,
        #[arg(long, conflicts_with = "pending", help = "Open the latest revision")]
        latest: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Print the current effective text of a proposition",
        display_order = 30
    )]
    Echo {
        #[arg(help = "The proposition or revision to print")]
        reference: String,
        #[arg(
            long,
            conflicts_with = "latest",
            help = "Print the first pending revision"
        )]
        pending: bool,
        #[arg(long, conflicts_with = "pending", help = "Print the latest revision")]
        latest: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Save a proposition's current text to a file",
        display_order = 0
    )]
    Export {
        #[arg(help = "The proposition or revision to export")]
        reference: String,
        #[arg(help = "Where to write the Markdown text")]
        file: PathBuf,
        #[arg(long, help = "Replace the output file if it already exists")]
        force: bool,
        #[arg(
            long,
            conflicts_with = "latest",
            help = "Export the first pending revision"
        )]
        pending: bool,
        #[arg(long, conflicts_with = "pending", help = "Export the latest revision")]
        latest: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Create a proposition from Markdown, optionally deciding it immediately",
        display_order = 0
    )]
    Import {
        #[arg(help = "A Markdown file, - for standard input, or omit to open an editor")]
        file: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            help = "Accept or reject the proposition as part of creation"
        )]
        decision: Option<DecisionChoice>,
        #[arg(
            long,
            help = "Use this short Markdown text instead of a file or editor"
        )]
        message: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(alias = "edit")]
    #[command(about = "Create a new revision of a proposition", display_order = 160)]
    Revise {
        #[arg(help = "The proposition to revise")]
        reference: String,
        #[arg(help = "A Markdown file, - for standard input, or omit to open an editor")]
        file: Option<PathBuf>,
        #[arg(
            long,
            help = "Use this short Markdown text instead of a file or editor"
        )]
        message: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Show which local ledger is active", display_order = 180)]
    Status {
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "List propositions and their current status",
        display_order = 70
    )]
    List {
        #[arg(long, value_enum, help = "Only show propositions with this status")]
        status: Option<ListStatus>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
        #[arg(
            long,
            default_value_t = 100,
            help = "Maximum rows to show; use 0 for no limit"
        )]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Number of rows to skip")]
        offset: usize,
        #[arg(long, help = "Start after this proposition reference")]
        after: Option<String>,
        #[arg(
            long,
            help = "Include propositions normally hidden from the everyday list"
        )]
        all: bool,
    },
    #[command(
        hide = true,
        about = "List the revisions of a proposition",
        display_order = 0
    )]
    Revisions {
        #[arg(help = "The proposition whose revisions you want to see")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "List propositions that still need a decision",
        display_order = 90
    )]
    Pending {
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Show, change, and search proposition tags",
        display_order = 190,
        override_usage = "tags [--list] [OPTIONS]\n       tags REF ACTION [TAG_1] [TAG_2]... [OPTIONS]\n       tags --search TAG_1 [TAG_2]... [OPTIONS]\n       tags export FILE [OPTIONS]\n       tags import FILE [OPTIONS]"
    )]
    Tags {
        #[arg(
            value_name = "REF",
            help = "A proposition reference for show or mutation actions"
        )]
        reference: Option<String>,
        #[arg(
            value_name = "ACTION",
            help = "One of show, add, remove, set, or clear"
        )]
        action: Option<String>,
        #[arg(
            value_name = "TAG",
            help = "Tags for mutation actions or additional search tags"
        )]
        tags: Vec<String>,
        #[arg(long, help = "List all effective tags in the selected ledger")]
        list: bool,
        #[arg(long, help = "Include proposition usage counts when listing tags")]
        counts: bool,
        #[arg(
            long,
            value_name = "TAG",
            num_args = 1..,
            help = "Search propositions by one or more tags"
        )]
        search: Vec<String>,
        #[arg(
            long = "match",
            value_enum,
            default_value_t = TagMatch::All,
            help = "Match any requested tag or all requested tags"
        )]
        match_mode: TagMatch,
        #[arg(
            long,
            value_name = "TEXT",
            help = "With --search, further filter by indexed proposition text"
        )]
        text: Option<String>,
        #[arg(long, value_enum, help = "Only show propositions with this status")]
        status: Option<ListStatus>,
        #[arg(
            long,
            help = "Include propositions normally hidden from the everyday list"
        )]
        all: bool,
        #[arg(
            long,
            default_value_t = 100,
            help = "Maximum rows to show; use 0 for no limit"
        )]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Number of rows to skip")]
        offset: usize,
        #[arg(long, help = "Start after this proposition reference")]
        after: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Create and inspect reconciliation propositions",
        display_order = 0
    )]
    Reconcile {
        #[command(subcommand)]
        command: ReconcileCommand,
    },
    #[command(
        about = "Resolve a proposition revision conflict",
        display_order = 150,
        override_usage = "resolve [OPTIONS] [REF] [FILE]"
    )]
    Resolve {
        #[arg(help = "A proposition, revision, or conflict reference to resolve")]
        reference: Option<String>,
        #[arg(help = "A Markdown file, - for standard input, or omit to open an editor")]
        file: Option<PathBuf>,
        #[arg(long, help = "Copy this conflicting revision into the resolution")]
        keep: Option<String>,
        #[arg(
            long,
            help = "Use this canonical Markdown text as the resolution content"
        )]
        message: Option<String>,
        #[arg(long, help = "Resolve with an external merge tool")]
        merge: bool,
        #[arg(
            long,
            value_name = "REF",
            help = "Revision branch to merge; repeatable"
        )]
        pick: Vec<String>,
        #[arg(long, help = "Merge tool command to run; otherwise use $FACT_MERGE")]
        tool: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        hide = true,
        about = "Find propositions containing matching words",
        display_order = 0
    )]
    Search {
        #[arg(help = "Words to find in proposition text")]
        text: String,
        #[arg(
            long,
            value_enum,
            help = "Only include propositions with this effective status"
        )]
        status: Option<ListStatus>,
        #[arg(
            long,
            help = "Only search the currently effective proposition revision"
        )]
        effective: bool,
        #[arg(
            long,
            value_name = "TAG",
            action = ArgAction::Append,
            help = "Only include propositions with these tags"
        )]
        tag: Vec<String>,
        #[arg(
            long = "tag-match",
            value_enum,
            default_value_t = TagMatch::All,
            help = "Match any requested tag or all requested tags"
        )]
        tag_match: TagMatch,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
        #[arg(
            long,
            default_value_t = 20,
            help = "Maximum number of results to show (default: 20)"
        )]
        page_size: usize,
    },
    #[command(
        about = "Find accepted propositions and optionally use one",
        display_order = 40
    )]
    Find {
        #[arg(help = "Words to find in accepted proposition text")]
        text: String,
        #[arg(
            long,
            value_name = "TAG",
            action = ArgAction::Append,
            help = "Only include propositions with these tags"
        )]
        tag: Vec<String>,
        #[arg(
            long = "tag-match",
            value_enum,
            default_value_t = TagMatch::All,
            help = "Match any requested tag or all requested tags"
        )]
        tag_match: TagMatch,
        #[arg(
            long,
            value_name = "COMMAND",
            help = "Run a command with the selected proposition as its first argument, e.g. --with echo or --with revisions"
        )]
        with: Option<String>,
        #[arg(long, help = "Select one result by its 1-based list number")]
        pick: Option<usize>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(alias = "log")]
    #[command(
        hide = true,
        about = "Show the history of a proposition and its revisions",
        display_order = 0
    )]
    History {
        #[arg(help = "The proposition to inspect; omit to show the ledger history")]
        reference: Option<String>,
        #[arg(long, help = "Maximum history entries to show; use 0 for all")]
        limit: Option<usize>,
        #[arg(long, help = "Resume after this content-hash cursor")]
        after: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Send local ledger data to a file or configured remote",
        display_order = 120
    )]
    Push {
        #[arg(help = "A local database to export (advanced use)")]
        database: Option<PathBuf>,
        #[arg(help = "A bundle file to create (advanced use)")]
        file: Option<PathBuf>,
        #[arg(long, help = "The configured remote to send data to")]
        remote: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(
        about = "Bring ledger data into a local ledger or file",
        display_order = 110
    )]
    Pull {
        #[arg(help = "A local database to update (advanced use)")]
        database: Option<PathBuf>,
        #[arg(help = "Use a ledger name, remote name, UUID, or short reference")]
        ledger: Option<String>,
        #[arg(help = "A bundle file to create or read (advanced use)")]
        output: Option<PathBuf>,
        #[arg(long, help = "A file containing hashes already known locally")]
        known_hashes: Option<PathBuf>,
        #[arg(long, help = "Resume after this content-hash cursor")]
        after: Option<String>,
        #[arg(long, help = "Maximum objects to pull")]
        limit: Option<usize>,
        #[arg(long, help = "Maximum total object bytes to pull")]
        max_object_bytes: Option<usize>,
        #[arg(long, help = "The configured remote to fetch data from")]
        remote: Option<String>,
    },
    #[command(
        hide = true,
        about = "Manage local identity keys and authority records",
        display_order = 0
    )]
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    #[command(
        about = "Exchange actors with remote ledger administrators",
        display_order = 11
    )]
    Actor {
        #[command(subcommand)]
        command: ActorCommand,
    },
    #[command(
        about = "Manage reusable local actor profile metadata",
        display_order = 95
    )]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(about = "Manage reusable local signing personas", display_order = 94)]
    Persona {
        #[command(subcommand)]
        command: PersonaCommand,
    },
    #[command(
        hide = true,
        about = "Manage ledger-scoped friendly identity directory entries",
        display_order = 0
    )]
    Directory {
        #[command(subcommand)]
        command: DirectoryCommand,
    },
    #[command(
        hide = true,
        about = "Grant or remove permission to perform ledger actions"
    )]
    Permission {
        #[command(subcommand)]
        command: PermissionCommand,
    },
    #[command(
        about = "Manage the remotes saved in this local environment",
        display_order = 140
    )]
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    #[command(
        hide = true,
        about = "Run and administer a Facts HTTP collaboration server",
        display_order = 55
    )]
    Http {
        #[command(subcommand)]
        command: HttpCommand,
    },
    #[command(hide = true, about = "Manage local ledgers and their configuration")]
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },
    #[command(
        hide = true,
        about = "Validate, import, and export signed protocol objects"
    )]
    Object {
        #[command(subcommand)]
        command: ObjectCommand,
    },
    #[command(hide = true, about = "Rebuild a local read model from ledger events")]
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    #[command(hide = true, about = "Build and verify compact lists of object hashes")]
    Commitment {
        #[command(subcommand)]
        command: CommitmentCommand,
    },
    #[command(hide = true, about = "Add or remove objects from a commitment proof")]
    Proof {
        #[command(subcommand)]
        command: ProofCommand,
    },
    #[command(
        hide = true,
        about = "Run low-level searches against a ledger database"
    )]
    Query {
        #[command(subcommand)]
        command: QueryCommand,
    },
    #[command(hide = true, about = "Verify a completed decision settlement")]
    Settlement {
        #[command(subcommand)]
        command: SettlementCommand,
    },
    #[command(hide = true, about = "Exchange ledger bundles with files or remotes")]
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    #[command(hide = true, about = "Inspect and manage a formal discussion")]
    Deliberation {
        #[command(subcommand)]
        command: DeliberationCommand,
    },
    #[command(hide = true, about = "Record a participant's decision in a discussion")]
    Decision {
        #[command(subcommand)]
        command: DecisionCommand,
    },
    #[command(
        hide = true,
        about = "Inspect the signed proposition objects behind the friendly CLI"
    )]
    Proposition {
        #[command(subcommand)]
        command: PropositionCommand,
    },
    #[command(hide = true, about = "Run implementation conformance checks")]
    Conformance {
        #[command(subcommand)]
        command: ConformanceCommand,
    },
}

#[derive(Subcommand)]
enum ActorCommand {
    #[command(about = "Create or switch a ledger actor")]
    New {
        #[arg(help = "Display name to register, or alias to switch to")]
        name: Option<String>,
        #[arg(short = 'a', long, help = "Stable directory alias for the actor")]
        alias: Option<String>,
        #[arg(long, help = "Apply a FACT_HOME actor profile")]
        profile: Option<String>,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(
            long,
            value_name = "CAPABILITY",
            action = ArgAction::Append,
            help = "Capability to grant when creating a new actor"
        )]
        permission: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "List ledger actors")]
    List {
        #[arg(
            long,
            default_value_t = 100,
            help = "Maximum rows to show; use 0 for no limit"
        )]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Number of rows to skip")]
        offset: usize,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Show one ledger actor")]
    Show {
        #[arg(help = "Actor ID, short ref, directory alias, or display name")]
        actor: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Use a local actor for future writes in a ledger")]
    Use {
        #[arg(help = "Actor ID, directory alias, or display name")]
        actor: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Name or rename a ledger actor")]
    Name {
        #[arg(help = "Actor ID, directory alias, or display name")]
        actor: String,
        #[arg(help = "Display name for the actor")]
        name: String,
        #[arg(long, help = "Stable directory alias for the actor")]
        alias: Option<String>,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Grant ledger capabilities to an actor")]
    Grant {
        #[arg(help = "Actor ID, alias, or display name")]
        actor: String,
        #[arg(long = "capability", help = "Capability to grant; repeat for more")]
        capabilities: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Revoke a ledger capability grant")]
    Revoke {
        #[arg(help = "Grant ID to revoke")]
        grant: String,
        #[arg(long, help = "A short explanation for removing the grant")]
        reason: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Create a remote ledger admission request")]
    Send {
        #[arg(help = "Display name or stable local actor name")]
        name: Option<String>,
        #[arg(long, help = "Stable alias claimed by this actor")]
        alias: Option<String>,
        #[arg(long, help = "Apply a FACT_HOME actor profile")]
        profile: Option<String>,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(
            long = "request",
            help = "Capability requested from the remote admin; repeat for more"
        )]
        requests: Vec<String>,
        #[arg(
            long,
            help = "Request participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            short = 'o',
            help = "Where to write the request artifact (default: ALIAS.actor.json)"
        )]
        output: Option<PathBuf>,
    },
    #[command(about = "Inspect a remote ledger admission request")]
    Inspect {
        #[arg(help = "A remote actor request artifact")]
        file: PathBuf,
    },
    #[command(about = "Import, name, recognize, and grant a remote actor")]
    Admit {
        #[arg(conflicts_with = "input", help = "A remote actor request artifact")]
        file: Option<PathBuf>,
        #[arg(
            long,
            short = 'i',
            help = "Read request artifact from FILE, or - for standard input"
        )]
        input: Option<PathBuf>,
        #[arg(long, help = "Override the requested display name")]
        name: Option<String>,
        #[arg(long, help = "Override the requested alias")]
        alias: Option<String>,
        #[arg(long = "type", help = "Override the requested actor type")]
        actor_type: Option<String>,
        #[arg(long = "capability", help = "Capability to grant; repeat for more")]
        capabilities: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(long, help = "Also issue an HTTP bearer token")]
        with_token: bool,
        #[arg(long, requires = "with_token", help = "Token expiry in days")]
        token_expires_days: Option<i64>,
        #[arg(long, requires = "with_token", help = "Operator label for the token")]
        token_label: Option<String>,
        #[arg(
            long,
            requires = "with_token",
            help = "Path to the server token SQLite database"
        )]
        token_store: Option<PathBuf>,
        #[arg(long, short = 'o', help = "Where to write the response artifact")]
        output: Option<PathBuf>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
        #[arg(
            long,
            help = "Configured remote name or URL to include in the response endpoint"
        )]
        remote: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    #[command(about = "Create a reusable local actor profile")]
    Add {
        #[arg(help = "Profile name")]
        profile: String,
        #[arg(long, help = "Display name to apply in ledgers")]
        name: String,
        #[arg(long, help = "Stable alias to apply in ledgers")]
        alias: Option<String>,
        #[arg(
            long = "type",
            default_value = "human",
            help = "Actor type: human, agent, or service"
        )]
        actor_type: String,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(long, help = "Make this the default profile")]
        default: bool,
    },
    #[command(about = "List reusable local actor profiles")]
    List,
    #[command(about = "Show one reusable local actor profile")]
    Show {
        #[arg(help = "Profile name")]
        profile: String,
    },
    #[command(about = "Update a reusable local actor profile")]
    Update {
        #[arg(help = "Profile name")]
        profile: String,
        #[arg(long, help = "Display name to apply in ledgers")]
        name: Option<String>,
        #[arg(long, help = "Stable alias to apply in ledgers")]
        alias: Option<String>,
        #[arg(long, help = "Clear the stored alias")]
        clear_alias: bool,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(long, help = "Clear the stored role")]
        clear_role: bool,
    },
    #[command(about = "Delete a reusable local actor profile")]
    Delete {
        #[arg(help = "Profile name")]
        profile: String,
    },
    #[command(about = "Set the default reusable local actor profile")]
    Default {
        #[arg(help = "Profile name")]
        profile: String,
    },
    #[command(about = "Apply a profile to ledger directory entries")]
    Apply {
        #[arg(help = "Profile name; defaults to the configured default profile")]
        profile: Option<String>,
        #[arg(
            long,
            action = ArgAction::Append,
            help = "Ledger to update; repeat to update multiple ledgers"
        )]
        ledger: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PersonaCommand {
    #[command(about = "Create a reusable local signing persona")]
    Add {
        #[arg(help = "Persona name")]
        persona: String,
        #[arg(long, help = "Display name for status and directory metadata")]
        name: String,
        #[arg(long, help = "Stable alias for status and directory metadata")]
        alias: Option<String>,
        #[arg(
            long = "type",
            default_value = "human",
            help = "Actor type: human, agent, or service"
        )]
        actor_type: String,
        #[arg(long, help = "Make this the default persona for new ledgers")]
        default: bool,
    },
    #[command(about = "List reusable local signing personas")]
    List,
    #[command(about = "Show one reusable local signing persona")]
    Show {
        #[arg(help = "Persona name, actor ID, short ref, or alias")]
        persona: String,
    },
    #[command(about = "Set the default reusable local signing persona")]
    Default {
        #[arg(help = "Persona name, actor ID, short ref, or alias")]
        persona: String,
    },
}

#[derive(Subcommand)]
enum InvitationsCommand {
    #[command(about = "List all invitations for the active actor")]
    List,
    #[command(about = "Join a discussion using an invitation")]
    Accept {
        #[arg(help = "The invitation reference")]
        reference: String,
    },
    #[command(about = "Decline an invitation")]
    Reject {
        #[arg(help = "The invitation reference")]
        reference: String,
        #[arg(long, help = "Reason recorded with the rejection")]
        reason: Option<String>,
    },
    #[command(about = "Show invitation details and next actions")]
    Show {
        #[arg(help = "The invitation reference")]
        reference: String,
    },
    #[command(about = "List invitations sent by the active actor")]
    Sent,
    #[command(about = "List invitations received by the active actor")]
    Received,
    #[command(about = "List active invitations that can still be acted on")]
    Pending,
}

#[derive(Subcommand)]
enum IdentityCommand {
    #[command(about = "Create a new local signing identity")]
    New {
        #[arg(
            long = "type",
            default_value = "human",
            help = "Actor type: human, agent, or service"
        )]
        actor_type: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "List imported actor identities")]
    List {
        #[arg(
            long,
            default_value_t = 100,
            help = "Maximum rows to show; use 0 for no limit"
        )]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Number of rows to skip")]
        offset: usize,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Show one imported actor identity")]
    Show {
        #[arg(help = "Actor ID, short ref, directory alias, or display name")]
        actor: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Use a local identity for future writes in a ledger")]
    Use {
        #[arg(help = "Actor ID, directory alias, or display name")]
        actor: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Import public identity objects without granting permissions")]
    Import {
        #[arg(help = "A file containing public identity objects")]
        file: PathBuf,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Export public identity objects safe to transmit")]
    Export {
        #[arg(
            value_name = "FILE",
            help = "Where to write public identity objects; private seeds stay under .facts/identities"
        )]
        file: Option<PathBuf>,
        #[arg(long, help = "Actor ID, short ref, directory alias, or display name")]
        actor: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Recognize an identity and grant it capabilities")]
    Recognize {
        #[arg(help = "The actor or identity to recognize")]
        actor: String,
        #[arg(
            long = "capability",
            help = "An action this identity may perform; repeat for more actions. Allowed: propose, deliberate, invite, comment, accept, reject, withdraw, archive, admin"
        )]
        capabilities: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Remove a previously granted authority record")]
    Revoke {
        #[arg(help = "The ID of the permission grant to remove")]
        grant: String,
        #[arg(long, help = "A short explanation for removing the grant")]
        reason: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Create a new signing key while retaining the old key for history")]
    Rotate {
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
}

#[derive(Subcommand)]
enum DirectoryCommand {
    #[command(about = "Add a friendly directory entry")]
    Add {
        #[arg(help = "Display name for the actor")]
        display_name: String,
        #[arg(long, help = "Actor ID to name")]
        actor: Option<String>,
        #[arg(
            long = "self",
            conflicts_with_all = ["actor", "with_identity"],
            help = "Name the current ledger identity; implies --type human unless --type is passed"
        )]
        self_actor: bool,
        #[arg(long, help = "Key ID to associate with the actor")]
        key: Option<String>,
        #[arg(long, help = "Stable command alias")]
        alias: Option<String>,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(long, help = "Source for this directory entry")]
        source: Option<String>,
        #[arg(long, help = "Who verified this directory entry")]
        verified_by: Option<String>,
        #[arg(long, help = "Create a new local identity and name it")]
        with_identity: bool,
        #[arg(long, help = "Also issue an HTTP bearer token for this actor")]
        with_token: bool,
        #[arg(
            long,
            requires = "with_token",
            help = "Token expiry in days when using --with-token"
        )]
        token_expires_days: Option<i64>,
        #[arg(
            long,
            requires = "with_token",
            help = "Operator label for the token created by --with-token"
        )]
        token_label: Option<String>,
        #[arg(
            long,
            requires = "with_token",
            help = "Path to the server token SQLite database"
        )]
        token_store: Option<PathBuf>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "List friendly directory entries")]
    List {
        #[arg(
            long,
            default_value_t = 100,
            help = "Maximum rows to show; use 0 for no limit"
        )]
        limit: usize,
        #[arg(long, default_value_t = 0, help = "Number of rows to skip")]
        offset: usize,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Show one friendly directory entry")]
    Show {
        #[arg(help = "Actor ID, alias, or display name")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Update a friendly directory entry")]
    Update {
        #[arg(help = "Actor ID, alias, or display name")]
        reference: String,
        #[arg(help = "Updated display name")]
        display_name: String,
        #[arg(long, help = "Key ID to associate with the actor")]
        key: Option<String>,
        #[arg(long, help = "Stable command alias")]
        alias: Option<String>,
        #[arg(long = "type", help = "Actor type: human, agent, or service")]
        actor_type: Option<String>,
        #[arg(long, help = "Role or responsibility label")]
        role: Option<String>,
        #[arg(long, help = "Source for this directory entry")]
        source: Option<String>,
        #[arg(long, help = "Who verified this directory entry")]
        verified_by: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Remove a friendly directory entry")]
    Delete {
        #[arg(help = "Actor ID, alias, or display name")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Resolve an actor ID, alias, or display name")]
    Resolve {
        #[arg(help = "Actor ID, directory alias, or display name")]
        reference: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Import a directory extension bundle")]
    Import {
        #[arg(help = "Directory extension bundle file")]
        file: PathBuf,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Export a directory extension bundle")]
    Export {
        #[arg(help = "Directory extension bundle file to write")]
        file: PathBuf,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Write directory extension state to a bundle")]
    Push {
        #[arg(help = "Directory extension bundle file to write")]
        file: PathBuf,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Read directory extension state from a bundle")]
    Pull {
        #[arg(help = "Directory extension bundle file to read")]
        file: PathBuf,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
}
#[derive(Subcommand)]
enum PermissionCommand {
    #[command(about = "List grantable permission capabilities")]
    Capabilities {
        #[arg(help = "Actor ID, short ref, directory alias, or display name to inspect")]
        actor: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Grant capabilities to an identity")]
    Grant {
        #[arg(long, help = "The actor or identity receiving permission")]
        identity: String,
        #[arg(
            long = "capability",
            help = "An action this identity may perform; repeat for more actions. Allowed: propose, deliberate, invite, comment, accept, reject, withdraw, archive, admin"
        )]
        capabilities: Vec<String>,
        #[arg(
            long,
            help = "Grant participation capabilities: propose, deliberate, comment, accept, reject"
        )]
        participate: bool,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
    #[command(about = "Revoke a permission grant")]
    Revoke {
        #[arg(help = "The ID of the permission grant to remove")]
        grant: Option<String>,
        #[arg(
            long,
            requires = "participate",
            help = "The actor whose participation permission grants should be revoked"
        )]
        identity: Option<String>,
        #[arg(
            long,
            requires = "identity",
            conflicts_with = "grant",
            help = "Revoke active participation grants for the identity"
        )]
        participate: bool,
        #[arg(long, help = "A short explanation for removing the grant")]
        reason: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
}
#[derive(Subcommand)]
enum RemoteCommand {
    #[command(about = "List configured remotes")]
    List,
    #[command(about = "Save a name and URL for a remote ledger service")]
    Add {
        #[arg(help = "A short name used to refer to this remote")]
        name: String,
        #[arg(help = "The URL of the remote ledger service")]
        url: String,
        #[arg(long, help = "Ledger name, remote name, UUID, or short reference")]
        ledger: Option<String>,
    },
    #[command(about = "Configure a remote from a descriptor")]
    From {
        #[arg(help = "A remote descriptor, or an actor response containing one")]
        file: PathBuf,
        #[arg(help = "A short name used to refer to this remote")]
        name: Option<String>,
    },
    #[command(about = "Forget a configured remote")]
    Remove {
        #[arg(help = "The configured remote name")]
        name: String,
    },
    #[command(about = "Change a configured remote's name")]
    Rename {
        #[arg(help = "The current remote name")]
        old_name: String,
        #[arg(help = "The new remote name")]
        new_name: String,
    },
    #[command(about = "Remember or clear the bearer token used for a remote")]
    Auth {
        #[arg(help = "The configured remote name")]
        name: String,
        #[arg(
            short = 'i',
            long,
            value_name = "FILE",
            conflicts_with_all = ["stdin", "token", "clear"],
            help = "Read the bearer token from FILE, or - for stdin"
        )]
        input: Option<PathBuf>,
        #[arg(
            long,
            conflicts_with_all = ["input", "token", "clear"],
            help = "Read the bearer token from stdin"
        )]
        stdin: bool,
        #[arg(
            long,
            conflicts_with_all = ["input", "stdin", "token"],
            help = "Forget the remote bearer token"
        )]
        clear: bool,
        #[arg(help = "The bearer token to remember")]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum HttpCommand {
    #[command(about = "Serve a local ledger over the Facts HTTP transport")]
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787", help = "Address to bind")]
        bind: String,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
        #[arg(long, help = "Serve every writable local ledger in the catalog")]
        all: bool,
        #[arg(long, help = "Override the public API root URL")]
        api_root: Option<String>,
        #[arg(long, help = "Path to the server token SQLite database")]
        token_store: Option<PathBuf>,
    },
    #[command(about = "Manage HTTP bearer tokens")]
    Token {
        #[command(subcommand)]
        command: HttpTokenCommand,
    },
}

#[derive(Subcommand)]
enum HttpTokenCommand {
    #[command(about = "Issue an opaque bearer token for an existing actor")]
    Issue {
        #[arg(long, help = "Actor ID; defaults to the active ledger actor")]
        actor: Option<String>,
        #[arg(
            long,
            help = "Ledger name, remote name, UUID, or short reference; defaults to the active ledger"
        )]
        ledger: Option<String>,
        #[arg(long, help = "Token expiry in days")]
        expires_days: Option<i64>,
        #[arg(long, help = "Operator label for this token")]
        label: Option<String>,
        #[arg(long, help = "Path to the server token SQLite database")]
        token_store: Option<PathBuf>,
        #[arg(
            short = 'o',
            long,
            value_name = "FILE",
            help = "Write the bearer token to FILE, or - for stdout"
        )]
        output: Option<PathBuf>,
        #[arg(long, help = "Include the bearer token in JSON output")]
        show_token: bool,
    },
    #[command(about = "List issued HTTP bearer token metadata")]
    List {
        #[arg(long, help = "Path to the server token SQLite database")]
        token_store: Option<PathBuf>,
    },
    #[command(about = "Revoke an issued HTTP bearer token by token ID")]
    Revoke {
        #[arg(help = "The token ID to revoke")]
        token_id: String,
        #[arg(long, help = "Path to the server token SQLite database")]
        token_store: Option<PathBuf>,
    },
    #[command(about = "Delete expired or revoked HTTP bearer token metadata")]
    Prune {
        #[arg(long, help = "Path to the server token SQLite database")]
        token_store: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LedgerCommand {
    #[command(about = "Import a bundle as a named read-only ledger")]
    Clone {
        #[arg(help = "A local bundle path or remote URL")]
        source: String,
        #[arg(help = "The friendly name for the local copy")]
        name: String,
        #[arg(
            long,
            help = "The ledger to copy by name, remote name, UUID, or short reference"
        )]
        ledger: String,
    },
    #[command(about = "Delete a local ledger")]
    Delete {
        #[arg(help = "The friendly name of the local ledger")]
        name: String,
        #[arg(
            long,
            help = "Delete even if the ledger is active or has extra safeguards"
        )]
        force: bool,
    },
    #[command(about = "Manage remotes for one local ledger")]
    Remote {
        #[command(subcommand)]
        command: LedgerRemoteCommand,
    },
    #[command(about = "Create an empty local ledger")]
    Create {
        #[arg(help = "The friendly name for the new ledger")]
        name: String,
    },
    #[command(about = "List local ledgers")]
    List,
    #[command(about = "Show details for one local ledger")]
    Show {
        #[arg(help = "The ledger to show by name, remote name, UUID, or short reference")]
        ledger: String,
    },
    #[command(about = "Initialize a ledger database at an exact path")]
    Init {
        #[arg(help = "Where to create the ledger database")]
        path: PathBuf,
        #[arg(long, help = "The namespace or ledger identifier to initialize")]
        namespace: String,
        #[arg(long, help = "A 32-byte signing seed as lowercase hexadecimal")]
        seed: Option<String>,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum DecisionChoice {
    Accept,
    Reject,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ListStatus {
    Pending,
    Accepted,
    Rejected,
    Contested,
    Withdrawn,
    Archived,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum TagMatch {
    Any,
    All,
}
#[derive(Subcommand)]
enum ReconcileCommand {
    #[command(about = "Create a reconciliation proposition for a contested proposition")]
    Create {
        #[arg(help = "The proposition being reconciled")]
        affected: String,
        #[arg(help = "The last undisputed common ancestor revision")]
        common_ancestor: String,
        #[arg(
            long,
            required = true,
            value_name = "REVISION:DELIBERATION:SETTLEMENT",
            help = "A conflicting revision, deliberation, and supporting settlement triple"
        )]
        conflict: Vec<String>,
        #[arg(
            long,
            value_name = "select|derive|reject-all",
            help = "How the conflict is resolved"
        )]
        mode: String,
        #[arg(long, help = "Selected revision for --mode select")]
        selected: Option<String>,
        #[arg(long, help = "Result revision for --mode derive")]
        result: Option<String>,
        #[arg(
            long = "resolved-tip",
            required = true,
            help = "A branch tip or reconciliation tip explicitly resolved by this reconciliation"
        )]
        resolved_tips: Vec<String>,
        #[arg(help = "Optional Markdown file for the reconciliation text")]
        file: Option<PathBuf>,
        #[arg(long, help = "Use this short Markdown text instead of a file")]
        message: Option<String>,
        #[arg(
            long,
            help = "Use a ledger name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
    },
}
#[derive(Subcommand)]
enum ObjectCommand {
    #[command(about = "Check whether a JSON object is canonical and valid")]
    Validate {
        #[arg(help = "The JSON object file to validate")]
        file: PathBuf,
    },
    #[command(about = "Import signed objects from a file")]
    Import {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(help = "The file containing signed objects")]
        file: PathBuf,
    },
    #[command(about = "Export one signed object from a database")]
    Export {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the object, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The object ID to export")]
        id: String,
        #[arg(help = "Where to write the exported object")]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum StateCommand {
    #[command(about = "Rebuild the local state database")]
    Rebuild {
        #[arg(help = "The database or state path to rebuild")]
        path: PathBuf,
    },
}
#[derive(Subcommand)]
enum CommitmentCommand {
    #[command(about = "Create a compact commitment from object hashes")]
    Create {
        #[arg(help = "A file containing one object hash per line")]
        hashes: PathBuf,
    },
    #[command(about = "Check a commitment against its object hashes")]
    Verify {
        #[arg(help = "A file containing one object hash per line")]
        hashes: PathBuf,
        #[arg(help = "The expected commitment root")]
        root: String,
    },
}
#[derive(Subcommand)]
enum ProofCommand {
    #[command(about = "Include an object in a commitment proof")]
    Include {
        #[arg(help = "The file containing the proof hashes")]
        hashes: PathBuf,
        #[arg(help = "The object hash to include")]
        target: String,
    },
    #[command(about = "Exclude an object from a commitment proof")]
    Exclude {
        #[arg(help = "The file containing the proof hashes")]
        hashes: PathBuf,
        #[arg(help = "The object hash to exclude")]
        target: String,
    },
}
#[derive(Subcommand)]
enum QueryCommand {
    #[command(about = "Search a ledger database using a query file")]
    Search {
        #[arg(help = "The local database to search")]
        database: PathBuf,
        #[arg(help = "The ledger to search, by name, remote name, UUID, or short reference")]
        ledger: String,
        #[arg(help = "A file describing the search query")]
        file: PathBuf,
    },
}
#[derive(Subcommand)]
enum SettlementCommand {
    #[command(about = "Verify a settlement object")]
    Verify {
        #[arg(help = "The settlement object file to verify")]
        object: PathBuf,
    },
}
#[derive(Subcommand)]
enum SyncCommand {
    #[command(about = "Push a database into a bundle or remote")]
    Push {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(help = "The bundle file to create")]
        file: PathBuf,
        #[arg(long, help = "The configured remote to send data to")]
        remote: Option<String>,
        #[arg(
            long,
            help = "The ledger to send by name, remote name, UUID, or short reference"
        )]
        ledger: Option<String>,
        #[arg(long, hide = true)]
        bearer_token: Option<String>,
    },
    #[command(about = "Pull a bundle or remote into a database")]
    Pull {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(help = "The ledger to update, by name, remote name, UUID, or short reference")]
        ledger: String,
        #[arg(help = "The bundle file to read or create")]
        output: PathBuf,
        #[arg(long, help = "A file containing hashes already known locally")]
        known_hashes: Option<PathBuf>,
        #[arg(long, help = "Resume after this content-hash cursor")]
        after: Option<String>,
        #[arg(long, help = "Maximum objects to pull")]
        limit: Option<usize>,
        #[arg(long, help = "Maximum total object bytes to pull")]
        max_object_bytes: Option<usize>,
        #[arg(long, help = "The configured remote to fetch data from")]
        remote: Option<String>,
        #[arg(long, hide = true)]
        bearer_token: Option<String>,
    },
    #[command(about = "Retry importing a previously deferred object bundle")]
    Retry {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(help = "The signed object, FACTBNDL, or FACTSNAP file to retry")]
        file: PathBuf,
    },
}
#[derive(Subcommand)]
enum DeliberationCommand {
    #[command(about = "Open a discussion for a proposition revision")]
    Open {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the proposition, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The proposition revision to discuss")]
        revision: String,
        #[arg(help = "The participant actor ID")]
        actor: String,
        #[arg(help = "The participant's signing key ID")]
        key_id: String,
        #[arg(help = "The participant's signing seed")]
        seed: String,
    },
    #[command(about = "Show the messages and decisions in a discussion")]
    Inspect {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the discussion, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The discussion ID to inspect")]
        deliberation: String,
    },
    #[command(about = "Show who joined or left a discussion")]
    Participants {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the discussion, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The discussion ID to inspect")]
        deliberation: String,
    },
}
#[derive(Subcommand)]
enum DecisionCommand {
    #[command(about = "Record a participant's accept or reject decision")]
    Cast {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the discussion, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The discussion ID receiving the decision")]
        deliberation: String,
        #[arg(help = "The participant casting the decision")]
        participant: String,
        #[arg(help = "The participant's signing key ID")]
        key_id: String,
        #[arg(help = "The decision value, such as accept or reject")]
        value: String,
        #[arg(help = "The participant's signing seed")]
        seed: String,
    },
}
#[derive(Subcommand)]
enum PropositionCommand {
    #[command(about = "Create a signed proposition object")]
    Propose {
        #[arg(help = "The local database to update")]
        database: PathBuf,
        #[arg(help = "The ledger to update, by name, remote name, UUID, or short reference")]
        ledger: String,
        #[arg(help = "The author actor ID")]
        actor: String,
        #[arg(help = "The author's signing key ID")]
        key_id: String,
        #[arg(help = "The author's signing seed")]
        seed: String,
        #[arg(help = "The Markdown file containing the proposition")]
        file: PathBuf,
    },
    #[command(about = "List revisions for a proposition")]
    Revisions {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the proposition, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The proposition ID to inspect")]
        proposition: String,
    },
    #[command(about = "Inspect a proposition's signed data and derived state")]
    Inspect {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the proposition, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The proposition ID to inspect")]
        proposition: String,
    },
    #[command(about = "List discussions associated with a proposition")]
    Deliberations {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the proposition, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The proposition ID to inspect")]
        proposition: String,
    },
    #[command(about = "List comments associated with a proposition")]
    Comments {
        #[arg(help = "The local database to read")]
        database: PathBuf,
        #[arg(
            help = "The ledger containing the proposition, by name, remote name, UUID, or short reference"
        )]
        ledger: String,
        #[arg(help = "The proposition ID to inspect")]
        proposition: String,
        #[arg(long, help = "Only show comments associated with this revision")]
        revision: Option<String>,
    },
}
#[derive(Subcommand)]
enum ConformanceCommand {
    #[command(about = "Run the implementation conformance checks")]
    Run {
        #[arg(help = "An optional fixture directory")]
        path: Option<PathBuf>,
    },
    #[command(about = "Create materialized conformance fixtures")]
    Materialize {
        #[arg(help = "Where to write the materialized fixtures")]
        path: PathBuf,
    },
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {}", user_facing_error(error.as_ref()));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let pager_policy = PagerPolicy::from_cli(&cli);
    match cli.command {
        Command::Help { command, all } => {
            print_help(&command, all, pager_policy)?;
        }
        Command::Capabilities { actor, ledger }
        | Command::Permission {
            command: PermissionCommand::Capabilities { actor, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let active = match environment.resolve(ledger.as_deref()) {
                Ok(mut entry) => {
                    if let Some(actor) = actor {
                        let actor_id =
                            fact_sdk::workflow::resolve_directory_actor_reference(&entry, &actor)?;
                        entry.actor_id = actor_id.to_string();
                    }
                    held_capabilities(&entry).ok().map(|held| (entry, held))
                }
                Err(_) => None,
            };
            print_capabilities(cli.json, active.as_ref())?;
        }
        Command::As {
            name,
            alias,
            self_actor,
            actor_type,
            profile,
            role,
            source,
            verified_by,
            home,
            print_env,
            use_home,
            permission,
            participate,
            no_create,
            update_directory,
            ledger,
        } => {
            let value = as_user_identity(fact_as::Input {
                name,
                alias,
                self_actor,
                actor_type,
                profile,
                role,
                source,
                verified_by,
                home,
                print_env,
                use_home,
                permission,
                participate,
                no_create,
                update_directory,
                ledger,
            })?;
            let actor = value
                .get("actor")
                .and_then(|actor| actor.get("display_name"))
                .and_then(|display_name| display_name.as_str())
                .unwrap_or("identity");
            let actor_alias = value
                .get("actor")
                .and_then(|actor| actor.get("alias"))
                .and_then(|alias| alias.as_str());
            let actor_display = actor_alias
                .map(|alias| format!("{actor} ({alias})"))
                .unwrap_or_else(|| actor.to_owned());
            let ledger_name = value
                .get("ledger")
                .and_then(|ledger| ledger.get("name"))
                .and_then(|name| name.as_str())
                .unwrap_or("ledger");
            let ledger = value
                .get("ledger")
                .and_then(|ledger| ledger.get("ledger_id"))
                .and_then(|ledger_id| ledger_id.as_str())
                .and_then(|ledger_id| uuid::Uuid::parse_str(ledger_id).ok())
                .map(|ledger_id| {
                    format!(
                        "{ledger_name} ({})",
                        fact_sdk::reference::short_uuid_reference(ledger_id)
                    )
                })
                .unwrap_or_else(|| ledger_name.to_owned());
            let human = if value.get("report").and_then(|report| report.as_bool()) == Some(true) {
                if value.get("actor").is_some_and(serde_json::Value::is_null) {
                    let suffix = if value
                        .get("ledger")
                        .and_then(|ledger| ledger.get("read_only"))
                        .and_then(|read_only| read_only.as_bool())
                        == Some(true)
                    {
                        " (read-only)"
                    } else {
                        ""
                    };
                    format!("no current signer for ledger {ledger}{suffix}")
                } else {
                    format!("current signer for ledger {ledger}: {actor_display}")
                }
            } else if value
                .get("self")
                .and_then(|self_value| self_value.as_bool())
                == Some(true)
            {
                format!("named current identity as {actor}")
            } else {
                format!("using {actor} for ledger {ledger}")
            };
            print_json_or(cli.json, value, human);
        }
        Command::Init { name, persona } => {
            let environment = UserEnvironment::discover()?;
            let name = name.unwrap_or_else(|| "default".to_owned());
            let (entry, created, persona_used) =
                ensure_user_ledger_with_persona(&environment, &name, persona.as_deref())?;
            let directory_entry_created =
                ensure_initial_admin_directory_entry(&environment, &entry, created)?;
            let active = environment::use_ledger(&environment, &name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"initialized":true,"active":active.name,"ledger_id":entry.ledger_id,"actor_id":entry.actor_id,"persona":persona_used,"directory_entry_created":directory_entry_created}),
                format!("initialized ledger {} ({})", entry.name, entry.ledger_id),
            );
        }
        Command::Here {
            path,
            init,
            persona,
            no_switch,
            force,
            print_env,
        } => {
            let base = match path {
                Some(path) => path,
                None => env::current_dir()?,
            };
            let root = base.join(".facts");
            let (environment, created) = initialize_here_environment(&root, force)?;
            let fact_home_set = env::var_os("FACT_HOME").is_some();
            let ledger = if let Some(name) = init {
                let (entry, created, persona_used) =
                    ensure_user_ledger_with_persona(&environment, &name, persona.as_deref())?;
                let directory_entry_created =
                    ensure_initial_admin_directory_entry(&environment, &entry, created)?;
                let active = if no_switch {
                    false
                } else {
                    environment.set_active(&name)?;
                    true
                };
                Some(serde_json::json!({
                    "created":created,
                    "name":entry.name,
                    "active":active,
                    "ledger_id":entry.ledger_id,
                    "actor_id":entry.actor_id,
                    "persona":persona_used,
                    "directory_entry_created":directory_entry_created
                }))
            } else {
                None
            };
            let absolute = root.canonicalize()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "initialized":true,
                        "path":absolute,
                        "created":created,
                        "fact_home_set":fact_home_set,
                        "discovery":{
                            "uses_here_when_fact_home_unset":true,
                            "fact_home_overrides":true
                        },
                        "ledger":ledger
                    })
                );
            } else if print_env {
                println!("export FACT_HOME={}", absolute.display());
            } else {
                let mut lines = Vec::new();
                if created {
                    lines.push(format!(
                        "initialized Fact environment at {}",
                        root.display()
                    ));
                } else {
                    lines.push(format!(
                        "Fact environment already exists at {}",
                        root.display()
                    ));
                }
                if let Some(ledger) = ledger {
                    lines.push(format!(
                        "initialized ledger {} ({})",
                        ledger["name"].as_str().unwrap_or("default"),
                        ledger["ledger_id"].as_str().unwrap_or("-")
                    ));
                }
                if fact_home_set {
                    lines.push(
                        "FACT_HOME is set; normal commands will keep using FACT_HOME until it is unset"
                            .to_owned(),
                    );
                }
                println!("{}", lines.join("\n"));
            }
        }
        Command::New { name, persona } => {
            let environment = UserEnvironment::discover()?;
            let name = name.unwrap_or_else(|| "default".to_owned());
            let (entry, created, persona_used) =
                ensure_user_ledger_with_persona(&environment, &name, persona.as_deref())?;
            let directory_entry_created =
                ensure_initial_admin_directory_entry(&environment, &entry, created)?;
            let active = environment.active_name()?;
            let message = if created {
                format!("created ledger {} ({})", entry.name, entry.ledger_id)
            } else {
                format!("ledger {} already exists ({})", entry.name, entry.ledger_id)
            };
            print_json_or(
                cli.json,
                serde_json::json!({
                    "created":created,
                    "name":entry.name,
                    "ledger_id":entry.ledger_id,
                    "actor_id":entry.actor_id,
                    "persona":persona_used,
                    "directory_entry_created":directory_entry_created,
                    "active":active,
                    "active_changed":false
                }),
                message,
            );
        }
        Command::Clone {
            source,
            remote,
            descriptor,
            ledger,
            name,
            actor,
        } => {
            let environment = UserEnvironment::discover()?;
            let source = clone_source_from_args(&environment, source, remote, descriptor)?;
            let requested_ledger = ledger
                .as_deref()
                .map(|value| environment.resolve_ledger_id(value))
                .transpose()?
                .or_else(|| source.ledger.clone());
            let ledger_id =
                environment::clone_source_ledger_id(&source.url, requested_ledger.as_deref())?;
            let name = match name {
                Some(name) => name,
                None => environment::clone_source_name(&environment, &source.name_source)?,
            };
            let actor = match actor.as_deref() {
                Some(actor) => Some(clone_actor_binding(&environment, actor)?),
                None => inferred_clone_actor_binding(&environment, &source)?,
            };
            let entry = clone_read_only_ledger(&environment, &name, &source, &ledger_id, actor)?;
            let remote_json = source
                .remote_name
                .as_deref()
                .map(|name| serde_json::Value::String(name.to_owned()))
                .unwrap_or_else(|| {
                    if source.is_remote_url {
                        serde_json::Value::String(source.url.clone())
                    } else {
                        serde_json::Value::Null
                    }
                });
            environment.set_active(&name)?;
            print_json_or(
                cli.json,
                serde_json::json!({
                    "cloned":true,
                    "name":entry.name,
                    "ledger_id":entry.ledger_id,
                    "read_only":entry.read_only,
                    "active":true,
                    "remote":remote_json,
                    "descriptor_contains_credential":source.from_descriptor && source.bearer_token.is_some(),
                    "actor_id":if entry.actor_id.is_empty() {serde_json::Value::Null} else {serde_json::Value::String(entry.actor_id.clone())},
                    "key_id":if entry.key_id.is_empty() {serde_json::Value::Null} else {serde_json::Value::String(entry.key_id.clone())}
                }),
                if source.from_descriptor && source.bearer_token.is_some() {
                    format!(
                        "cloned {} ledger {}; descriptor file still contains a live credential",
                        if entry.read_only {
                            "read-only"
                        } else {
                            "writable"
                        },
                        entry.name
                    )
                } else if entry.read_only {
                    format!("cloned read-only ledger {}", entry.name)
                } else {
                    format!(
                        "cloned writable ledger {} as {}",
                        entry.name, entry.actor_id
                    )
                },
            );
        }
        Command::From {
            database,
            name,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let name = match name {
                Some(name) => name,
                None => environment::clone_source_name(&environment, &database.to_string_lossy())?,
            };
            let requested_ledger = ledger
                .as_deref()
                .map(|value| environment.resolve_ledger_id(value))
                .transpose()?;
            let entry = environment::register_read_only_ledger_database(
                &environment,
                &name,
                &database,
                requested_ledger.as_deref(),
            )?;
            environment.set_active(&name)?;
            print_json_or(
                cli.json,
                serde_json::json!({
                    "registered":true,
                    "name":entry.name,
                    "ledger_id":entry.ledger_id,
                    "database":entry.database,
                    "read_only":true,
                    "active":true
                }),
                format!("registered read-only ledger {}", entry.name),
            );
        }
        Command::Use { name } => {
            let environment = UserEnvironment::discover()?;
            let result = environment::use_ledger(&environment, &name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"active":result.name,"ledger_id":result.ledger_id}),
                format!("using ledger {} ({})", result.name, result.ledger_id),
            );
        }
        Command::Propose {
            file,
            decision,
            message,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let markdown = read_or_edit_markdown(file, message.as_deref())?;
            let outcome = create_user_proposition(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &markdown,
                decision.map(|value| match value {
                    DecisionChoice::Accept => "accepted",
                    DecisionChoice::Reject => "rejected",
                }),
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                format!("proposed {} ({})", outcome.proposition_id, outcome.summary),
            );
        }
        Command::Deliberate { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = if let Some(value) = open_missing_user_deliberation(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
            )? {
                value
            } else {
                user_deliberation(&entry, &reference)?
            };
            print_json_or(
                cli.json,
                value.clone(),
                format!("deliberation {}", value["deliberation_id"]),
            );
        }
        Command::Deliberations { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let values = list_user_deliberations(&entry, &reference)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else if values.is_empty() {
                println!("no deliberations");
            } else {
                for value in values {
                    println!(
                        "{}  revision {}  {}",
                        value["reference"], value["revision_id"], value["status"]
                    );
                }
            }
        }
        Command::ShowDeliberation { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = show_user_deliberation(&entry, &reference)?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("deliberation {}", value["deliberation_id"]),
            );
        }
        Command::Comment {
            reference,
            file,
            message,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let content = read_or_edit_markdown(file, message.as_deref())?;
            let value = create_user_comment(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
                &content,
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("commented on {}", value["deliberation_id"]),
            );
        }
        Command::Comments {
            reference,
            revision,
            mine,
            author,
            mentions_me,
            since,
            unresolved,
            text,
            limit,
            content,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let comments = list_user_comments(CommentReviewInput {
                entry: &entry,
                reference: reference.as_deref(),
                revision: revision.as_deref(),
                mine,
                author: author.as_deref(),
                mentions_me,
                since: since.as_deref(),
                unresolved,
                text: text.as_deref(),
                limit,
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&comments)?);
            } else {
                print_comments_review(&comments, reference.is_some(), content);
            }
        }
        Command::Show {
            reference,
            revisions,
            comments,
            conflicts,
            pending,
            participants,
            history,
            all,
            content,
            no_content: _,
            limit,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let overview = fact_sdk::workflow::show_proposition_overview(
                &entry,
                fact_sdk::workflow::ShowOverviewInput {
                    reference,
                    revision_limit: Some(revisions),
                    comments_limit: Some(comments),
                    history_limit: (limit != 0).then_some(limit),
                    include_conflicts_all: all,
                    include_history: history || all,
                    include_content: content,
                    include_participants: participants,
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&overview)?);
            } else {
                let text = format_show_overview(
                    &overview,
                    ShowHumanOptions {
                        show_empty_conflicts: conflicts,
                        show_empty_pending: pending,
                        show_participants: participants,
                        show_history: history || all,
                        show_content: content,
                    },
                );
                print_or_page(&text, pager_policy, content)?;
            }
        }
        Command::Conflicts {
            reference,
            all,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let conflicts =
                fact_sdk::workflow::list_revision_conflicts(&entry, reference.as_deref(), all)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&conflicts)?);
            } else if conflicts.is_empty() {
                println!("no revision conflicts");
            } else {
                for group in &conflicts {
                    println!("{}  {}  {}", group.reference, group.status, group.summary);
                    if let Some(common_ancestor) = group.common_ancestor_revision_id {
                        println!("  common ancestor: {}", short_uuid(common_ancestor));
                    }
                    for revision in &group.conflicts {
                        let marker = if revision.matched_reference { "*" } else { " " };
                        let mut line = format!(
                            "  {marker} revision {}  {}",
                            short_uuid(revision.revision_id),
                            revision.status
                        );
                        if let Some(deliberation_id) = revision.deliberation_id {
                            line.push_str(&format!(
                                "  deliberation {}",
                                short_uuid(deliberation_id)
                            ));
                        }
                        if let Some(settlement_id) = revision.settlement_id {
                            line.push_str(&format!("  settlement {}", short_uuid(settlement_id)));
                        }
                        println!("{line}");
                    }
                }
            }
        }
        Command::Accept { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let outcome = decide_user_proposition(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                reference.as_deref(),
                "accepted",
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                decision_human_message("Accepted", &outcome),
            );
        }
        Command::Invite {
            reference,
            actor,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = create_user_invitation(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
                &actor,
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("invited {}", value["invited_actor_id"]),
            );
        }
        Command::Invitations { command, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            match command {
                None | Some(InvitationsCommand::List) => {
                    let invitations = list_user_invitations(&entry, InvitationListScope::All)?;
                    print_json_or(
                        cli.json,
                        serde_json::Value::Array(invitations.clone()),
                        format_invitations_list(&invitations),
                    );
                }
                Some(InvitationsCommand::Sent) => {
                    let invitations = list_user_invitations(&entry, InvitationListScope::Sent)?;
                    print_json_or(
                        cli.json,
                        serde_json::Value::Array(invitations.clone()),
                        format_invitations_list(&invitations),
                    );
                }
                Some(InvitationsCommand::Received) => {
                    let invitations = list_user_invitations(&entry, InvitationListScope::Received)?;
                    print_json_or(
                        cli.json,
                        serde_json::Value::Array(invitations.clone()),
                        format_invitations_list(&invitations),
                    );
                }
                Some(InvitationsCommand::Pending) => {
                    let invitations = list_user_invitations(&entry, InvitationListScope::Pending)?;
                    print_json_or(
                        cli.json,
                        serde_json::Value::Array(invitations.clone()),
                        format_invitations_list(&invitations),
                    );
                }
                Some(InvitationsCommand::Show { reference }) => {
                    let invitation = show_user_invitation(&entry, &reference)?;
                    print_json_or(
                        cli.json,
                        invitation.clone(),
                        format_invitation_show(&invitation),
                    );
                }
                Some(InvitationsCommand::Accept { reference }) => {
                    let value = create_user_participant_join_from_invitation(
                        &entry,
                        &read_seed_for_write(&environment, &entry)?,
                        &reference,
                    )?;
                    print_json_or(
                        cli.json,
                        value.clone(),
                        format!("joined deliberation {}", value["deliberation_id"]),
                    );
                }
                Some(InvitationsCommand::Reject { reference, reason }) => {
                    let value = reject_user_invitation(
                        &entry,
                        &read_seed_for_write(&environment, &entry)?,
                        &reference,
                        reason
                            .as_deref()
                            .unwrap_or("rejected from fact invitations"),
                    )?;
                    print_json_or(
                        cli.json,
                        value.clone(),
                        format!(
                            "rejected invitation {}",
                            value["invitation_id"].as_str().unwrap_or("-")
                        ),
                    );
                }
            }
        }
        Command::Join {
            reference,
            invitation,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = if let Some(invitation) = invitation {
                create_user_participant_join(
                    &entry,
                    &read_seed_for_write(&environment, &entry)?,
                    &reference,
                    &invitation,
                )?
            } else {
                create_user_participant_join_from_invitation(
                    &entry,
                    &read_seed_for_write(&environment, &entry)?,
                    &reference,
                )?
            };
            print_json_or(
                cli.json,
                value.clone(),
                format!("joined deliberation {}", value["deliberation_id"]),
            );
        }
        Command::Leave { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = create_user_participant_leave(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("left deliberation {}", value["deliberation_id"]),
            );
        }
        Command::Withdraw {
            reference,
            reason,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = create_user_lifecycle(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
                "withdraw",
                reason
                    .as_deref()
                    .unwrap_or("user requested lifecycle change"),
            )?;
            print_json_or(cli.json, value, format!("withdrew {reference}"));
        }
        Command::Archive {
            reference,
            reason,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = create_user_lifecycle(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
                "archive",
                reason
                    .as_deref()
                    .unwrap_or("user requested lifecycle change"),
            )?;
            print_json_or(cli.json, value, format!("archived {reference}"));
        }
        Command::Reject { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let outcome = decide_user_proposition(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                reference.as_deref(),
                "rejected",
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                decision_human_message("Rejected", &outcome),
            );
        }
        Command::Open {
            reference,
            pending,
            latest,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            open_user_content(&entry, &reference, content_selection(pending, latest))?;
        }
        Command::Echo {
            reference,
            pending,
            latest,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let content =
                resolve_user_content(&entry, &reference, content_selection(pending, latest))?.0;
            std::io::Write::write_all(&mut io::stdout(), &content)?;
        }
        Command::Export {
            reference,
            file,
            force,
            pending,
            latest,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let (content, revision_id) =
                resolve_user_content(&entry, &reference, content_selection(pending, latest))?;
            if file.exists() && !force {
                return Err(
                    format!("refusing to overwrite {}; use --force", file.display()).into(),
                );
            }
            fs::write(&file, &content)?;
            print_json_or(
                cli.json,
                serde_json::json!({"written":true,"file":file,"revision_id":revision_id}),
                format!("wrote revision {revision_id} to {}", file.display()),
            );
        }
        Command::Import {
            file,
            decision,
            message,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let markdown = read_or_edit_markdown(file, message.as_deref())?;
            let outcome = create_user_proposition(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &markdown,
                decision.map(|value| match value {
                    DecisionChoice::Accept => "accepted",
                    DecisionChoice::Reject => "rejected",
                }),
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                format!(
                    "wrote proposition {} ({})",
                    outcome.proposition_id, outcome.summary
                ),
            );
        }
        Command::Revise {
            reference,
            file,
            message,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let initial = Some(resolve_latest_user_content(&entry, &reference)?);
            let markdown =
                read_or_edit_markdown_with_initial(file, message.as_deref(), initial.as_deref())?;
            if initial.as_deref() == Some(markdown.as_slice()) {
                return Err(user_error(
                    "no changes made; the proposition was left unchanged",
                ));
            }
            let outcome = revise_user_proposition(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &reference,
                &markdown,
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                format!(
                    "Revision created: {}\n{}\nNew revision is pending acceptance from {} participant(s).\n\nNext:\n  fact accept {}\n  fact reject {}",
                    short_uuid(outcome.revision_id),
                    if outcome.previous_revision_effective == Some(true) {
                        "Previous revision remains effective."
                    } else {
                        "No revision is currently effective."
                    },
                    outcome.pending_participant_count.unwrap_or(0),
                    short_uuid(outcome.proposition_id),
                    short_uuid(outcome.proposition_id)
                ),
            );
        }
        Command::Status { ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let pending_count = if entry.read_only {
                0
            } else {
                fact_sdk::workflow::pending_proposition_count(&entry)?
            };
            let remotes = environment.load_remotes()?;
            let persona = persona_for_actor(&environment, &entry.actor_id)?;
            let persona_name = persona.as_ref().map(|(name, _)| name.clone());
            let local_private_key_material =
                !entry.read_only && !entry.actor_id.is_empty() && entry.seed_file.is_file();
            let missing_key_warning =
                !entry.read_only && !entry.actor_id.is_empty() && !local_private_key_material;
            let value = serde_json::json!({
                "ledger_name":entry.name,
                "ledger_id":entry.ledger_id,
                "database":entry.database,
                "actor_id":entry.actor_id,
                "key_id":entry.key_id,
                "persona":persona_name,
                "read_only":entry.read_only,
                "local_private_key_material":local_private_key_material,
                "pending_actions":pending_count,
                "remotes":scoped_remotes(remotes.values(), &entry.ledger_id),
                "synchronization":{"state":"local-only","last_push":null,"last_pull":null}
            });
            print_json_or(cli.json, value, {
                let mut output = format!(
                    "{}  {}  {} pending action(s), {} remote(s){}",
                    entry.name,
                    short_uuid_string(&entry.ledger_id),
                    pending_count,
                    scoped_remotes(remotes.values(), &entry.ledger_id).len(),
                    persona_name
                        .map(|name| format!("  persona {name}"))
                        .unwrap_or_default()
                );
                if missing_key_warning {
                    output.push_str(
                            "\nwarning: local private key material is missing; writes will fail until the identity key is restored or rotated",
                        );
                }
                output
            });
        }
        Command::List {
            status,
            ledger,
            limit,
            offset,
            after,
            all,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let items = list_user_propositions(&entry, status, all, limit, offset, after)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("no propositions");
            } else {
                for item in &items {
                    println!(
                        "{}  {}  {}",
                        item.reference,
                        proposition_display_status(item),
                        item.summary
                    );
                }
            }
        }
        Command::Revisions { reference, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let revisions = list_user_revisions(&entry, &reference)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&revisions)?);
            } else if revisions.is_empty() {
                println!("no revisions");
            } else {
                for revision in &revisions {
                    println!(
                        "{}  {}  {}  {}",
                        revision["reference"],
                        revision["status"],
                        revision["created_at"],
                        revision["summary"]
                    );
                }
            }
        }
        Command::Pending { ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let items = pending_for_actor(&entry)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("no pending actions");
            } else {
                for item in &items {
                    let action = if item.pending_deliberation_id.is_some() {
                        "accept or reject"
                    } else {
                        "repair pending review"
                    };
                    println!(
                        "{}  {}  {}  [{}]",
                        item.reference,
                        proposition_display_status(item),
                        item.summary,
                        action
                    );
                }
            }
        }
        Command::Tags {
            reference,
            action,
            tags,
            search,
            list,
            counts,
            match_mode,
            text,
            status,
            all,
            limit,
            offset,
            after,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            if matches!(reference.as_deref(), Some("export" | "import")) {
                if list
                    || counts
                    || !search.is_empty()
                    || !tags.is_empty()
                    || text.is_some()
                    || status.is_some()
                    || all
                    || limit != 100
                    || offset != 0
                    || after.is_some()
                {
                    return Err("tag extension sync omits listing and search options".into());
                }
                let action_name = reference.as_deref().unwrap();
                let file = action.ok_or(format!("fact tags {action_name} requires FILE"))?;
                match action_name {
                    "export" => {
                        let result = fact_sdk::workflow::export_tags(&entry)?;
                        fs::write(&file, &result.bundle)?;
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&result)?);
                        } else {
                            println!("exported {} tag event(s)", result.exported);
                        }
                    }
                    "import" => {
                        let bytes = fs::read(&file)?;
                        let result = fact_sdk::workflow::import_tags(&entry, &bytes)?;
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&result)?);
                        } else {
                            println!(
                                "imported {} tag event(s), skipped {}",
                                result.imported, result.skipped
                            );
                        }
                    }
                    _ => unreachable!(),
                }
            } else if list || (reference.is_none() && action.is_none() && search.is_empty()) {
                if reference.is_some()
                    || action.is_some()
                    || !search.is_empty()
                    || !tags.is_empty()
                    || text.is_some()
                {
                    return Err("tag listing omits REF, ACTION, and --search".into());
                }
                let items = fact_sdk::workflow::list_tags(
                    &entry,
                    fact_sdk::workflow::ListPropositionsFilter {
                        status: status.map(sdk_list_status),
                        all,
                    },
                    fact_sdk::workflow::ListPropositionsPage {
                        offset,
                        limit: (limit != 0).then_some(limit),
                        after,
                    },
                )?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&items)?);
                } else if items.is_empty() {
                    println!("no tags");
                } else if counts {
                    for item in &items {
                        println!("{}  {}", item.tag, item.count);
                    }
                } else {
                    for item in &items {
                        println!("{}", item.tag);
                    }
                }
            } else if !search.is_empty() {
                if reference.is_some() || action.is_some() {
                    return Err("tag search omits REF and ACTION".into());
                }
                if counts {
                    return Err("--counts is only valid with tag listing".into());
                }
                let mut search_tags = search;
                search_tags.extend(tags);
                let results = fact_sdk::workflow::search_tags(
                    &entry,
                    &search_tags,
                    sdk_tag_match(match_mode),
                    fact_sdk::workflow::ListPropositionsFilter {
                        status: status.map(sdk_list_status),
                        all,
                    },
                    fact_sdk::workflow::ListPropositionsPage {
                        offset,
                        limit: (limit != 0).then_some(limit),
                        after,
                    },
                    text.as_deref(),
                )?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else if results.is_empty() {
                    println!("no propositions matched those tags");
                } else {
                    for item in &results {
                        println!(
                            "{}  {}  {}  [{}]",
                            item.reference,
                            item.status,
                            item.summary,
                            item.tags.join(" ")
                        );
                    }
                }
            } else {
                let reference =
                    reference.ok_or("fact tags requires REF unless --search is used")?;
                if counts {
                    return Err("--counts is only valid with tag listing".into());
                }
                if text.is_some() {
                    return Err("--text is only valid with tag search".into());
                }
                let action = action.unwrap_or_else(|| "show".to_owned());
                let operation = parse_tag_operation(&action)?;
                let result = if operation == fact_sdk::workflow::TagOperation::Show {
                    if !tags.is_empty() {
                        return Err("show does not accept tag arguments".into());
                    }
                    fact_sdk::workflow::show_tags(&entry, &reference)?
                } else {
                    if matches!(
                        operation,
                        fact_sdk::workflow::TagOperation::Add
                            | fact_sdk::workflow::TagOperation::Remove
                    ) && tags.is_empty()
                    {
                        return Err(
                            format!("{} requires at least one tag", operation.as_str()).into()
                        );
                    }
                    let seed = read_seed_for_write(&environment, &entry)?;
                    fact_sdk::workflow::mutate_tags(&entry, &seed, &reference, operation, &tags)?
                };
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if operation == fact_sdk::workflow::TagOperation::Show {
                    if result.tags.is_empty() {
                        println!("{}  no tags", result.reference);
                    } else {
                        println!("{}  {}", result.reference, result.tags.join(" "));
                    }
                } else {
                    println!("tagged {}: {}", result.reference, result.tags.join(" "));
                }
            }
        }
        Command::Reconcile {
            command:
                ReconcileCommand::Create {
                    affected,
                    common_ancestor,
                    conflict,
                    mode,
                    selected,
                    result,
                    resolved_tips,
                    file,
                    message,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let outcome = create_user_reconciliation(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                ReconciliationCliInput {
                    affected,
                    common_ancestor,
                    conflicts: conflict,
                    mode,
                    selected,
                    result,
                    resolved_tips,
                    file,
                    message,
                },
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                format!(
                    "created reconciliation {} ({})\nNext:\n  fact accept {}",
                    outcome.proposition_id,
                    outcome.resolution_mode,
                    short_uuid(outcome.proposition_id)
                ),
            );
        }
        Command::Resolve {
            reference,
            file,
            keep,
            message,
            merge,
            pick,
            tool,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let outcome = resolve_user_conflict(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                ResolveCliInput {
                    reference,
                    file,
                    keep,
                    message,
                    merge,
                    pick,
                    tool,
                },
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&outcome)?,
                resolve_human_message(&outcome),
            );
        }
        Command::Search {
            text,
            status,
            effective,
            tag,
            tag_match,
            ledger,
            page_size,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let results = if tag.is_empty() {
                search_user_ledger(&entry, &text, status, effective, page_size)?
            } else {
                fact_sdk::workflow::search_proposition_content_by_tags(
                    &entry,
                    &text,
                    status.map(sdk_list_status),
                    effective,
                    page_size,
                    &tag,
                    sdk_tag_match(tag_match),
                )?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else if results.is_empty() {
                println!("no results");
            } else {
                for result in &results {
                    println!("{}  {}  {}", result.reference, result.score, result.summary);
                }
            }
        }
        Command::Find {
            text,
            tag,
            tag_match,
            with,
            pick,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let results = if tag.is_empty() {
                search_user_ledger(&entry, &text, Some(ListStatus::Accepted), true, 20)?
            } else {
                fact_sdk::workflow::search_proposition_content_by_tags(
                    &entry,
                    &text,
                    Some(fact_sdk::workflow::ListPropositionStatus::Accepted),
                    true,
                    20,
                    &tag,
                    sdk_tag_match(tag_match),
                )?
            };
            let selected = match (results.as_slice(), pick) {
                ([], _) => return Err(format!("no accepted propositions matched {text:?}").into()),
                ([result], None) => Some(result),
                (_, Some(0)) => return Err("--pick starts at 1".into()),
                (results, Some(number)) => results
                    .get(number - 1)
                    .ok_or_else(|| {
                        format!(
                            "--pick {number} is out of range; choose 1-{}",
                            results.len()
                        )
                    })
                    .map(Some)?,
                (results, None) => {
                    println!("multiple accepted propositions matched {text:?}");
                    for (index, result) in results.iter().enumerate() {
                        println!("  {}. {}  {}", index + 1, result.reference, result.summary);
                    }
                    return Err("provide --pick N to select one result".into());
                }
            };
            let result = selected.ok_or("no proposition was selected")?;
            if let Some(command) = with {
                let forwarded_reference = result
                    .proposition_id
                    .unwrap_or(result.object_id)
                    .to_string();
                validate_find_with_command(&command)?;
                let args = [command, forwarded_reference];
                forward_cli_command_passthrough(cli.json, args)?;
            } else if cli.json {
                println!("{}", serde_json::to_string_pretty(result)?);
            } else {
                println!("{}  {}", result.reference, result.summary);
            }
        }
        Command::History {
            ledger,
            reference,
            limit,
            after,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let history_limit = limit.or_else(|| reference.is_none().then_some(100));
            let history = history_user_ledger(
                &entry,
                reference.as_deref(),
                Some(fact_sdk::workflow::HistoryPage {
                    after,
                    limit: history_limit,
                }),
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&history)?);
            } else {
                let mut text = String::new();
                for item in &history {
                    let actor = item
                        .actor_display
                        .clone()
                        .or_else(|| item.actor_id.map(|id| id.to_string()))
                        .unwrap_or_else(|| "-".to_owned());
                    text.push_str(&format!(
                        "{}  {}  {}  {}  {}",
                        item.reference, item.created_at, item.object_type, actor, item.description
                    ));
                    text.push('\n');
                }
                print_or_page(&text, pager_policy, true)?;
            }
        }
        Command::Object {
            command: ObjectCommand::Validate { file },
        } => {
            let bytes = fs::read(file)?;
            let result = fact_sdk::sync::validate_object_bytes(&bytes)?;
            if cli.json {
                println!("{}", serde_json::to_string(&result)?)
            } else {
                println!(
                    "valid {} {} object bytes ({})",
                    if result.signed { "signed" } else { "canonical" },
                    result.object_type,
                    result.canonical_bytes
                )
            }
        }
        Command::Object {
            command: ObjectCommand::Import { database, file },
        } => {
            let store = fact_store::Store::open(database)?;
            let bytes = fs::read(file)?;
            let result = fact_sdk::sync::import_object_bytes(&store, &bytes)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"imported":result.imported}).to_string()
                } else {
                    format!("imported {} object(s)", result.imported)
                }
            );
        }
        Command::Object {
            command:
                ObjectCommand::Export {
                    database,
                    ledger,
                    id,
                    output,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?;
            let id = parse_uuid7(&id, "object")?;
            let store = fact_store::Store::open(database)?;
            let result = fact_sdk::sync::export_object(&store, ledger, id)?;
            fs::write(output, &result.bytes)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"exported":result.exported,"object_id":result.object_id})
                        .to_string()
                } else {
                    format!("exported object {}", result.object_id)
                }
            );
        }
        Command::Identity {
            command: IdentityCommand::New { actor_type, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let runtime = fact_sdk::runtime::production_runtime();
            let seed = runtime.seed()?;
            let store = fact_store::Store::open(&entry.database)?;
            let result = fact_sdk::workflow::create_identity(
                &store,
                fact_sdk::workflow::CreateIdentityInput {
                    namespace: format!("local.identity.{actor_type}"),
                    seed,
                    actor_type,
                },
            )?;
            let seed_file = environment
                .identity_dir
                .join(format!("{}.seed", result.actor_id));
            environment.write_seed(&seed_file, &seed)?;
            print_json_or(
                cli.json,
                serde_json::json!({
                    "created":true,
                    "actor_id":result.actor_id,
                    "actor_ref":fact_sdk::reference::short_uuid_reference(result.actor_id),
                    "key_id":result.key_id,
                    "key_ref":fact_sdk::reference::short_uuid_reference(result.key_id),
                    "private_key_material":"stored locally"
                }),
                format!(
                    "created identity {} with key {}",
                    fact_sdk::reference::short_uuid_reference(result.actor_id),
                    fact_sdk::reference::short_uuid_reference(result.key_id)
                ),
            );
        }
        Command::Identity {
            command:
                IdentityCommand::List {
                    limit,
                    offset,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let store = fact_store::Store::open(&entry.database)?;
            let directory_entries = directory_entries_by_actor(&entry)?;
            let mut items = Vec::new();
            for (id, _, object_type) in store.list_identity_objects()? {
                if object_type != "actor" {
                    continue;
                }
                let local_seed = environment.identity_dir.join(format!("{id}.seed")).exists();
                let key_id = identity_actor_key_id(&store, id)?;
                let directory = directory_entries.get(&id);
                let capabilities = actor_capabilities_in_store(&store, &entry, id)?;
                let persona = persona_for_actor(&environment, &id.to_string())?;
                let admin = capabilities.iter().any(|capability| capability == "admin");
                items.push(serde_json::json!({
                    "actor_id":id,
                    "actor_ref":fact_sdk::reference::short_uuid_reference(id),
                    "key_id":key_id,
                    "key_ref":key_id.map(fact_sdk::reference::short_uuid_reference),
                    "persona":persona.as_ref().map(|(name, _)| name.clone()),
                    "display_name":directory.as_ref().map(|item| item.display_name.clone()),
                    "alias":directory.as_ref().and_then(|item| item.alias.clone()),
                    "capabilities":capabilities,
                    "admin":admin,
                    "local_private_key_material":local_seed,
                    "active":entry.actor_id == id.to_string()
                }));
            }
            let items = items
                .into_iter()
                .skip(offset)
                .take(if limit == 0 { usize::MAX } else { limit })
                .collect::<Vec<_>>();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("no identities");
            } else {
                for item in &items {
                    let name = item["display_name"].as_str().unwrap_or("No name");
                    let key = item["key_ref"].as_str().unwrap_or("-");
                    let alias = item["alias"].as_str().unwrap_or("No alias");
                    let active = if item["active"].as_bool() == Some(true) {
                        "  active"
                    } else {
                        ""
                    };
                    let capabilities = item["capabilities"]
                        .as_array()
                        .map(|capabilities| {
                            capabilities
                                .iter()
                                .filter_map(|capability| capability.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|capabilities| !capabilities.is_empty())
                        .map(|capabilities| format!("  {capabilities}"))
                        .unwrap_or_default();
                    println!(
                        "{}  {}  {}  {}{}{}",
                        item["actor_ref"].as_str().unwrap(),
                        key,
                        name,
                        alias,
                        capabilities,
                        active
                    );
                }
            }
        }
        Command::Identity {
            command: IdentityCommand::Show { actor, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let actor_id = fact_sdk::workflow::resolve_directory_actor_reference(&entry, &actor)?;
            let store = fact_store::Store::open(&entry.database)?;
            let local_seed = environment
                .identity_dir
                .join(format!("{actor_id}.seed"))
                .exists();
            let directory_entries = directory_entries_by_actor(&entry)?;
            let directory = directory_entries.get(&actor_id);
            let capabilities = actor_capabilities_in_store(&store, &entry, actor_id)?;
            let key_id = identity_actor_key_id(&store, actor_id)?;
            let persona = persona_for_actor(&environment, &actor_id.to_string())?;
            let value = serde_json::json!({
                "actor_id":actor_id,
                "actor_ref":fact_sdk::reference::short_uuid_reference(actor_id),
                "key_id":key_id,
                "key_ref":key_id.map(fact_sdk::reference::short_uuid_reference),
                "persona":persona.as_ref().map(|(name, _)| name.clone()),
                "display_name":directory.as_ref().map(|item| item.display_name.clone()),
                "alias":directory.as_ref().and_then(|item| item.alias.clone()),
                "capabilities":capabilities,
                "local_private_key_material":local_seed,
                "active":entry.actor_id == actor_id.to_string(),
                "imported":store.get_cose_by_id_any(actor_id.as_bytes())?.is_some()
            });
            let capabilities = value["capabilities"]
                .as_array()
                .map(|capabilities| {
                    capabilities
                        .iter()
                        .filter_map(|capability| capability.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|capabilities| !capabilities.is_empty())
                .unwrap_or_else(|| "none".to_owned());
            print_json_or(
                cli.json,
                value.clone(),
                format!(
                    "{}  {}\nkey: {}\npersona: {}\ncapabilities: {}",
                    value["actor_ref"].as_str().unwrap_or("-"),
                    value["display_name"].as_str().unwrap_or("unnamed"),
                    value["key_ref"].as_str().unwrap_or("-"),
                    value["persona"].as_str().unwrap_or("-"),
                    capabilities
                ),
            );
        }
        Command::Identity {
            command: IdentityCommand::Use { actor, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let requested_name = entry.name.clone();
            let mut entries = environment.load()?;
            let resolved = fact_sdk::workflow::resolve_directory_reference(&entry, &actor)?;
            let store = fact_store::Store::open(&entry.database)?;
            let key_id = resolved
                .key_id
                .or(identity_actor_key_id(&store, resolved.actor_id)?)
                .ok_or_else(|| {
                    user_error(format!(
                        "actor {} has no signing key association",
                        resolved.actor_id
                    ))
                })?;
            let seed_file = local_identity_seed_file(&environment, resolved.actor_id, key_id)?;
            let updated = LedgerEntry {
                actor_id: resolved.actor_id.to_string(),
                key_id: key_id.to_string(),
                seed_file,
                ..entry
            };
            entries.insert(requested_name.clone(), updated);
            environment.save(&entries)?;
            print_json_or(
                cli.json,
                serde_json::json!({
                    "active":true,
                    "ledger":requested_name,
                    "actor_id":resolved.actor_id,
                    "key_id":key_id,
                    "display_name":resolved.display_name
                }),
                format!(
                    "using {} for ledger {}",
                    resolved.display_name, requested_name
                ),
            );
        }
        Command::Identity {
            command:
                IdentityCommand::Recognize {
                    actor,
                    capabilities,
                    participate,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let capabilities = expanded_capabilities(capabilities, participate)?;
            let value = recognize_user_identity(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &actor,
                &capabilities,
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!(
                    "recognized {} with explicit capabilities",
                    value["actor_id"]
                ),
            );
        }
        Command::Identity {
            command:
                IdentityCommand::Revoke {
                    grant,
                    reason,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = revoke_user_grant(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &grant,
                reason
                    .as_deref()
                    .unwrap_or("authority revoked by ledger administrator"),
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("revoked grant {}", value["revoked_grant_id"]),
            );
        }
        Command::Identity {
            command: IdentityCommand::Rotate { ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let seed = read_seed_for_write(&environment, &entry)?;
            let value = rotate_user_identity(&environment, &entry, &seed)?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("rotated signing key to {}", value["key_id"]),
            );
        }
        Command::Actor { command } => handle_actor_command(cli.json, command)?,
        Command::Profile { command } => handle_profile_command(cli.json, command)?,
        Command::Persona { command } => handle_persona_command(cli.json, command)?,
        Command::Directory {
            command:
                DirectoryCommand::Add {
                    display_name,
                    actor,
                    self_actor,
                    key,
                    alias,
                    actor_type,
                    role,
                    source,
                    verified_by,
                    with_identity,
                    with_token,
                    token_expires_days,
                    token_label,
                    token_store,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let seed = read_seed_for_write(&environment, &entry)?;
            let actor_id = if self_actor {
                Some(uuid::Uuid::parse_str(&entry.actor_id)?)
            } else {
                actor
                    .as_deref()
                    .map(|value| {
                        fact_sdk::workflow::resolve_directory_actor_reference(&entry, value)
                    })
                    .transpose()?
            };
            let key_id = if self_actor && key.is_none() {
                Some(uuid::Uuid::parse_str(&entry.key_id)?)
            } else {
                key.as_deref()
                    .map(|value| fact_sdk::workflow::resolve_directory_key_reference(&entry, value))
                    .transpose()?
            };
            let actor_type = if self_actor && actor_type.is_none() {
                Some("human".to_owned())
            } else {
                actor_type
            };
            let result = fact_sdk::workflow::add_directory_entry(
                &entry,
                &seed,
                fact_sdk::workflow::DirectoryAddInput {
                    display_name,
                    actor_id,
                    key_id,
                    alias,
                    actor_type,
                    role,
                    source,
                    verified_by,
                    with_identity,
                    seed: None,
                },
            )?;
            if let Some(identity_seed) = result.seed {
                let seed_file = environment
                    .identity_dir
                    .join(format!("{}.seed", result.actor_id));
                environment.write_seed(&seed_file, &identity_seed)?;
            }
            let access_token = if with_token {
                Some(issue_http_actor_token(
                    &environment,
                    &entry,
                    result.actor_id,
                    token_expires_days,
                    token_label,
                    token_store,
                )?)
            } else {
                None
            };
            let mut value = serde_json::to_value(&result)?;
            if let Some(access_token) = &access_token {
                value["access_token"] = access_token_json(access_token, false);
            }
            print_json_or(
                cli.json,
                value,
                if let Some(access_token) = access_token {
                    format!(
                        "added {} as {}\nissued token {}\n{}",
                        result.display_name,
                        result.actor_ref,
                        access_token.issued.record.token_id,
                        access_token.issued.token
                    )
                } else {
                    format!("added {} as {}", result.display_name, result.actor_ref)
                },
            );
        }
        Command::Directory {
            command:
                DirectoryCommand::List {
                    limit,
                    offset,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let entries = fact_sdk::workflow::list_directory(&entry)?
                .into_iter()
                .skip(offset)
                .take(if limit == 0 { usize::MAX } else { limit })
                .collect::<Vec<_>>();
            if cli.json {
                let store = fact_store::Store::open(&entry.database)?;
                let entries = entries
                    .into_iter()
                    .map(|item| {
                        let capabilities =
                            actor_capabilities_in_store(&store, &entry, item.actor_id)?;
                        let admin = capabilities.iter().any(|capability| capability == "admin");
                        let mut value = serde_json::to_value(item)?;
                        if let Some(object) = value.as_object_mut() {
                            object
                                .insert("capabilities".to_owned(), serde_json::json!(capabilities));
                            object.insert("admin".to_owned(), serde_json::json!(admin));
                        }
                        Ok::<_, Box<dyn std::error::Error>>(value)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("no directory entries");
            } else {
                let store = fact_store::Store::open(&entry.database)?;
                for item in &entries {
                    let alias = item
                        .alias
                        .as_ref()
                        .map(|alias| format!("  @{alias}"))
                        .unwrap_or_default();
                    let capabilities =
                        actor_capabilities_in_store(&store, &entry, item.actor_id)?.join(", ");
                    let capabilities = if capabilities.is_empty() {
                        String::new()
                    } else {
                        format!("  {capabilities}")
                    };
                    println!(
                        "{}  {}{}{}",
                        item.actor_ref, item.display_name, alias, capabilities
                    );
                }
            }
        }
        Command::Directory {
            command: DirectoryCommand::Show { reference, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let result = fact_sdk::workflow::show_directory_entry(&entry, &reference)?;
            if cli.json {
                println!("{}", serde_json::to_value(&result)?);
            } else {
                print!("{}", format_directory_entry_show(&result));
            }
        }
        Command::Directory {
            command:
                DirectoryCommand::Update {
                    reference,
                    display_name,
                    key,
                    alias,
                    actor_type,
                    role,
                    source,
                    verified_by,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let seed = read_seed_for_write(&environment, &entry)?;
            let existing = fact_sdk::workflow::show_directory_entry(&entry, &reference)?;
            let key_id = key
                .as_deref()
                .map(|value| fact_sdk::workflow::resolve_directory_key_reference(&entry, value))
                .transpose()?
                .or(existing.key_id);
            let result = fact_sdk::workflow::add_directory_entry(
                &entry,
                &seed,
                fact_sdk::workflow::DirectoryAddInput {
                    display_name,
                    actor_id: Some(existing.actor_id),
                    key_id,
                    alias,
                    actor_type,
                    role,
                    source,
                    verified_by,
                    with_identity: false,
                    seed: None,
                },
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&result)?,
                format!("updated {} as {}", result.display_name, result.actor_ref),
            );
        }
        Command::Directory {
            command: DirectoryCommand::Delete { reference, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let result = fact_sdk::workflow::remove_directory_entry(
                &entry,
                fact_sdk::workflow::DirectoryRemoveInput { reference },
            )?;
            print_json_or(
                cli.json,
                serde_json::to_value(&result)?,
                format!("removed {}", result.actor_ref),
            );
        }
        Command::Directory {
            command: DirectoryCommand::Resolve { reference, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let result = fact_sdk::workflow::resolve_directory_reference(&entry, &reference)?;
            print_json_or(
                cli.json,
                serde_json::to_value(&result)?,
                format!("{}  {}", result.actor_ref, result.display_name),
            );
        }
        Command::Directory {
            command:
                DirectoryCommand::Import { file, ledger } | DirectoryCommand::Pull { file, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let bytes = fs::read(file)?;
            let result = fact_sdk::workflow::import_directory(&entry, &bytes)?;
            print_json_or(
                cli.json,
                serde_json::to_value(&result)?,
                format!(
                    "imported {} directory event(s), skipped {}",
                    result.imported, result.skipped
                ),
            );
        }
        Command::Directory {
            command:
                DirectoryCommand::Push { file, ledger } | DirectoryCommand::Export { file, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let result = fact_sdk::workflow::export_directory(&entry)?;
            fs::write(&file, &result.bundle)?;
            print_json_or(
                cli.json,
                serde_json::json!({"exported":result.exported,"bundle_bytes":result.bundle_bytes,"file":file}),
                format!("exported {} directory event(s)", result.exported),
            );
        }
        Command::Permission {
            command:
                PermissionCommand::Grant {
                    identity,
                    capabilities,
                    participate,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let capabilities = expanded_capabilities(capabilities, participate)?;
            let value = recognize_user_identity(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &identity,
                &capabilities,
            )?;
            print_json_or(
                cli.json,
                value.clone(),
                format!("granted {} to {}", value["capabilities"], value["actor_id"]),
            );
        }
        Command::Permission {
            command:
                PermissionCommand::Revoke {
                    grant,
                    identity,
                    participate,
                    reason,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let seed = read_seed_for_write(&environment, &entry)?;
            let reason = reason
                .as_deref()
                .unwrap_or("authority revoked by ledger administrator");
            if participate {
                let identity = identity
                    .as_deref()
                    .ok_or_else(|| user_error("--participate revoke requires --identity"))?;
                let value = revoke_participation_user_grants(&entry, &seed, identity, reason)?;
                print_json_or(
                    cli.json,
                    value.clone(),
                    format!(
                        "revoked {} participation grant(s) for {}",
                        value["revoked_count"], value["actor_id"]
                    ),
                );
            } else {
                let grant = grant
                    .as_deref()
                    .ok_or_else(|| user_error("permission revoke requires a grant reference"))?;
                let value = revoke_user_grant(&entry, &seed, grant, reason)?;
                print_json_or(
                    cli.json,
                    value.clone(),
                    format!("revoked grant {}", value["revoked_grant_id"]),
                );
            }
        }
        Command::Remote {
            command: RemoteCommand::List,
        } => {
            let environment = UserEnvironment::discover()?;
            let remotes = environment::list_remotes(&environment)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&remotes)?);
            } else {
                for remote in &remotes {
                    print_remote(remote);
                }
            }
        }
        Command::Remote {
            command: RemoteCommand::Add { name, url, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let ledger = remote_add_ledger(&environment, &url, ledger.as_deref())?;
            let result = add_remote_with_ledger(&environment, &name, &url, ledger)?;
            print_json_or(
                cli.json,
                serde_json::json!({"added":true,"name":result.name,"url":result.url,"ledger":result.ledger,"scope":result.scope}),
                format!("added remote {name} {url}"),
            );
        }
        Command::Remote {
            command: RemoteCommand::From { file, name },
        } => {
            let environment = UserEnvironment::discover()?;
            let result = configure_remote_from_descriptor(&environment, &file, name.as_deref())?;
            let contains_credential = result.bearer_token.is_some();
            print_json_or(
                cli.json,
                serde_json::json!({
                    "configured":true,
                    "name":result.name,
                    "url":result.url,
                    "ledger":result.ledger,
                    "genesis_hash":result.genesis_hash,
                    "contains_credential":contains_credential,
                    "scope":"local-environment"
                }),
                if contains_credential {
                    format!(
                        "configured remote {}; descriptor file still contains a live credential",
                        result.name
                    )
                } else {
                    format!("configured remote {}", result.name)
                },
            );
        }
        Command::Remote {
            command: RemoteCommand::Remove { name },
        } => {
            let environment = UserEnvironment::discover()?;
            let result = environment::remove_remote(&environment, &name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"removed":true,"name":result.name,"scope":result.scope}),
                format!("removed remote {name}"),
            );
        }
        Command::Remote {
            command: RemoteCommand::Rename { old_name, new_name },
        } => {
            let environment = UserEnvironment::discover()?;
            let result = environment::rename_remote(&environment, &old_name, &new_name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"renamed":true,"old_name":result.old_name,"new_name":result.new_name,"scope":result.scope}),
                format!("renamed remote {old_name} to {new_name}"),
            );
        }
        Command::Remote {
            command:
                RemoteCommand::Auth {
                    name,
                    input,
                    stdin,
                    clear,
                    token,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let bearer_token = if clear {
                None
            } else if let Some(input) = input {
                Some(read_bearer_token_input(&input)?)
            } else if stdin {
                let mut value = String::new();
                io::stdin().read_to_string(&mut value)?;
                Some(value.trim().to_owned())
            } else {
                Some(token.ok_or_else(|| {
                    user_error("remote auth requires TOKEN, --input, --stdin, or --clear")
                })?)
            };
            let result = environment::set_remote_bearer_token(&environment, &name, bearer_token)?;
            print_json_or(
                cli.json,
                serde_json::json!({"authenticated":!clear,"name":result.name,"scope":result.scope}),
                if clear {
                    format!("cleared auth for remote {name}")
                } else {
                    format!("stored auth for remote {name}")
                },
            );
        }
        Command::Http {
            command:
                HttpCommand::Serve {
                    bind,
                    ledger,
                    all,
                    api_root,
                    token_store,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let token_store_path = token_store_path(&environment, token_store);
            let bearer_tokens =
                Arc::new(fact_http::SqliteBearerTokenStore::open(&token_store_path)?);
            let address = bind.parse::<std::net::SocketAddr>()?;
            let api_root = api_root.unwrap_or_else(|| format!("http://{address}/facts"));
            let served_ledgers = if all {
                if ledger.is_some() {
                    return Err(user_error(
                        "fact http serve accepts either --ledger or --all, not both",
                    ));
                }
                environment
                    .load()?
                    .into_values()
                    .filter(|entry| !entry.read_only)
                    .collect::<Vec<_>>()
            } else {
                vec![environment.resolve(ledger.as_deref())?]
            };
            if served_ledgers.is_empty() {
                return Err(user_error("no writable ledgers to serve"));
            }
            let hosted_ledgers = served_ledgers
                .iter()
                .map(|entry| {
                    let store = fact_store::Store::open(&entry.database)?;
                    let seed = read_seed_for_write(&environment, entry)?;
                    let coordinator_key = fact_crypto::SigningKey::from_seed(&seed)?;
                    let ledger_id = entry.ledger_id.parse::<fact_core::ObjectId>()?;
                    let coordinator_actor_id = entry.actor_id.parse::<fact_core::ObjectId>()?;
                    Ok(fact_http::HostedLedger {
                        ledger_id,
                        store,
                        coordinator_key,
                        coordinator_actor_id,
                    })
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
            let state = fact_http::AppState::new_with_reference_policy_for_ledgers(
                api_root.clone(),
                hosted_ledgers,
            )
            .map_err(user_error)?
            .with_bearer_token_store(bearer_tokens);
            if !cli.json {
                if all {
                    eprintln!("serving {} ledgers at {api_root}", served_ledgers.len());
                    for entry in &served_ledgers {
                        eprintln!("serving ledger {}", entry.ledger_id);
                    }
                } else {
                    eprintln!(
                        "serving ledger {} at {api_root}",
                        served_ledgers[0].ledger_id
                    );
                }
                eprintln!("token store {}", token_store_path.display());
            }
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(address).await?;
                fact_http::serve_reference(listener, state).await
            })?;
        }
        Command::Http {
            command: HttpCommand::Token { command },
        } => {
            handle_http_token_command(cli.json, command)?;
        }
        Command::Ledger {
            command:
                LedgerCommand::Clone {
                    source,
                    name,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let source = CloneSource {
                is_remote_url: environment::is_remote_url(&source),
                name_source: source.clone(),
                url: source.clone(),
                remote_name: None,
                ledger: None,
                genesis_hash: None,
                bearer_token: None,
                actor: None,
                claims: None,
                from_descriptor: false,
            };
            let ledger = environment.resolve_ledger_id(&ledger)?;
            let entry = clone_read_only_ledger(&environment, &name, &source, &ledger, None)?;
            environment.set_active(&name)?;
            print_json_or(
                cli.json,
                serde_json::json!({
                    "cloned":true,
                    "name":entry.name,
                    "ledger_id":entry.ledger_id,
                    "read_only":true,
                    "remote":if source.is_remote_url {serde_json::Value::String(source.url)} else {serde_json::Value::Null}
                }),
                format!("cloned read-only ledger {}", entry.name),
            );
        }
        Command::Ledger {
            command: LedgerCommand::Delete { name, force },
        } => {
            let environment = UserEnvironment::discover()?;
            let persona_seed = environment
                .load()
                .ok()
                .and_then(|entries| entries.get(&name).cloned())
                .and_then(|entry| {
                    persona_for_actor(&environment, &entry.actor_id)
                        .ok()
                        .flatten()
                        .map(|(_, _)| entry.seed_file)
                })
                .and_then(|seed_file| fs::read(&seed_file).ok().map(|bytes| (seed_file, bytes)));
            let result = environment::delete_ledger(&environment, &name, force)?;
            if let Some((seed_file, bytes)) = persona_seed {
                if !seed_file.exists() {
                    if let Some(parent) = seed_file.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    write_sensitive_file(&seed_file, &bytes)?;
                }
            }
            print_json_or(
                cli.json,
                serde_json::to_value(&result)?,
                format!("deleted ledger {name}"),
            );
        }
        Command::Ledger {
            command:
                LedgerCommand::Remote {
                    command: LedgerRemoteCommand::List,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let remotes = environment::list_remotes(&environment)?;
            let entry = ensure_active_entry(&environment, None)?;
            let remotes = scoped_remotes(&remotes, &entry.ledger_id);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&remotes)?);
            } else {
                for remote in remotes {
                    print_remote(remote);
                }
            }
        }
        Command::Push {
            database,
            file,
            remote,
            ledger,
        } => match (database, file) {
            (Some(database), Some(file)) => {
                let mut args = vec!["sync", "push"];
                let database = database.to_string_lossy().into_owned();
                let file = file.to_string_lossy().into_owned();
                args.extend([database.as_str(), file.as_str()]);
                let remote_value;
                let ledger_value;
                if let Some(value) = remote {
                    args.push("--remote");
                    remote_value = value;
                    args.push(remote_value.as_str());
                }
                if let Some(value) = ledger {
                    args.push("--ledger");
                    ledger_value = value;
                    args.push(ledger_value.as_str());
                }
                forward_cli_command(cli.json, args)?;
            }
            (None, None) => {
                let environment = UserEnvironment::discover()?;
                let entry = ensure_active_entry(&environment, ledger.as_deref())?;
                let remote = configured_remote_for_ledger(&environment, remote.as_deref(), &entry)?;
                personal_push(&entry, &remote, cli.json)?;
            }
            _ => return Err("fact push requires both DATABASE and FILE, or neither".into()),
        },
        Command::Pull {
            database,
            ledger,
            output,
            known_hashes,
            after,
            limit,
            max_object_bytes,
            remote,
        } => {
            let personal_ledger = ledger.clone();
            match (database, ledger, output) {
                (Some(database), Some(ledger), Some(output)) => {
                    let mut args = vec!["sync", "pull"];
                    let database = database.to_string_lossy().into_owned();
                    let output = output.to_string_lossy().into_owned();
                    args.extend([database.as_str(), ledger.as_str(), output.as_str()]);
                    let known_value;
                    let remote_value;
                    if let Some(value) = known_hashes {
                        args.push("--known-hashes");
                        known_value = value.to_string_lossy().into_owned();
                        args.push(known_value.as_str());
                    }
                    let after_value;
                    if let Some(value) = after {
                        args.push("--after");
                        after_value = value;
                        args.push(after_value.as_str());
                    }
                    let limit_value;
                    if let Some(value) = limit {
                        args.push("--limit");
                        limit_value = value.to_string();
                        args.push(limit_value.as_str());
                    }
                    let max_object_bytes_value;
                    if let Some(value) = max_object_bytes {
                        args.push("--max-object-bytes");
                        max_object_bytes_value = value.to_string();
                        args.push(max_object_bytes_value.as_str());
                    }
                    if let Some(value) = remote {
                        args.push("--remote");
                        remote_value = value;
                        args.push(remote_value.as_str());
                    }
                    forward_cli_command(cli.json, args)?;
                }
                (None, None, None)
                    if known_hashes.is_none()
                        && after.is_none()
                        && limit.is_none()
                        && max_object_bytes.is_none() =>
                {
                    let environment = UserEnvironment::discover()?;
                    if personal_ledger.is_none() && environment.active_name()?.is_none() {
                        return Err(
                            "no local ledger is active; use `fact clone --remote NAME --ledger LEDGER` first"
                                .into(),
                        );
                    }
                    let entry = ensure_active_entry(&environment, personal_ledger.as_deref())?;
                    let remote =
                        configured_remote_for_ledger(&environment, remote.as_deref(), &entry)?;
                    personal_pull(&entry, &remote, cli.json)?;
                }
                _ => return Err("fact pull requires DATABASE, LEDGER, and OUTPUT, or none".into()),
            }
        }
        Command::Identity {
            command: IdentityCommand::Import { file, ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let bytes = fs::read(file)?;
            let import = read_identity_import_bundle(&bytes)?;
            let mut result = fact_sdk::workflow::import_identity(&entry, &import.identity_bundle)?;
            let directory_result = import
                .directory_bundle
                .as_deref()
                .map(|bundle| fact_sdk::workflow::import_directory(&entry, bundle))
                .transpose()?;
            for actor in &mut result.actors {
                if actor.display_name.is_none() {
                    if let Ok(directory) = fact_sdk::workflow::resolve_directory_reference(
                        &entry,
                        &actor.actor_id.to_string(),
                    ) {
                        actor.display_name = Some(directory.display_name);
                    }
                }
            }
            print_json_or(
                cli.json,
                identity_import_result_value(&result, directory_result.as_ref())?,
                format_identity_import_result(&result, directory_result.as_ref()),
            );
        }
        Command::Identity {
            command:
                IdentityCommand::Export {
                    file,
                    actor,
                    ledger,
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let actor_id = actor
                .as_deref()
                .map(|actor| fact_sdk::workflow::resolve_directory_actor_reference(&entry, actor))
                .transpose()?;
            let file = match file {
                Some(file) => file,
                None => default_identity_export_file(&entry, actor_id)?,
            };
            let result = if let Some(actor_id) = actor_id {
                let scoped_entry = identity_export_entry_for_actor(&environment, &entry, actor_id)?;
                fact_sdk::workflow::export_identity_for_actor(&scoped_entry, actor_id)?
            } else {
                fact_sdk::workflow::export_identity(&entry)?
            };
            let actors = identity_bundle_actor_values(&result.bundle)?;
            let actor_ids = actors
                .iter()
                .filter_map(|actor| actor["actor_id"].as_str())
                .filter_map(|actor| uuid::Uuid::parse_str(actor).ok())
                .collect::<Vec<_>>();
            let bundle = identity_export_bundle_with_directory(&entry, &result.bundle, &actor_ids)?;
            fs::write(&file, &bundle)?;
            let actor_text = actors
                .iter()
                .map(|actor| actor["actor_ref"].as_str().unwrap_or(""))
                .collect::<Vec<_>>()
                .join(", ");
            print_json_or(
                cli.json,
                serde_json::json!({"exported":result.exported,"objects":result.objects,"actors":actors,"private_key_material":result.private_key_material,"file":file}),
                format!(
                    "exported {} identity object(s) for {} to {}",
                    result.objects,
                    actor_text,
                    file.display()
                ),
            );
        }
        Command::Ledger {
            command:
                LedgerCommand::Remote {
                    command: LedgerRemoteCommand::Add { name, url },
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, None)?;
            let result =
                add_remote_with_ledger(&environment, &name, &url, Some(entry.ledger_id.clone()))?;
            print_json_or(
                cli.json,
                serde_json::json!({"added":true,"name":result.name,"url":result.url,"ledger":result.ledger}),
                format!("added remote {name} {url}"),
            );
        }
        Command::Ledger {
            command:
                LedgerCommand::Remote {
                    command: LedgerRemoteCommand::Remove { name },
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let result = environment::remove_remote(&environment, &name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"removed":true,"name":result.name}),
                format!("removed remote {name}"),
            );
        }
        Command::Ledger {
            command:
                LedgerCommand::Remote {
                    command: LedgerRemoteCommand::Rename { old_name, new_name },
                },
        } => {
            let environment = UserEnvironment::discover()?;
            let result = environment::rename_remote(&environment, &old_name, &new_name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"renamed":true,"old_name":result.old_name,"new_name":result.new_name}),
                format!("renamed remote {old_name} to {new_name}"),
            );
        }
        Command::Ledger {
            command: LedgerCommand::Create { name },
        } => {
            let environment = UserEnvironment::discover()?;
            let (entry, _) = environment::ensure_user_ledger(&environment, &name)?;
            print_json_or(
                cli.json,
                serde_json::json!({"created":true,"name":name,"ledger_id":entry.ledger_id}),
                format!("created ledger {} ({})", entry.name, entry.ledger_id),
            );
        }
        Command::Ledger {
            command: LedgerCommand::List,
        } => {
            let environment = UserEnvironment::discover()?;
            let entries = environment::list_ledgers(&environment)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in &entries {
                    println!(
                        "{}{}  {}  {} remote(s)",
                        if entry.active { "* " } else { "  " },
                        entry.name,
                        short_uuid_string(&entry.ledger_id),
                        entry.remote_count
                    );
                }
            }
        }
        Command::Ledger {
            command: LedgerCommand::Show { ledger },
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = environment.resolve(Some(&ledger))?;
            let value = ledger_show_value(&environment, &entry)?;
            print_ledger_show(cli.json, &value)?;
        }
        Command::Ledger {
            command:
                LedgerCommand::Init {
                    path,
                    namespace,
                    seed,
                },
        } => {
            let signing_seed = seed
                .map(|seed| {
                    let bytes = hex::decode(seed).map_err(|error| error.to_string())?;
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| String::from("--seed must decode to exactly 32 bytes"))
                })
                .transpose()?;
            let bootstrap = environment::init_ledger_database(&path, &namespace, signing_seed)?;
            println!(
                "{}",
                if cli.json {
                    format!(
                        "{{\"initialized\":true,\"ledger_id\":\"{}\",\"genesis_id\":\"{}\",\"actor_id\":\"{}\",\"key_id\":\"{}\",\"namespace\":\"{}\"}}",
                        bootstrap.ledger_id, bootstrap.genesis_id, bootstrap.actor_id, bootstrap.key_id, namespace
                    )
                } else {
                    format!(
                        "ledger initialized: {} ({}) actor {} key {} genesis {}",
                        bootstrap.ledger_id,
                        namespace,
                        bootstrap.actor_id,
                        bootstrap.key_id,
                        bootstrap.genesis_id
                    )
                }
            );
        }
        Command::State {
            command: StateCommand::Rebuild { path },
        } => {
            let result = fact_sdk::workflow::rebuild_state_at(path)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else {
                    format!(
                        "state rebuilt ({} deliberation projecteds, {} effective propositions)",
                        result.deliberations, result.effective_propositions
                    )
                }
            )
        }
        Command::Commitment {
            command: CommitmentCommand::Create { hashes },
        } => {
            let result = fact_sdk::workflow::create_commitment(read_hashes(&hashes)?)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else {
                    result.root
                }
            )
        }
        Command::Commitment {
            command: CommitmentCommand::Verify { hashes, root },
        } => {
            let expected: fact_core::Hash = root.parse()?;
            let result = fact_sdk::workflow::verify_commitment(read_hashes(&hashes)?, expected)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else if result.valid {
                    "valid commitment".to_string()
                } else {
                    format!(
                        "invalid commitment: expected {}, got {}",
                        expected, result.root
                    )
                }
            );
            if !result.valid {
                return Err("commitment root mismatch".into());
            }
        }
        Command::Proof {
            command: ProofCommand::Include { hashes, target },
        } => {
            let target: fact_core::Hash = target.parse()?;
            let value = fact_sdk::workflow::create_inclusion_proof(read_hashes(&hashes)?, target)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&value)?
                } else {
                    format!(
                        "inclusion proof for {target} at index {}, root {}",
                        value.index, value.root
                    )
                }
            );
        }
        Command::Proof {
            command: ProofCommand::Exclude { hashes, target },
        } => {
            let target: fact_core::Hash = target.parse()?;
            let value =
                fact_sdk::workflow::create_non_inclusion_proof(read_hashes(&hashes)?, target)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&value)?
                } else {
                    format!("non-inclusion proof for {target}, root {}", value.root)
                }
            );
        }
        Command::Query {
            command:
                QueryCommand::Search {
                    database,
                    ledger,
                    file,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?;
            let input = fs::read(file)?;
            let store = fact_store::Store::open(database)?;
            let output = fact_sdk::workflow::query_search(&store, ledger, &input)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&output)?
                } else {
                    format!(
                        "{} result(s), commitment {}",
                        output.results.len(),
                        output.input_commitment_hash
                    )
                }
            );
        }
        Command::Settlement {
            command: SettlementCommand::Verify { object },
        } => {
            let bytes = fs::read(object)?;
            let result = fact_sdk::workflow::verify_settlement_object(&bytes)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else {
                    format!("valid settlement {}", result.content_hash)
                }
            );
        }
        Command::Sync {
            command:
                SyncCommand::Push {
                    database,
                    file,
                    remote,
                    ledger,
                    bearer_token,
                },
        } => {
            let bytes = fs::read(file)?;
            if !bytes.starts_with(b"FACTBNDL") && !bytes.starts_with(b"FACTSNAP") {
                return Err("sync push requires a FACTBNDL or FACTSNAP file".into());
            }
            if let Some(remote) = remote {
                let ledger = resolve_ledger_uuid(
                    ledger
                        .as_deref()
                        .ok_or("--ledger is required with --remote")?,
                )?;
                validate_remote_serves_ledger(&remote, ledger)?;
                let endpoint = format!(
                    "{}/facts/ledgers/{}/object-pushes",
                    remote.trim_end_matches('/'),
                    ledger
                );
                let request = reqwest::blocking::Client::new()
                    .post(endpoint)
                    .header("content-type", "application/fact-bundle")
                    .header("facts-protocol-version", "0")
                    .header("facts-ledger", ledger.to_string())
                    .header(
                        "content-digest",
                        fact_sdk::sync::content_digest_header(&bytes),
                    )
                    .body(bytes);
                let response = with_bearer_token(request, bearer_token.as_deref()).send()?;
                let status = response.status();
                let body = response.bytes()?.to_vec();
                if !status.is_success() {
                    return Err(format!(
                        "remote push failed ({status}): {}",
                        String::from_utf8_lossy(&body)
                    )
                    .into());
                }
                println!(
                    "{}",
                    if cli.json {
                        serde_json::json!({"remote":true,"status":status.as_u16(),"response":serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::json!({}))}).to_string()
                    } else {
                        format!("remote push succeeded ({status})")
                    }
                );
                return Ok(());
            }
            let store = fact_store::Store::open(database)?;
            let result = fact_sdk::sync::push_bundle_to_store(&store, &bytes)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"pushed":result.imported,"content_hashes":result.content_hashes}).to_string()
                } else {
                    format!("pushed {} object(s)", result.imported)
                }
            );
        }
        Command::Sync {
            command:
                SyncCommand::Pull {
                    database,
                    ledger,
                    output,
                    known_hashes,
                    after,
                    limit,
                    max_object_bytes,
                    remote,
                    bearer_token,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?;
            let explicit_known = known_hashes.map(|path| read_hashes(&path)).transpose()?;
            if let Some(remote) = remote {
                validate_remote_serves_ledger(&remote, ledger)?;
                let known = match explicit_known {
                    Some(hashes) => hashes.into_iter().collect::<std::collections::HashSet<_>>(),
                    None if database.exists() => {
                        let store = fact_store::Store::open(&database)?;
                        let mut known = store
                            .list_object_hashes(ledger.as_bytes())?
                            .into_iter()
                            .collect::<std::collections::HashSet<_>>();
                        known.extend(
                            store
                                .list_identity_objects()?
                                .into_iter()
                                .map(|(_, hash, _)| hash),
                        );
                        known
                    }
                    None => std::collections::HashSet::new(),
                };
                if limit.is_some() || max_object_bytes.is_some() {
                    return Err(
                        "--limit and --max-object-bytes are only supported for local pull".into(),
                    );
                }
                let endpoint = format!(
                    "{}/facts/ledgers/{}/object-pulls",
                    remote.trim_end_matches('/'),
                    ledger
                );
                let mut objects = Vec::new();
                let mut cursor = after;
                let status = loop {
                    let body =
                        fact_sdk::sync::encode_pull_request(ledger, &known, cursor.as_deref())?;
                    let request = reqwest::blocking::Client::new()
                        .post(&endpoint)
                        .header("content-type", "application/fact+json")
                        .header("facts-protocol-version", "0")
                        .header("facts-ledger", ledger.to_string())
                        .header(
                            "content-digest",
                            fact_sdk::sync::content_digest_header(&body),
                        )
                        .body(body);
                    let response = with_bearer_token(request, bearer_token.as_deref()).send()?;
                    let status = response.status();
                    let response_body = response.bytes()?.to_vec();
                    if !status.is_success() {
                        return Err(format!(
                            "remote pull failed ({status}): {}",
                            String::from_utf8_lossy(&response_body)
                        )
                        .into());
                    }
                    let response_value: serde_json::Value = serde_json::from_slice(&response_body)?;
                    for (hash, cose) in
                        fact_sdk::sync::decode_remote_response_objects(&response_value, "pull")?
                    {
                        if !objects.iter().any(|(known_hash, _)| *known_hash == hash) {
                            objects.push((hash, cose));
                        }
                    }
                    let next = response_value
                        .get("body")
                        .and_then(|body| body.get("next_cursor"));
                    match next.and_then(serde_json::Value::as_str) {
                        Some(next) => cursor = Some(next.to_owned()),
                        None => break status,
                    }
                };
                fetch_remote_dependencies(
                    remote.trim_end_matches('/'),
                    ledger,
                    &mut objects,
                    &known,
                    bearer_token.as_deref(),
                )?;
                let bundle = fact_sdk::sync::encode_bundle(ledger, &objects)?;
                fs::write(output, &bundle)?;
                println!(
                    "{}",
                    if cli.json {
                        serde_json::json!({"remote":true,"status":status.as_u16(),"objects":objects.len(),"bundle_bytes":bundle.len()}).to_string()
                    } else {
                        format!("remote pull succeeded ({status})")
                    }
                );
                return Ok(());
            }
            let known = explicit_known
                .unwrap_or_default()
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            let store = fact_store::Store::open(database)?;
            let mut output_file = fs::File::create(output)?;
            let result = fact_sdk::sync::write_pull_bundle_from_store_with_options(
                &store,
                ledger,
                &known,
                fact_sdk::sync::PullBundleOptions {
                    after,
                    max_objects: limit,
                    max_object_bytes,
                },
                &mut output_file,
            )?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"pulled":result.pulled,"bundle_bytes":result.bundle_bytes,"complete":result.complete,"next_cursor":result.next_cursor})
                        .to_string()
                } else {
                    match result.next_cursor {
                        Some(cursor) => {
                            format!("pulled {} object(s); next cursor {cursor}", result.pulled)
                        }
                        None => format!("pulled {} object(s)", result.pulled),
                    }
                }
            );
        }
        Command::Sync {
            command: SyncCommand::Retry { database, file },
        } => {
            let bytes = fs::read(file)?;
            let store = fact_store::Store::open(database)?;
            let result = match fact_sdk::sync::import_object_bytes(&store, &bytes) {
                Ok(result) => result,
                Err(fact_sdk::Error::Store(fact_store::Error::Duplicate)) => {
                    fact_sdk::sync::ImportObjectsResult {
                        imported: 0,
                        content_hashes: Vec::new(),
                    }
                }
                Err(error) => return Err(error.into()),
            };
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"retried":result.imported,"content_hashes":result.content_hashes}).to_string()
                } else {
                    format!("retried {} object(s)", result.imported)
                }
            );
        }
        Command::Deliberation {
            command:
                DeliberationCommand::Open {
                    database,
                    ledger,
                    revision,
                    actor,
                    key_id,
                    seed,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let revision = parse_uuid7(&revision, "revision")?;
            let seed = hex::decode(seed)?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| "identity seed must be 32 bytes")?;
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: actor,
                key_id,
                seed_file: PathBuf::new(),
                read_only: false,
            };
            let result =
                fact_sdk::workflow::open_deliberation_for_revision(&entry, &seed, revision)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else {
                    format!(
                        "opened deliberation {} ({})",
                        result.object_id, result.content_hash
                    )
                }
            );
        }
        Command::Deliberation {
            command:
                DeliberationCommand::Inspect {
                    database,
                    ledger,
                    deliberation,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?;
            let deliberation = parse_uuid7(&deliberation, "deliberation")?;
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger.to_string(),
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let value = fact_sdk::workflow::show_deliberation_by_id(&entry, ledger, deliberation)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string_pretty(&value)?
                } else {
                    format!(
                        "deliberation {}  proposition {}  revision {}",
                        deliberation,
                        value["deliberation"]["body"]["proposition_id"]
                            .as_str()
                            .unwrap_or("-"),
                        value["deliberation"]["body"]["revision_id"]
                            .as_str()
                            .unwrap_or("-")
                    )
                }
            );
        }
        Command::Deliberation {
            command:
                DeliberationCommand::Participants {
                    database,
                    ledger,
                    deliberation,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?;
            let deliberation = parse_uuid7(&deliberation, "deliberation")?;
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger.to_string(),
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let changes = fact_sdk::workflow::participant_changes(&entry, deliberation)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string_pretty(&changes)?
                } else if changes.is_empty() {
                    "no participant changes".to_owned()
                } else {
                    changes
                        .iter()
                        .map(|change| {
                            format!(
                                "{}  {}  {}",
                                change["body"]["participant_actor_id"],
                                change["body"]["operation"],
                                change["created_at"]
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            );
        }
        Command::Decision {
            command:
                DecisionCommand::Cast {
                    database,
                    ledger,
                    deliberation,
                    participant,
                    key_id,
                    value,
                    seed,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            if value != "accepted" && value != "rejected" {
                return Err("decision value must be accepted or rejected".into());
            }
            let seed = hex::decode(seed)?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| "identity seed must be 32 bytes")?;
            let result = fact_sdk::workflow::create_decision(
                &LedgerEntry {
                    name: "technical".to_owned(),
                    ledger_id: ledger,
                    database,
                    actor_id: participant.clone(),
                    key_id,
                    seed_file: PathBuf::new(),
                    read_only: false,
                },
                &seed,
                fact_sdk::workflow::DecisionInput {
                    deliberation_id: parse_uuid7(&deliberation, "deliberation")?,
                    participant_actor_id: parse_uuid7(&participant, "participant")?,
                    value: if value == "accepted" {
                        fact_sdk::workflow::CastDecisionValue::Accepted
                    } else {
                        fact_sdk::workflow::CastDecisionValue::Rejected
                    },
                    supersedes_decision_ids: Vec::new(),
                    authorization_ref: None,
                },
            )?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"created":true,"object_type":result.object_type,"object_id":result.object_id,"content_hash":result.content_hash}).to_string()
                } else {
                    format!(
                        "cast decision {} ({})",
                        result.object_id, result.content_hash
                    )
                }
            );
        }
        Command::Proposition {
            command:
                PropositionCommand::Propose {
                    database,
                    ledger,
                    actor,
                    key_id,
                    seed,
                    file,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let markdown = fs::read(&file)?;
            fact_canonical::validate_canonical_markdown(&markdown)?;
            let seed = hex::decode(seed)?;
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| "identity seed must be 32 bytes")?;
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: actor,
                key_id,
                seed_file: PathBuf::new(),
                read_only: false,
            };
            let outcome = fact_sdk::workflow::create_proposition(&entry, &seed, &markdown, None)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::json!({"created":true,"proposition_id":outcome.proposition_id,"revision_id":outcome.revision_id,"deliberation_id":outcome.deliberation_id,"content_hashes":outcome.content_hashes}).to_string()
                } else {
                    format!(
                        "proposed {} with revision {} and deliberation {}",
                        outcome.proposition_id, outcome.revision_id, outcome.deliberation_id
                    )
                }
            );
        }
        Command::Proposition {
            command:
                PropositionCommand::Revisions {
                    database,
                    ledger,
                    proposition,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let revisions = fact_sdk::proposition::list_revisions(&entry, &proposition)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string_pretty(&revisions)?
                } else {
                    revisions
                        .iter()
                        .map(|value| {
                            format!(
                                "{}  {}",
                                value["object_id"].as_str().unwrap_or("-"),
                                value["summary"].as_str().unwrap_or("-")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            );
        }
        Command::Proposition {
            command:
                PropositionCommand::Inspect {
                    database,
                    ledger,
                    proposition,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let output = fact_sdk::proposition::inspect_proposition(&entry, &proposition)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                let state = output["effective_state"].clone();
                let revision_state = &output["revision_state"];
                let deliberation_count = output["deliberations"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or(0);
                println!(
                    "proposition {}  status {}  effective revision {}  latest revision {}  deliberations {}",
                    proposition,
                    state
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("pending"),
                    state
                        .get("revision_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| "-".to_owned()),
                    revision_state
                        .get("latest_revision")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| "-".to_owned()),
                    deliberation_count
                );
                if revision_state["has_pending_revision"].as_bool() == Some(true) {
                    println!(
                        "revision status: {}",
                        revision_state["latest_revision_status"]
                    );
                    if let Some(revision) = revision_state["pending_revision"].as_str() {
                        println!("pending revision: {revision}");
                    }
                    if let Some(deliberation) = revision_state["pending_deliberation"].as_str() {
                        println!("pending deliberation: {deliberation}");
                    }
                }
            }
        }
        Command::Proposition {
            command:
                PropositionCommand::Deliberations {
                    database,
                    ledger,
                    proposition,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let deliberations = fact_sdk::proposition::list_deliberations(&entry, &proposition)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string_pretty(&deliberations)?
                } else {
                    deliberations
                        .iter()
                        .map(|value| {
                            format!(
                                "{}  revision {}",
                                value["object_id"].as_str().unwrap_or("-"),
                                value["body"]["revision_id"].as_str().unwrap_or("-")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            );
        }
        Command::Proposition {
            command:
                PropositionCommand::Comments {
                    database,
                    ledger,
                    proposition,
                    revision,
                },
        } => {
            let ledger = resolve_ledger_uuid(&ledger)?.to_string();
            let revision = revision
                .as_deref()
                .map(|value| parse_uuid7(value, "revision"))
                .transpose()?;
            let entry = LedgerEntry {
                name: "technical".to_owned(),
                ledger_id: ledger,
                database,
                actor_id: String::new(),
                key_id: String::new(),
                seed_file: PathBuf::new(),
                read_only: true,
            };
            let comments = fact_sdk::proposition::list_comments(&entry, &proposition, revision)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string_pretty(&comments)?
                } else if comments.is_empty() {
                    "no comments".to_owned()
                } else {
                    comments
                        .iter()
                        .map(|value| {
                            format!(
                                "{}  {}  {}",
                                value["object_id"].as_str().unwrap_or("-"),
                                value["actor_id"].as_str().unwrap_or("-"),
                                value["summary"].as_str().unwrap_or("-")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            );
        }
        Command::Conformance {
            command: ConformanceCommand::Run { path },
        } => {
            let mut report = fact_sdk::workflow::run_conformance(path.as_deref());
            report.implementation_version = env!("CARGO_PKG_VERSION").to_owned();
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&report)?
                } else {
                    format!(
                        "conformance vectors: {} passed, {} failed ({:?})",
                        report.passed, report.failed, path
                    )
                }
            )
        }
        Command::Conformance {
            command: ConformanceCommand::Materialize { path },
        } => {
            let result = fact_sdk::workflow::materialize_conformance(&path)?;
            println!(
                "{}",
                if cli.json {
                    serde_json::to_string(&result)?
                } else {
                    format!(
                        "materialized conformance fixtures in {}",
                        result.path.display()
                    )
                }
            )
        }
    }
    Ok(())
}

type PropositionResult = fact_sdk::workflow::PropositionResult;
type PropositionListItem = fact_sdk::workflow::PropositionListItem;
type ReconciliationResult = fact_sdk::workflow::ReconciliationResult;

type SearchResult = fact_sdk::workflow::SearchResult;
type HistoryItem = fact_sdk::workflow::HistoryItem;

struct ReconciliationCliInput {
    affected: String,
    common_ancestor: String,
    conflicts: Vec<String>,
    mode: String,
    selected: Option<String>,
    result: Option<String>,
    resolved_tips: Vec<String>,
    file: Option<PathBuf>,
    message: Option<String>,
}

struct ResolveCliInput {
    reference: Option<String>,
    file: Option<PathBuf>,
    keep: Option<String>,
    message: Option<String>,
    merge: bool,
    pick: Vec<String>,
    tool: Option<String>,
}

fn initialize_here_environment(
    root: &Path,
    force: bool,
) -> Result<(UserEnvironment, bool), Box<dyn std::error::Error>> {
    let existed = root.exists();
    if existed && !root.is_dir() {
        return Err(user_error(format!(
            "{} exists but is not a directory",
            root.display()
        )));
    }
    if existed {
        validate_here_environment(root, force)?;
    }
    fs::create_dir_all(root)?;
    let environment = UserEnvironment::from_root(root);
    if force || !environment.catalog.exists() {
        environment.save(&Default::default())?;
    } else {
        environment.load()?;
    }
    if force || !environment.remote_file.exists() {
        environment.save_remotes(&Default::default())?;
    } else {
        environment.load_remotes()?;
    }
    environment.ensure_dirs()?;
    Ok((environment, !existed))
}

fn validate_here_environment(root: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let allowed = [
        OsStr::new("active"),
        OsStr::new("catalog.toml"),
        OsStr::new("identities"),
        OsStr::new("ledgers"),
        OsStr::new("personas.toml"),
        OsStr::new("profiles.toml"),
        OsStr::new("remotes.toml"),
    ];
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !allowed.contains(&entry.file_name().as_os_str()) && !force {
            return Err(user_error(format!(
                "{} is not a Fact environment file; rerun with --force to accept it",
                entry.path().display()
            )));
        }
    }
    let catalog = root.join("catalog.toml");
    if catalog.exists() && !catalog.is_file() && !force {
        return Err(user_error(format!(
            "{} exists but is not a file",
            catalog.display()
        )));
    }
    let remotes = root.join("remotes.toml");
    if remotes.exists() && !remotes.is_file() && !force {
        return Err(user_error(format!(
            "{} exists but is not a file",
            remotes.display()
        )));
    }
    let profiles = root.join("profiles.toml");
    if profiles.exists() && !profiles.is_file() && !force {
        return Err(user_error(format!(
            "{} exists but is not a file",
            profiles.display()
        )));
    }
    let personas = root.join("personas.toml");
    if personas.exists() && !personas.is_file() && !force {
        return Err(user_error(format!(
            "{} exists but is not a file",
            personas.display()
        )));
    }
    let active = root.join("active");
    if active.exists() && !active.is_file() && !force {
        return Err(user_error(format!(
            "{} exists but is not a file",
            active.display()
        )));
    }
    for directory in [root.join("identities"), root.join("ledgers")] {
        if directory.exists() && !directory.is_dir() && !force {
            return Err(user_error(format!(
                "{} exists but is not a directory",
                directory.display()
            )));
        }
    }
    if !force {
        let environment = UserEnvironment::from_root(root);
        environment.load()?;
        environment.load_remotes()?;
    }
    Ok(())
}

fn print_json_or(json: bool, value: serde_json::Value, human: String) {
    if json {
        println!("{value}");
    } else {
        println!("{human}");
    }
}

fn read_bearer_token_input(input: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut value = String::new();
    if input == Path::new("-") {
        io::stdin().read_to_string(&mut value)?;
    } else {
        value = fs::read_to_string(input)?;
    }
    Ok(value.trim().to_owned())
}

fn write_file_with_mode(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_file_mode(path, mode)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn write_bearer_token_file(output: &Path, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    write_file_with_mode(output, token.as_bytes(), 0o600)
}

fn write_sensitive_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    write_file_with_mode(path, bytes, 0o600)
}

fn token_store_path(environment: &UserEnvironment, override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| {
        environment
            .remote_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("remotes")
            .join("tokens.sqlite")
    })
}

fn handle_http_token_command(
    json: bool,
    command: HttpTokenCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let environment = UserEnvironment::discover()?;
    match command {
        HttpTokenCommand::Issue {
            actor,
            ledger,
            expires_days,
            label,
            token_store,
            output,
            show_token,
        } => {
            let entry = environment.resolve(ledger.as_deref())?;
            let actor_id = match actor {
                Some(actor) => {
                    fact_sdk::workflow::resolve_directory_actor_reference(&entry, &actor)?
                }
                None => uuid::Uuid::parse_str(&entry.actor_id)?,
            };
            let issued = issue_http_actor_token(
                &environment,
                &entry,
                actor_id,
                expires_days,
                label,
                token_store,
            )?;
            if let Some(output) = output.as_deref().filter(|path| *path != Path::new("-")) {
                write_bearer_token_file(output, &issued.issued.token)?;
            }
            let token_to_stdout = output.as_deref() == Some(Path::new("-"));
            let mut value = access_token_json(&issued, show_token || token_to_stdout);
            if let Some(output) = &output {
                value["credential_output"] = serde_json::json!(if output == Path::new("-") {
                    "stdout".to_owned()
                } else {
                    output.display().to_string()
                });
            }
            print_json_or(
                json,
                value,
                issued_http_token_human_output(&issued, output.as_deref()),
            );
        }
        HttpTokenCommand::List { token_store } => {
            let path = token_store_path(&environment, token_store);
            let store = fact_http::SqliteBearerTokenStore::open(&path)?;
            let records = store.list_tokens()?;
            let value = serde_json::json!({
                "token_store":path,
                "tokens":records.iter().map(token_record_json).collect::<Vec<_>>()
            });
            if json {
                println!("{value}");
            } else if records.is_empty() {
                println!("no tokens");
            } else {
                for record in records {
                    println!(
                        "{}  actor {}  ledger {}{}{}",
                        record.token_id,
                        record.actor_id,
                        record
                            .ledger_id
                            .map(|ledger| ledger.to_string())
                            .unwrap_or_else(|| "-".into()),
                        record
                            .expires_at
                            .map(|value| format!("  expires {}", format_http_time(value)))
                            .unwrap_or_default(),
                        if record.revoked_at.is_some() {
                            "  revoked"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        HttpTokenCommand::Revoke {
            token_id,
            token_store,
        } => {
            let path = token_store_path(&environment, token_store);
            let store = fact_http::SqliteBearerTokenStore::open(&path)?;
            let revoked = store.revoke_token_id(&token_id, time::OffsetDateTime::now_utc())?;
            print_json_or(
                json,
                serde_json::json!({"revoked":revoked,"token_id":token_id,"token_store":path}),
                if revoked {
                    format!("revoked token {token_id}")
                } else {
                    format!("token not found or already revoked: {token_id}")
                },
            );
        }
        HttpTokenCommand::Prune { token_store } => {
            let path = token_store_path(&environment, token_store);
            let store = fact_http::SqliteBearerTokenStore::open(&path)?;
            let pruned = store.prune_expired_or_revoked(time::OffsetDateTime::now_utc())?;
            print_json_or(
                json,
                serde_json::json!({"pruned":pruned,"token_store":path}),
                format!("pruned {pruned} token(s)"),
            );
        }
    }
    Ok(())
}

struct IssuedHttpActorToken {
    issued: fact_http::IssuedBearerToken,
    token_store: PathBuf,
}

fn issue_http_actor_token(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    actor_id: uuid::Uuid,
    expires_days: Option<i64>,
    label: Option<String>,
    token_store: Option<PathBuf>,
) -> Result<IssuedHttpActorToken, Box<dyn std::error::Error>> {
    let ledger_id = entry.ledger_id.parse::<fact_core::ObjectId>()?;
    let actor_id = actor_id.to_string().parse::<fact_core::ObjectId>()?;
    let expires_at = http_token_expires_at(expires_days)?;
    let path = token_store_path(environment, token_store);
    let store = fact_http::SqliteBearerTokenStore::open(&path)?;
    let issued = store.issue_token(actor_id, Some(ledger_id), expires_at, label)?;
    Ok(IssuedHttpActorToken {
        issued,
        token_store: path,
    })
}

fn http_token_expires_at(
    expires_days: Option<i64>,
) -> Result<Option<time::OffsetDateTime>, Box<dyn std::error::Error>> {
    expires_days
        .map(|days| {
            if days <= 0 {
                return Err(user_error("--expires-days must be greater than zero"));
            }
            Ok(time::OffsetDateTime::now_utc() + time::Duration::days(days))
        })
        .transpose()
}

fn access_token_json(token: &IssuedHttpActorToken, include_secret: bool) -> serde_json::Value {
    let issued = &token.issued;
    let mut value = serde_json::json!({
        "token_id":issued.record.token_id,
        "actor_id":issued.record.actor_id.to_string(),
        "ledger_id":issued.record.ledger_id.map(|ledger| ledger.to_string()),
        "expires_at":issued.record.expires_at.map(format_http_time),
        "label":issued.record.label.clone(),
        "token_store":token.token_store.clone()
    });
    if include_secret {
        value["token"] = serde_json::json!(issued.token);
    }
    value
}

fn issued_http_token_human_output(token: &IssuedHttpActorToken, output: Option<&Path>) -> String {
    let issued = &token.issued;
    let mut lines = vec![
        format!("issued token {}", issued.record.token_id),
        format!("actor {}", issued.record.actor_id),
        format!(
            "ledger {}",
            issued
                .record
                .ledger_id
                .map(|ledger| ledger.to_string())
                .unwrap_or_else(|| "-".to_owned())
        ),
    ];
    if let Some(label) = &issued.record.label {
        lines.push(format!("label {label}"));
    }
    match output {
        Some(path) if path != Path::new("-") => {
            lines.push(format!("wrote credential {}", path.display()));
        }
        _ => {
            lines.push(issued.token.clone());
            lines.push("shown only once; store it now".to_owned());
        }
    }
    lines.join("\n")
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct ActorRegistry {
    actors: std::collections::BTreeMap<String, ActorRegistryEntry>,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct ProfileFile {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    profiles: std::collections::BTreeMap<String, ActorProfile>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct ActorProfile {
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    actor_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct PersonaFile {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    personas: std::collections::BTreeMap<String, PersonaEntry>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct PersonaEntry {
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    actor_type: String,
    ledger_id: String,
    actor_id: String,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_bundle: Option<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct ActorRegistryEntry {
    name: String,
    alias: Option<String>,
    actor_type: String,
    ledger_id: String,
    actor_id: String,
    key_id: String,
}

#[derive(Clone)]
struct ActorRequestIdentity {
    name: String,
    alias: Option<String>,
    actor_type: String,
    ledger_id: String,
    database: PathBuf,
    actor_id: String,
    key_id: String,
    seed_file: PathBuf,
}

#[derive(Clone)]
struct ActorBundleIdentity {
    actor_id: uuid::Uuid,
    key_id: uuid::Uuid,
    fingerprint: String,
}

struct ActorRequestReview {
    request: actor_exchange::ActorRequest,
    bundle: Vec<u8>,
    identity: ActorBundleIdentity,
    filename_mismatch: Option<String>,
}

fn profile_path(environment: &UserEnvironment) -> PathBuf {
    environment.root().join("profiles.toml")
}

fn load_profiles(environment: &UserEnvironment) -> Result<ProfileFile, Box<dyn std::error::Error>> {
    match fs::read_to_string(profile_path(environment)) {
        Ok(text) => Ok(toml::from_str(&text)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ProfileFile::default()),
        Err(error) => Err(error.into()),
    }
}

fn save_profiles(
    environment: &UserEnvironment,
    profiles: &ProfileFile,
) -> Result<(), Box<dyn std::error::Error>> {
    environment.ensure_dirs()?;
    fs::write(profile_path(environment), toml::to_string_pretty(profiles)?)?;
    Ok(())
}

fn named_profile(
    environment: &UserEnvironment,
    name: &str,
) -> Result<ActorProfile, Box<dyn std::error::Error>> {
    let profiles = load_profiles(environment)?;
    profiles
        .profiles
        .get(name)
        .cloned()
        .ok_or_else(|| user_error(format!("unknown profile: {name}")))
}

fn default_profile(
    environment: &UserEnvironment,
) -> Result<Option<(String, ActorProfile)>, Box<dyn std::error::Error>> {
    let profiles = load_profiles(environment)?;
    let Some(name) = profiles.default else {
        return Ok(None);
    };
    let profile = profiles
        .profiles
        .get(&name)
        .cloned()
        .ok_or_else(|| user_error(format!("default profile is missing: {name}")))?;
    Ok(Some((name, profile)))
}

fn profile_json(name: &str, profile: &ActorProfile, default: bool) -> serde_json::Value {
    serde_json::json!({
        "profile":name,
        "display_name":profile.display_name,
        "alias":profile.alias,
        "actor_type":profile.actor_type,
        "role":profile.role,
        "default":default
    })
}

fn handle_profile_command(
    json: bool,
    command: ProfileCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let environment = UserEnvironment::discover()?;
    match command {
        ProfileCommand::Add {
            profile,
            name,
            alias,
            actor_type,
            role,
            default,
        } => {
            validate_profile_name(&profile)?;
            let mut profiles = load_profiles(&environment)?;
            if profiles.profiles.contains_key(&profile) {
                return Err(user_error(format!("profile already exists: {profile}")));
            }
            let value = ActorProfile {
                display_name: name,
                alias,
                actor_type,
                role,
            };
            profiles.profiles.insert(profile.clone(), value.clone());
            if default || profiles.default.is_none() {
                profiles.default = Some(profile.clone());
            }
            save_profiles(&environment, &profiles)?;
            let is_default = profiles.default.as_deref() == Some(profile.as_str());
            print_json_or(
                json,
                profile_json(&profile, &value, is_default),
                format!("added profile {profile}"),
            );
        }
        ProfileCommand::List => {
            let profiles = load_profiles(&environment)?;
            let items = profiles
                .profiles
                .iter()
                .map(|(name, profile)| {
                    profile_json(
                        name,
                        profile,
                        profiles.default.as_deref() == Some(name.as_str()),
                    )
                })
                .collect::<Vec<_>>();
            if json {
                println!("{}", serde_json::json!(items));
            } else if items.is_empty() {
                println!("no profiles");
            } else {
                for item in items {
                    println!(
                        "{}  {}{}{}",
                        item["profile"].as_str().unwrap(),
                        item["display_name"].as_str().unwrap(),
                        item["alias"]
                            .as_str()
                            .map(|alias| format!("  @{alias}"))
                            .unwrap_or_default(),
                        if item["default"].as_bool() == Some(true) {
                            "  default"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        ProfileCommand::Show { profile } => {
            let profiles = load_profiles(&environment)?;
            let value = profiles
                .profiles
                .get(&profile)
                .ok_or_else(|| user_error(format!("unknown profile: {profile}")))?;
            let is_default = profiles.default.as_deref() == Some(profile.as_str());
            print_json_or(
                json,
                profile_json(&profile, value, is_default),
                format!(
                    "{}  {}{}{}",
                    profile,
                    value.display_name,
                    value
                        .alias
                        .as_ref()
                        .map(|alias| format!("  @{alias}"))
                        .unwrap_or_default(),
                    if is_default { "  default" } else { "" }
                ),
            );
        }
        ProfileCommand::Update {
            profile,
            name,
            alias,
            clear_alias,
            actor_type,
            role,
            clear_role,
        } => {
            let mut profiles = load_profiles(&environment)?;
            let value = profiles
                .profiles
                .get_mut(&profile)
                .ok_or_else(|| user_error(format!("unknown profile: {profile}")))?;
            if let Some(name) = name {
                value.display_name = name;
            }
            if clear_alias {
                value.alias = None;
            } else if alias.is_some() {
                value.alias = alias;
            }
            if let Some(actor_type) = actor_type {
                value.actor_type = actor_type;
            }
            if clear_role {
                value.role = None;
            } else if role.is_some() {
                value.role = role;
            }
            let output = value.clone();
            save_profiles(&environment, &profiles)?;
            print_json_or(
                json,
                profile_json(
                    &profile,
                    &output,
                    profiles.default.as_deref() == Some(profile.as_str()),
                ),
                format!("updated profile {profile}"),
            );
        }
        ProfileCommand::Delete { profile } => {
            let mut profiles = load_profiles(&environment)?;
            if profiles.profiles.remove(&profile).is_none() {
                return Err(user_error(format!("unknown profile: {profile}")));
            }
            if profiles.default.as_deref() == Some(profile.as_str()) {
                profiles.default = None;
            }
            save_profiles(&environment, &profiles)?;
            print_json_or(
                json,
                serde_json::json!({"deleted":true,"profile":profile}),
                format!("deleted profile {profile}"),
            );
        }
        ProfileCommand::Default { profile } => {
            let mut profiles = load_profiles(&environment)?;
            if !profiles.profiles.contains_key(&profile) {
                return Err(user_error(format!("unknown profile: {profile}")));
            }
            profiles.default = Some(profile.clone());
            save_profiles(&environment, &profiles)?;
            print_json_or(
                json,
                serde_json::json!({"profile":profile,"default":true}),
                format!("default profile {profile}"),
            );
        }
        ProfileCommand::Apply { profile, ledger } => {
            let profiles = load_profiles(&environment)?;
            let profile_name = match profile.or(profiles.default.clone()) {
                Some(profile) => profile,
                None => return Err(user_error("no profile named and no default profile is set")),
            };
            let value = profiles
                .profiles
                .get(&profile_name)
                .cloned()
                .ok_or_else(|| user_error(format!("unknown profile: {profile_name}")))?;
            let ledgers = if ledger.is_empty() {
                vec![selected_active_ledger_name(&environment)?]
            } else {
                ledger
            };
            let mut applied = Vec::new();
            for ledger in ledgers {
                let entry = ensure_active_entry(&environment, Some(&ledger))?;
                let directory =
                    apply_profile_to_entry(&environment, &entry, &profile_name, &value)?;
                applied.push(serde_json::json!({
                    "ledger":entry.name,
                    "ledger_id":entry.ledger_id,
                    "actor_id":directory.actor_id,
                    "actor_ref":fact_sdk::reference::short_uuid_reference(directory.actor_id),
                    "profile":profile_name
                }));
            }
            print_json_or(
                json,
                serde_json::json!({"applied":applied}),
                format!("applied profile {profile_name}"),
            );
        }
    }
    Ok(())
}

fn selected_active_ledger_name(
    environment: &UserEnvironment,
) -> Result<String, Box<dyn std::error::Error>> {
    environment
        .active_name()?
        .ok_or_else(|| user_error("no active ledger; run `fact init`"))
}

fn validate_profile_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if fact_sdk::environment::valid_name(name) {
        Ok(())
    } else {
        Err(user_error(format!("invalid profile name: {name}")))
    }
}

fn apply_profile_to_entry(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    profile_name: &str,
    profile: &ActorProfile,
) -> Result<fact_sdk::workflow::DirectoryAddResult, Box<dyn std::error::Error>> {
    let seed = read_seed_for_write(environment, entry)?;
    let actor_id = uuid::Uuid::parse_str(&entry.actor_id)?;
    let key_id = uuid::Uuid::parse_str(&entry.key_id)?;
    let result = fact_sdk::workflow::add_directory_entry(
        entry,
        &seed,
        fact_sdk::workflow::DirectoryAddInput {
            display_name: profile.display_name.clone(),
            actor_id: Some(actor_id),
            key_id: Some(key_id),
            alias: profile.alias.clone(),
            actor_type: Some(profile.actor_type.clone()),
            role: profile.role.clone(),
            source: Some(format!("profile:{profile_name}")),
            verified_by: None,
            with_identity: false,
            seed: None,
        },
    )?;
    Ok(result)
}

fn persona_path(environment: &UserEnvironment) -> PathBuf {
    environment.root().join("personas.toml")
}

fn persona_database(environment: &UserEnvironment) -> PathBuf {
    environment.identity_dir.join("personas.sqlite")
}

fn load_personas(environment: &UserEnvironment) -> Result<PersonaFile, Box<dyn std::error::Error>> {
    match fs::read_to_string(persona_path(environment)) {
        Ok(text) => Ok(toml::from_str(&text)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PersonaFile::default()),
        Err(error) => Err(error.into()),
    }
}

fn save_personas(
    environment: &UserEnvironment,
    personas: &PersonaFile,
) -> Result<(), Box<dyn std::error::Error>> {
    environment.ensure_dirs()?;
    fs::write(persona_path(environment), toml::to_string_pretty(personas)?)?;
    Ok(())
}

fn resolve_persona(
    environment: &UserEnvironment,
    reference: &str,
) -> Result<(String, PersonaEntry), Box<dyn std::error::Error>> {
    let personas = load_personas(environment)?;
    if let Some(persona) = personas.personas.get(reference) {
        return Ok((reference.to_owned(), persona.clone()));
    }
    let matches = personas
        .personas
        .iter()
        .filter(|(_, persona)| {
            persona.alias.as_deref() == Some(reference)
                || persona.actor_id == reference
                || uuid::Uuid::parse_str(&persona.actor_id)
                    .ok()
                    .map(fact_sdk::reference::short_uuid_reference)
                    .as_deref()
                    == Some(reference)
        })
        .map(|(name, persona)| (name.clone(), persona.clone()))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(name, persona)] => Ok((name.clone(), persona.clone())),
        [] => Err(user_error(format!("unknown persona: {reference}"))),
        _ => Err(user_error(format!(
            "ambiguous persona reference: {reference}"
        ))),
    }
}

fn default_persona(
    environment: &UserEnvironment,
) -> Result<Option<(String, PersonaEntry)>, Box<dyn std::error::Error>> {
    let personas = load_personas(environment)?;
    let Some(name) = personas.default else {
        return Ok(None);
    };
    let persona = personas
        .personas
        .get(&name)
        .cloned()
        .ok_or_else(|| user_error(format!("default persona is missing: {name}")))?;
    Ok(Some((name, persona)))
}

fn persona_seed_file(environment: &UserEnvironment, persona: &PersonaEntry) -> PathBuf {
    environment
        .identity_dir
        .join(format!("{}.seed", persona.actor_id))
}

fn persona_ledger_entry(
    environment: &UserEnvironment,
    name: &str,
    persona: &PersonaEntry,
) -> LedgerEntry {
    LedgerEntry {
        name: name.to_owned(),
        ledger_id: persona.ledger_id.clone(),
        database: persona_database(environment),
        actor_id: persona.actor_id.clone(),
        key_id: persona.key_id.clone(),
        seed_file: persona_seed_file(environment, persona),
        read_only: false,
    }
}

fn persona_identity_bundle(
    environment: &UserEnvironment,
    name: &str,
    persona: &PersonaEntry,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(bundle) = &persona.identity_bundle {
        return decode_base64url(bundle)
            .ok_or_else(|| user_error(format!("persona {name} has invalid identity bundle")));
    }
    let persona_entry = persona_ledger_entry(environment, name, persona);
    Ok(fact_sdk::workflow::export_identity_for_actor(
        &persona_entry,
        uuid::Uuid::parse_str(&persona.actor_id)?,
    )?
    .bundle)
}

fn persona_for_actor(
    environment: &UserEnvironment,
    actor_id: &str,
) -> Result<Option<(String, PersonaEntry)>, Box<dyn std::error::Error>> {
    let personas = load_personas(environment)?;
    Ok(personas
        .personas
        .into_iter()
        .find(|(_, persona)| persona.actor_id == actor_id))
}

fn persona_json(
    environment: &UserEnvironment,
    name: &str,
    persona: &PersonaEntry,
    default: bool,
) -> serde_json::Value {
    let actor_id = uuid::Uuid::parse_str(&persona.actor_id).ok();
    let key_id = uuid::Uuid::parse_str(&persona.key_id).ok();
    serde_json::json!({
        "persona":name,
        "display_name":persona.display_name,
        "alias":persona.alias,
        "actor_type":persona.actor_type,
        "ledger_id":persona.ledger_id,
        "actor_id":persona.actor_id,
        "actor_ref":actor_id.map(fact_sdk::reference::short_uuid_reference),
        "key_id":persona.key_id,
        "key_ref":key_id.map(fact_sdk::reference::short_uuid_reference),
        "default":default,
        "local_private_key_material":persona_seed_file(environment, persona).exists()
    })
}

fn handle_persona_command(
    json: bool,
    command: PersonaCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let environment = UserEnvironment::discover()?;
    match command {
        PersonaCommand::Add {
            persona,
            name,
            alias,
            actor_type,
            default,
        } => {
            validate_profile_name(&persona)?;
            let mut personas = load_personas(&environment)?;
            if personas.personas.contains_key(&persona) {
                return Err(user_error(format!("persona already exists: {persona}")));
            }
            environment.ensure_dirs()?;
            let runtime = fact_sdk::runtime::production_runtime();
            let seed = runtime.seed()?;
            let created = fact_sdk::workflow::create_identity_for_persona(
                fact_sdk::workflow::CreatePersonaIdentityInput {
                    namespace: format!("local.persona.{persona}"),
                    seed,
                    actor_type: actor_type.clone(),
                },
            )?;
            let entry = PersonaEntry {
                display_name: name,
                alias,
                actor_type,
                ledger_id: created.ledger_id.to_string(),
                actor_id: created.actor_id.to_string(),
                key_id: created.key_id.to_string(),
                identity_bundle: Some(encode_base64url(&created.bundle)),
            };
            environment.write_seed(&persona_seed_file(&environment, &entry), &created.seed)?;
            personas.personas.insert(persona.clone(), entry.clone());
            if default || personas.default.is_none() {
                personas.default = Some(persona.clone());
            }
            save_personas(&environment, &personas)?;
            print_json_or(
                json,
                persona_json(
                    &environment,
                    &persona,
                    &entry,
                    personas.default.as_deref() == Some(persona.as_str()),
                ),
                format!("added persona {persona}"),
            );
        }
        PersonaCommand::List => {
            let personas = load_personas(&environment)?;
            let items = personas
                .personas
                .iter()
                .map(|(name, persona)| {
                    persona_json(
                        &environment,
                        name,
                        persona,
                        personas.default.as_deref() == Some(name.as_str()),
                    )
                })
                .collect::<Vec<_>>();
            if json {
                println!("{}", serde_json::json!(items));
            } else if items.is_empty() {
                println!("no personas");
            } else {
                for item in items {
                    println!(
                        "{}  {}  {}{}{}",
                        item["persona"].as_str().unwrap(),
                        item["actor_ref"].as_str().unwrap_or("-"),
                        item["display_name"].as_str().unwrap(),
                        item["alias"]
                            .as_str()
                            .map(|alias| format!("  @{alias}"))
                            .unwrap_or_default(),
                        if item["default"].as_bool() == Some(true) {
                            "  default"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        PersonaCommand::Show { persona } => {
            let (name, persona) = resolve_persona(&environment, &persona)?;
            let personas = load_personas(&environment)?;
            let is_default = personas.default.as_deref() == Some(name.as_str());
            print_json_or(
                json,
                persona_json(&environment, &name, &persona, is_default),
                format!(
                    "{}  {}  {}{}{}",
                    name,
                    fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(
                        &persona.actor_id
                    )?),
                    persona.display_name,
                    persona
                        .alias
                        .as_ref()
                        .map(|alias| format!("  @{alias}"))
                        .unwrap_or_default(),
                    if is_default { "  default" } else { "" }
                ),
            );
        }
        PersonaCommand::Default { persona } => {
            let (name, _) = resolve_persona(&environment, &persona)?;
            let mut personas = load_personas(&environment)?;
            personas.default = Some(name.clone());
            save_personas(&environment, &personas)?;
            print_json_or(
                json,
                serde_json::json!({"persona":name,"default":true}),
                format!("default persona {name}"),
            );
        }
    }
    Ok(())
}

fn ensure_user_ledger_with_persona(
    environment: &UserEnvironment,
    name: &str,
    requested_persona: Option<&str>,
) -> Result<(LedgerEntry, bool, Option<String>), Box<dyn std::error::Error>> {
    if let Some(entry) = environment.load()?.get(name).cloned() {
        let persona = persona_for_actor(environment, &entry.actor_id)?.map(|(name, _)| name);
        return Ok((entry, false, persona));
    }
    let persona = match requested_persona {
        Some(reference) => Some(resolve_persona(environment, reference)?),
        None => default_persona(environment)?,
    };
    let (entry, created) = environment::ensure_user_ledger(environment, name)?;
    let Some((persona_name, persona)) = persona else {
        return Ok((entry, created, None));
    };
    if !created {
        return Ok((entry, false, Some(persona_name)));
    }
    let persona_bundle = persona_identity_bundle(environment, &persona_name, &persona)?;
    fact_sdk::workflow::import_identity(&entry, &persona_bundle)?;
    let seed = read_seed_for_write(environment, &entry)?;
    fact_sdk::workflow::create_identity_grant(
        &entry,
        &seed,
        &persona.actor_id,
        &["admin".to_owned()],
    )?;
    let mut entries = environment.load()?;
    let mut updated = entry.clone();
    updated.actor_id = persona.actor_id.clone();
    updated.key_id = persona.key_id.clone();
    updated.seed_file = persona_seed_file(environment, &persona);
    entries.insert(name.to_owned(), updated.clone());
    environment.save(&entries)?;
    Ok((updated, true, Some(persona_name)))
}

fn directory_entries_by_actor(
    entry: &LedgerEntry,
) -> Result<
    std::collections::BTreeMap<uuid::Uuid, fact_sdk::workflow::DirectoryEntry>,
    Box<dyn std::error::Error>,
> {
    Ok(fact_sdk::workflow::list_directory(entry)?
        .into_iter()
        .map(|entry| (entry.actor_id, entry))
        .collect())
}

fn ledger_proposition_counts(
    items: &[PropositionListItem],
) -> std::collections::BTreeMap<&'static str, usize> {
    fn increment(counts: &mut std::collections::BTreeMap<&'static str, usize>, key: &'static str) {
        counts.entry(key).and_modify(|count| *count += 1);
    }

    let mut counts = std::collections::BTreeMap::from([
        ("total", items.len()),
        ("accepted", 0),
        ("pending", 0),
        ("rejected", 0),
        ("contested", 0),
        ("withdrawn", 0),
        ("archived", 0),
        ("update_pending", 0),
    ]);
    for item in items {
        match proposition_display_status(item).as_str() {
            "accepted" => increment(&mut counts, "accepted"),
            "pending" => increment(&mut counts, "pending"),
            "rejected" => increment(&mut counts, "rejected"),
            "contested" | "conflict" => increment(&mut counts, "contested"),
            "withdrawn" => increment(&mut counts, "withdrawn"),
            "archived" => increment(&mut counts, "archived"),
            status if status.ends_with(", update pending") => {
                increment(&mut counts, "update_pending");
                match status.trim_end_matches(", update pending") {
                    "accepted" => increment(&mut counts, "accepted"),
                    "pending" => increment(&mut counts, "pending"),
                    "rejected" => increment(&mut counts, "rejected"),
                    "contested" | "conflict" => increment(&mut counts, "contested"),
                    _ => {}
                }
            }
            _ => {}
        };
    }
    counts
}

fn ledger_show_value(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let propositions = list_user_propositions(entry, None, true, 0, 0, None)?;
    let actors = actor_identity_list_items(environment, entry, 0, 0)?;
    let remotes = environment.load_remotes()?;
    let remote_count = scoped_remotes(remotes.values(), &entry.ledger_id).len();
    let active = environment
        .active_name()?
        .as_deref()
        .is_some_and(|active| active == entry.name);
    Ok(serde_json::json!({
        "name":entry.name,
        "ledger_id":entry.ledger_id,
        "ledger_ref":short_uuid_string(&entry.ledger_id),
        "database":entry.database,
        "read_only":entry.read_only,
        "active":active,
        "remote_count":remote_count,
        "propositions":ledger_proposition_counts(&propositions),
        "actors":actors
    }))
}

fn format_ledger_proposition_counts(counts: &serde_json::Value) -> String {
    format!(
        "{} total, {} accepted, {} pending, {} rejected, {} contested, {} withdrawn, {} archived, {} update pending",
        counts["total"].as_u64().unwrap_or_default(),
        counts["accepted"].as_u64().unwrap_or_default(),
        counts["pending"].as_u64().unwrap_or_default(),
        counts["rejected"].as_u64().unwrap_or_default(),
        counts["contested"].as_u64().unwrap_or_default(),
        counts["withdrawn"].as_u64().unwrap_or_default(),
        counts["archived"].as_u64().unwrap_or_default(),
        counts["update_pending"].as_u64().unwrap_or_default()
    )
}

fn print_ledger_show(
    json: bool,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    println!(
        "ledger        {}  {}",
        value["name"].as_str().unwrap_or("-"),
        value["ledger_ref"].as_str().unwrap_or("-")
    );
    println!(
        "database      {}",
        value["database"].as_str().unwrap_or("-")
    );
    println!(
        "read only     {}",
        value["read_only"].as_bool().unwrap_or_default()
    );
    println!(
        "active        {}",
        value["active"].as_bool().unwrap_or_default()
    );
    println!(
        "remotes       {}",
        value["remote_count"].as_u64().unwrap_or_default()
    );
    println!(
        "propositions  {}",
        format_ledger_proposition_counts(&value["propositions"])
    );
    println!("actors");
    let actors = value["actors"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    print_actor_identity_items(false, actors)?;
    Ok(())
}

fn actor_identity_list_items(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    limit: usize,
    offset: usize,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let store = fact_store::Store::open(&entry.database)?;
    let directory_entries = directory_entries_by_actor(entry)?;
    let mut items = Vec::new();
    for (id, _, object_type) in store.list_identity_objects()? {
        if object_type != "actor" {
            continue;
        }
        let local_seed = environment.identity_dir.join(format!("{id}.seed")).exists();
        let key_id = identity_actor_key_id(&store, id)?;
        let directory = directory_entries.get(&id);
        let capabilities = actor_capabilities_in_store(&store, entry, id)?;
        let persona = persona_for_actor(environment, &id.to_string())?;
        let admin = capabilities.iter().any(|capability| capability == "admin");
        items.push(serde_json::json!({
            "actor_id":id,
            "actor_ref":fact_sdk::reference::short_uuid_reference(id),
            "key_id":key_id,
            "key_ref":key_id.map(fact_sdk::reference::short_uuid_reference),
            "persona":persona.as_ref().map(|(name, _)| name.clone()),
            "display_name":directory.as_ref().map(|item| item.display_name.clone()),
            "alias":directory.as_ref().and_then(|item| item.alias.clone()),
            "capabilities":capabilities,
            "admin":admin,
            "local_private_key_material":local_seed,
            "active":entry.actor_id == id.to_string()
        }));
    }
    Ok(items
        .into_iter()
        .skip(offset)
        .take(if limit == 0 { usize::MAX } else { limit })
        .collect())
}

fn print_actor_identity_items(
    json: bool,
    items: &[serde_json::Value],
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        println!("{}", serde_json::to_string_pretty(items)?);
    } else if items.is_empty() {
        println!("no actors");
    } else {
        for item in items {
            let name = item["display_name"].as_str().unwrap_or("No name");
            let key = item["key_ref"].as_str().unwrap_or("-");
            let alias = item["alias"].as_str().unwrap_or("No alias");
            let active = if item["active"].as_bool() == Some(true) {
                "  active"
            } else {
                ""
            };
            let capabilities = item["capabilities"]
                .as_array()
                .map(|capabilities| {
                    capabilities
                        .iter()
                        .filter_map(|capability| capability.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|capabilities| !capabilities.is_empty())
                .map(|capabilities| format!("  {capabilities}"))
                .unwrap_or_default();
            println!(
                "{}  {}  {}  {}{}{}",
                item["actor_ref"].as_str().unwrap(),
                key,
                name,
                alias,
                capabilities,
                active
            );
        }
    }
    Ok(())
}

fn actor_identity_show_value(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    actor: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let actor_id = fact_sdk::workflow::resolve_directory_actor_reference(entry, actor)?;
    let store = fact_store::Store::open(&entry.database)?;
    let local_seed = environment
        .identity_dir
        .join(format!("{actor_id}.seed"))
        .exists();
    let directory_entries = directory_entries_by_actor(entry)?;
    let directory = directory_entries.get(&actor_id);
    let capabilities = actor_capabilities_in_store(&store, entry, actor_id)?;
    let key_id = identity_actor_key_id(&store, actor_id)?;
    let persona = persona_for_actor(environment, &actor_id.to_string())?;
    Ok(serde_json::json!({
        "actor_id":actor_id,
        "actor_ref":fact_sdk::reference::short_uuid_reference(actor_id),
        "key_id":key_id,
        "key_ref":key_id.map(fact_sdk::reference::short_uuid_reference),
        "persona":persona.as_ref().map(|(name, _)| name.clone()),
        "display_name":directory.as_ref().map(|item| item.display_name.clone()),
        "alias":directory.as_ref().and_then(|item| item.alias.clone()),
        "capabilities":capabilities,
        "local_private_key_material":local_seed,
        "active":entry.actor_id == actor_id.to_string(),
        "imported":store.get_cose_by_id_any(actor_id.as_bytes())?.is_some()
    }))
}

fn print_actor_identity_show(
    json: bool,
    value: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let capabilities = value["capabilities"]
        .as_array()
        .map(|capabilities| {
            capabilities
                .iter()
                .filter_map(|capability| capability.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|capabilities| !capabilities.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    print_json_or(
        json,
        value.clone(),
        format!(
            "{}  {}\nkey: {}\npersona: {}\ncapabilities: {}",
            value["actor_ref"].as_str().unwrap_or("-"),
            value["display_name"].as_str().unwrap_or("unnamed"),
            value["key_ref"].as_str().unwrap_or("-"),
            value["persona"].as_str().unwrap_or("-"),
            capabilities
        ),
    );
    Ok(())
}

fn use_actor_identity(
    environment: &UserEnvironment,
    entry: LedgerEntry,
    actor: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let requested_name = entry.name.clone();
    let mut entries = environment.load()?;
    let resolved = fact_sdk::workflow::resolve_directory_reference(&entry, actor)?;
    let store = fact_store::Store::open(&entry.database)?;
    let key_id = resolved
        .key_id
        .or(identity_actor_key_id(&store, resolved.actor_id)?)
        .ok_or_else(|| {
            user_error(format!(
                "actor {} has no signing key association",
                resolved.actor_id
            ))
        })?;
    let seed_file = local_identity_seed_file(environment, resolved.actor_id, key_id)?;
    let updated = LedgerEntry {
        actor_id: resolved.actor_id.to_string(),
        key_id: key_id.to_string(),
        seed_file,
        ..entry
    };
    entries.insert(requested_name.clone(), updated);
    environment.save(&entries)?;
    Ok(serde_json::json!({
        "active":true,
        "ledger":requested_name,
        "actor_id":resolved.actor_id,
        "key_id":key_id,
        "display_name":resolved.display_name
    }))
}

fn name_actor_identity(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    actor: &str,
    display_name: String,
    alias: Option<String>,
    actor_type: Option<String>,
    role: Option<String>,
) -> Result<fact_sdk::workflow::DirectoryAddResult, Box<dyn std::error::Error>> {
    let seed = read_seed_for_write(environment, entry)?;
    let actor_id = fact_sdk::workflow::resolve_directory_actor_reference(entry, actor)?;
    let store = fact_store::Store::open(&entry.database)?;
    let current = fact_sdk::workflow::show_directory_entry(entry, &actor_id.to_string()).ok();
    let key_id = current
        .as_ref()
        .and_then(|entry| entry.key_id)
        .or(identity_actor_key_id(&store, actor_id)?);
    fact_sdk::workflow::add_directory_entry(
        entry,
        &seed,
        fact_sdk::workflow::DirectoryAddInput {
            display_name,
            actor_id: Some(actor_id),
            key_id,
            alias: alias.or_else(|| current.as_ref().and_then(|entry| entry.alias.clone())),
            actor_type: actor_type
                .or_else(|| current.as_ref().and_then(|entry| entry.actor_type.clone())),
            role: role.or_else(|| current.as_ref().and_then(|entry| entry.role.clone())),
            source: Some("actor-name".to_owned()),
            verified_by: None,
            with_identity: false,
            seed: None,
        },
    )
    .map_err(Into::into)
}

fn handle_actor_command(
    json: bool,
    command: ActorCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ActorCommand::New {
            name,
            alias,
            profile,
            actor_type,
            role,
            permission,
            participate,
            ledger,
        } => {
            let value = as_user_identity(fact_as::Input {
                name,
                alias,
                self_actor: false,
                actor_type,
                profile,
                role,
                source: None,
                verified_by: None,
                home: None,
                print_env: false,
                use_home: false,
                permission,
                participate,
                no_create: false,
                update_directory: false,
                ledger,
            })?;
            print_json_or(
                json,
                value.clone(),
                format!(
                    "using {} for ledger {}",
                    value["actor"]["display_name"].as_str().unwrap_or("actor"),
                    value["ledger"]["name"].as_str().unwrap_or("-")
                ),
            );
        }
        ActorCommand::List {
            limit,
            offset,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let items = actor_identity_list_items(&environment, &entry, limit, offset)?;
            print_actor_identity_items(json, &items)?;
        }
        ActorCommand::Show { actor, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = actor_identity_show_value(&environment, &entry, &actor)?;
            print_actor_identity_show(json, value)?;
        }
        ActorCommand::Use { actor, ledger } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = use_actor_identity(&environment, entry, &actor)?;
            print_json_or(
                json,
                value.clone(),
                format!(
                    "using {} for ledger {}",
                    value["display_name"].as_str().unwrap_or("actor"),
                    value["ledger"].as_str().unwrap_or("-")
                ),
            );
        }
        ActorCommand::Name {
            actor,
            name,
            alias,
            actor_type,
            role,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let result =
                name_actor_identity(&environment, &entry, &actor, name, alias, actor_type, role)?;
            print_json_or(
                json,
                serde_json::to_value(&result)?,
                format!("named {} as {}", result.display_name, result.actor_ref),
            );
        }
        ActorCommand::Grant {
            actor,
            capabilities,
            participate,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let capabilities = expanded_capabilities(capabilities, participate)?;
            let value = recognize_user_identity(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &actor,
                &capabilities,
            )?;
            print_json_or(
                json,
                value.clone(),
                format!("granted {} to {}", value["capabilities"], value["actor_id"]),
            );
        }
        ActorCommand::Revoke {
            grant,
            reason,
            ledger,
        } => {
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let value = revoke_user_grant(
                &entry,
                &read_seed_for_write(&environment, &entry)?,
                &grant,
                reason
                    .as_deref()
                    .unwrap_or("authority revoked by ledger administrator"),
            )?;
            print_json_or(
                json,
                value.clone(),
                format!("revoked grant {}", value["revoked_grant_id"]),
            );
        }
        ActorCommand::Send {
            name,
            alias,
            profile,
            actor_type,
            requests,
            participate,
            output,
        } => {
            let environment = UserEnvironment::discover()?;
            let profile = profile
                .as_deref()
                .map(|name| {
                    named_profile(&environment, name).map(|profile| (name.to_owned(), profile))
                })
                .transpose()?;
            let name = name
                .or_else(|| {
                    profile
                        .as_ref()
                        .map(|(_, profile)| profile.display_name.clone())
                })
                .ok_or_else(|| user_error("fact actor send requires a name or --profile"))?;
            let alias = alias.or_else(|| {
                profile
                    .as_ref()
                    .and_then(|(_, profile)| profile.alias.clone())
            });
            let actor_type = actor_type
                .or_else(|| {
                    profile
                        .as_ref()
                        .map(|(_, profile)| profile.actor_type.clone())
                })
                .unwrap_or_else(|| "human".to_owned());
            let actor =
                ensure_actor_request_identity(&environment, &name, alias.as_deref(), &actor_type)?;
            let entry = actor_request_ledger_entry(&actor);
            let bundle = fact_sdk::workflow::export_identity_for_actor(
                &entry,
                uuid::Uuid::parse_str(&actor.actor_id)?,
            )?
            .bundle;
            let identity =
                identity_from_actor_bundle(&bundle, uuid::Uuid::parse_str(&actor.actor_id)?)?;
            let requests = expanded_actor_requests(requests, participate)?;
            let request = actor_exchange::encode_actor_request(
                identity.actor_id,
                actor_exchange::ActorClaims {
                    display_name: Some(actor.name.clone()),
                    alias: actor.alias.clone(),
                    actor_type: Some(actor.actor_type.clone()),
                },
                requests,
                &bundle,
            );
            let bytes = actor_exchange::request_json(&request, false)?;
            let output = output
                .unwrap_or_else(|| actor_request_default_file(&actor.name, actor.alias.as_deref()));
            write_actor_artifact(&output, &bytes, false)?;
            let value = serde_json::json!({
                "created":true,
                "actor_id":identity.actor_id,
                "actor_ref":fact_sdk::reference::short_uuid_reference(identity.actor_id),
                "key_id":identity.key_id,
                "key_ref":fact_sdk::reference::short_uuid_reference(identity.key_id),
                "fingerprint":identity.fingerprint,
                "claims":request.claims,
                "requests":request.requests,
                "output":output
            });
            print_json_or(
                json,
                value,
                format!(
                    "wrote {}\nactor      {}\nclaims     {}\nrequests   {}\nkey        {}",
                    output.display(),
                    fact_sdk::reference::short_uuid_reference(identity.actor_id),
                    format_actor_claims(&request.claims),
                    format_capability_list(&request.requests),
                    identity.fingerprint
                ),
            );
        }
        ActorCommand::Inspect { file } => {
            let review = read_actor_request_review(&file)?;
            let value = actor_request_review_json(&review);
            print_json_or(json, value, format_actor_request_review(&review));
        }
        ActorCommand::Admit {
            file,
            input,
            name,
            alias,
            actor_type,
            capabilities,
            participate,
            with_token,
            token_expires_days,
            token_label,
            token_store,
            output,
            ledger,
            remote,
        } => {
            let request_path = input.or(file).ok_or_else(|| {
                user_error(
                    "fact actor admit requires FILE or --input FILE; use --input - for stdin",
                )
            })?;
            let review = read_actor_request_review(&request_path)?;
            let capabilities = expanded_capabilities(capabilities, participate)?;
            let environment = UserEnvironment::discover()?;
            let entry = ensure_active_entry(&environment, ledger.as_deref())?;
            let remote = configured_remote_for_ledger(&environment, remote.as_deref(), &entry)?;
            let store = fact_store::Store::open(&entry.database)?;
            let ledger_id = uuid::Uuid::parse_str(&entry.ledger_id)?;
            let (namespace, genesis_hash) = store
                .get_ledger_metadata(ledger_id.as_bytes())?
                .ok_or_else(|| {
                    user_error(format!(
                        "ledger metadata is missing for {}",
                        entry.ledger_id
                    ))
                })?;
            let genesis_hash = genesis_hash.ok_or_else(|| {
                user_error(format!(
                    "ledger genesis hash is missing for {}; cannot write a remote descriptor",
                    entry.ledger_id
                ))
            })?;
            let claims = &review.request.claims;
            let display_name = name
                .or_else(|| claims.display_name.clone())
                .unwrap_or_else(|| review.identity.actor_id.to_string());
            let alias = alias.or_else(|| claims.alias.clone());
            let actor_type = actor_type
                .or_else(|| claims.actor_type.clone())
                .or_else(|| Some("human".to_owned()));
            let seed = read_seed_for_write(&environment, &entry)?;
            let imported = fact_sdk::workflow::import_identity(&entry, &review.bundle)?;
            let directory = fact_sdk::workflow::add_directory_entry(
                &entry,
                &seed,
                fact_sdk::workflow::DirectoryAddInput {
                    display_name: display_name.clone(),
                    actor_id: Some(review.identity.actor_id),
                    key_id: Some(review.identity.key_id),
                    alias: alias.clone(),
                    actor_type: actor_type.clone(),
                    role: None,
                    source: Some("actor-admit".to_owned()),
                    verified_by: None,
                    with_identity: false,
                    seed: None,
                },
            )?;
            let grant = fact_sdk::workflow::create_identity_grant(
                &entry,
                &seed,
                &review.identity.actor_id.to_string(),
                &capabilities,
            )?;
            let issued_token = if with_token {
                Some(issue_http_actor_token(
                    &environment,
                    &entry,
                    review.identity.actor_id,
                    token_expires_days,
                    token_label
                        .or_else(|| alias.clone())
                        .or_else(|| Some(display_name.clone())),
                    token_store,
                )?)
            } else {
                None
            };
            let grant_id = uuid::Uuid::parse_str(&grant.grant_id.to_string())?;
            let grant_bytes = store
                .get_cose_by_id(ledger_id.as_bytes(), grant_id.as_bytes())?
                .ok_or_else(|| {
                    user_error(format!(
                        "created grant object is missing: {}",
                        grant.grant_id
                    ))
                })?;
            let grant_hash = fact_core::Hash::from_str(&grant.content_hash)?;
            let grant_bundle =
                fact_sdk::workflow::encode_bundle(ledger_id, &[(grant_hash, grant_bytes)])?;
            let response = actor_exchange::encode_actor_response(
                review.identity.actor_id,
                Some(actor_exchange::ActorClaims {
                    display_name: Some(display_name.clone()),
                    alias: alias.clone(),
                    actor_type: actor_type.clone(),
                }),
                actor_exchange::ResponseLedger {
                    id: ledger_id,
                    genesis_hash: genesis_hash.hex(),
                    namespace,
                },
                capabilities.clone(),
                actor_exchange::ResponseEndpoint {
                    schema: "fact-remote-v0".to_owned(),
                    url: remote.url,
                    ledger_id: entry.ledger_id.clone(),
                    genesis_hash: genesis_hash.hex(),
                    token: issued_token
                        .as_ref()
                        .map(|token| token.issued.token.clone()),
                },
                request_fingerprint(&review.bundle),
                &grant_bundle,
            );
            let response_bytes = actor_exchange::response_json(&response, false)?;
            let output = output
                .unwrap_or_else(|| actor_response_default_file(alias.as_deref(), &display_name));
            write_actor_artifact(&output, &response_bytes, response.endpoint.token.is_some())?;
            let mut value = serde_json::json!({
                "admitted":true,
                "actor_id":review.identity.actor_id,
                "actor_ref":fact_sdk::reference::short_uuid_reference(review.identity.actor_id),
                "directory":directory,
                "identity_import":imported,
                "grant":grant,
                "granted":capabilities,
                "fingerprint":review.identity.fingerprint,
                "response":response,
                "output":output
            });
            if let Some(token) = &issued_token {
                value["access_token"] = access_token_json(token, false);
            }
            let mut human = format_actor_request_review(&review);
            human.push('\n');
            human.push_str(&format!(
                "recognized {} as {}\ngranted {}\nwrote {}",
                fact_sdk::reference::short_uuid_reference(review.identity.actor_id),
                format_actor_claims(&actor_exchange::ActorClaims {
                    display_name: Some(display_name),
                    alias,
                    actor_type,
                }),
                format_capability_list(&capabilities),
                output.display()
            ));
            print_json_or(json, value, human);
        }
    }
    Ok(())
}

fn actor_registry_path(environment: &UserEnvironment) -> PathBuf {
    environment.identity_dir.join("actors.json")
}

fn actor_request_database(environment: &UserEnvironment) -> PathBuf {
    environment.identity_dir.join("actors.sqlite")
}

fn load_actor_registry(
    environment: &UserEnvironment,
) -> Result<ActorRegistry, Box<dyn std::error::Error>> {
    let path = actor_registry_path(environment);
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ActorRegistry::default()),
        Err(error) => Err(error.into()),
    }
}

fn save_actor_registry(
    environment: &UserEnvironment,
    registry: &ActorRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    environment.ensure_dirs()?;
    fs::write(
        actor_registry_path(environment),
        serde_json::to_vec_pretty(registry)?,
    )?;
    Ok(())
}

fn ensure_actor_request_identity(
    environment: &UserEnvironment,
    name: &str,
    alias: Option<&str>,
    actor_type: &str,
) -> Result<ActorRequestIdentity, Box<dyn std::error::Error>> {
    environment.ensure_dirs()?;
    if let Some(identity) = directory_actor_request_identity(environment, name, alias)? {
        return Ok(identity);
    }
    let key = actor_registry_key(name, alias)?;
    let mut registry = load_actor_registry(environment)?;
    if let Some(existing) = registry.actors.get(&key) {
        let seed_file = environment
            .identity_dir
            .join(format!("{}.seed", existing.actor_id));
        if seed_file.exists() {
            let mut updated = existing.clone();
            updated.name = name.to_owned();
            updated.alias = alias.map(str::to_owned).or(existing.alias.clone());
            updated.actor_type = actor_type.to_owned();
            registry.actors.insert(key, updated.clone());
            save_actor_registry(environment, &registry)?;
            return Ok(registry_actor_request_identity(environment, updated));
        }
    }
    let runtime = fact_sdk::runtime::production_runtime();
    let seed = runtime.seed()?;
    let database = actor_request_database(environment);
    let store = fact_store::Store::open(&database)?;
    let result = fact_sdk::workflow::create_identity(
        &store,
        fact_sdk::workflow::CreateIdentityInput {
            namespace: format!("local.actor.{key}"),
            seed,
            actor_type: actor_type.to_owned(),
        },
    )?;
    let seed_file = environment
        .identity_dir
        .join(format!("{}.seed", result.actor_id));
    environment.write_seed(&seed_file, &seed)?;
    let entry = ActorRegistryEntry {
        name: name.to_owned(),
        alias: alias.map(str::to_owned),
        actor_type: actor_type.to_owned(),
        ledger_id: result.ledger_id.to_string(),
        actor_id: result.actor_id.to_string(),
        key_id: result.key_id.to_string(),
    };
    registry.actors.insert(key, entry.clone());
    save_actor_registry(environment, &registry)?;
    Ok(registry_actor_request_identity(environment, entry))
}

fn actor_request_ledger_entry(actor: &ActorRequestIdentity) -> LedgerEntry {
    LedgerEntry {
        name: actor_registry_key(&actor.name, actor.alias.as_deref())
            .unwrap_or_else(|_| "actor".to_owned()),
        ledger_id: actor.ledger_id.clone(),
        database: actor.database.clone(),
        actor_id: actor.actor_id.clone(),
        key_id: actor.key_id.clone(),
        seed_file: actor.seed_file.clone(),
        read_only: false,
    }
}

fn registry_actor_request_identity(
    environment: &UserEnvironment,
    actor: ActorRegistryEntry,
) -> ActorRequestIdentity {
    ActorRequestIdentity {
        name: actor.name,
        alias: actor.alias,
        actor_type: actor.actor_type,
        ledger_id: actor.ledger_id,
        database: actor_request_database(environment),
        actor_id: actor.actor_id.clone(),
        key_id: actor.key_id,
        seed_file: environment
            .identity_dir
            .join(format!("{}.seed", actor.actor_id)),
    }
}

fn directory_actor_request_identity(
    environment: &UserEnvironment,
    name: &str,
    alias: Option<&str>,
) -> Result<Option<ActorRequestIdentity>, Box<dyn std::error::Error>> {
    let Ok(entry) = environment.resolve(None) else {
        return Ok(None);
    };
    let directory = alias
        .map(|alias| fact_sdk::workflow::show_directory_entry(&entry, alias))
        .transpose()?
        .or_else(|| fact_sdk::workflow::show_directory_entry(&entry, name).ok());
    let Some(directory) = directory else {
        return Ok(None);
    };
    let Some(key_id) = directory.key_id else {
        return Ok(None);
    };
    let seed_file = environment
        .identity_dir
        .join(format!("{}.seed", directory.actor_id));
    if !seed_file.exists() {
        return Ok(None);
    }
    Ok(Some(ActorRequestIdentity {
        name: directory.display_name,
        alias: directory.alias,
        actor_type: directory.actor_type.unwrap_or_else(|| "human".to_owned()),
        ledger_id: entry.ledger_id,
        database: entry.database,
        actor_id: directory.actor_id.to_string(),
        key_id: key_id.to_string(),
        seed_file,
    }))
}

fn actor_registry_key(
    name: &str,
    alias: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let source = alias.unwrap_or(name);
    let key = actor_artifact_stem(source);
    if !portable_name(&key) {
        return Err(user_error(format!("invalid actor name: {source}")));
    }
    Ok(key)
}

fn actor_artifact_stem(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            output.push((byte as char).to_ascii_lowercase());
        } else if matches!(byte, b'-' | b'_') {
            output.push(byte as char);
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    output.trim_matches('-').to_owned()
}

fn actor_request_default_file(name: &str, alias: Option<&str>) -> PathBuf {
    PathBuf::from(format!(
        "{}.actor.json",
        actor_artifact_stem(alias.unwrap_or(name))
    ))
}

fn actor_response_default_file(alias: Option<&str>, display_name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}.connection.json",
        actor_artifact_stem(alias.unwrap_or(display_name))
    ))
}

fn expanded_actor_requests(
    requests: Vec<String>,
    participate: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut expanded = Vec::new();
    let mut expand_participate = participate;
    for request in requests {
        if request == "participate" {
            expand_participate = true;
        } else {
            expanded.push(request);
        }
    }
    let expanded = expanded_optional_capabilities(expanded, expand_participate);
    validate_capabilities(&expanded)?;
    Ok(expanded)
}

fn read_actor_request_review(
    path: &Path,
) -> Result<ActorRequestReview, Box<dyn std::error::Error>> {
    let bytes = read_actor_artifact(path)?;
    let request = actor_exchange::parse_request(&bytes).map_err(user_error)?;
    let bundle = actor_exchange::request_bundle(&request).map_err(user_error)?;
    let identity = identity_from_actor_bundle(&bundle, request.actor)?;
    let filename_mismatch = filename_actor_mismatch(path, request.actor);
    Ok(ActorRequestReview {
        request,
        bundle,
        identity,
        filename_mismatch,
    })
}

fn read_actor_artifact(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        Ok(fs::read(path)?)
    }
}

fn write_actor_artifact(
    path: &Path,
    bytes: &[u8],
    sensitive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if path == Path::new("-") {
        io::stdout().write_all(bytes)?;
        return Ok(());
    }
    if sensitive {
        write_file_with_mode(path, bytes, 0o600)?;
    } else {
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn identity_from_actor_bundle(
    bundle: &[u8],
    actor_id: uuid::Uuid,
) -> Result<ActorBundleIdentity, Box<dyn std::error::Error>> {
    let bundle =
        fact_commitment::decode_bundle(bundle).map_err(|error| user_error(error.to_string()))?;
    let mut actor_seen = false;
    let mut binding_key = None;
    let mut keys = std::collections::BTreeMap::<uuid::Uuid, String>::new();
    for object in bundle.objects {
        let payload = fact_crypto::decode_sign1(&object)?.payload;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        match value.get("object_type").and_then(serde_json::Value::as_str) {
            Some("actor") => {
                if value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    == Some(actor_id)
                {
                    actor_seen = true;
                }
            }
            Some("actor_key_binding") => {
                let body = value.get("body").and_then(serde_json::Value::as_object);
                if body
                    .and_then(|body| body.get("actor_id"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    == Some(actor_id)
                {
                    binding_key = body
                        .and_then(|body| body.get("key_id"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| uuid::Uuid::parse_str(value).ok());
                }
            }
            Some("key") => {
                let Some(key_id) = value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                else {
                    continue;
                };
                let Some(fingerprint) = value
                    .get("body")
                    .and_then(|body| body.get("public_key"))
                    .and_then(|key| key.get("fingerprint"))
                    .and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                keys.insert(key_id, format!("SHA256:{fingerprint}"));
            }
            _ => {}
        }
    }
    if !actor_seen {
        return Err(user_error(format!(
            "request bundle does not contain signed actor {actor_id}"
        )));
    }
    let key_id = binding_key.ok_or_else(|| {
        user_error(format!(
            "request bundle does not contain a signing key binding for {actor_id}"
        ))
    })?;
    let fingerprint = keys.get(&key_id).cloned().ok_or_else(|| {
        user_error(format!(
            "request bundle does not contain signing key {key_id}"
        ))
    })?;
    Ok(ActorBundleIdentity {
        actor_id,
        key_id,
        fingerprint,
    })
}

fn filename_actor_mismatch(path: &Path, actor_id: uuid::Uuid) -> Option<String> {
    if path == Path::new("-") {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    let candidate = uuid::Uuid::parse_str(stem).ok()?;
    (candidate != actor_id).then(|| {
        format!(
            "filename actor {candidate} does not match bundle actor {actor_id}; using bundle actor"
        )
    })
}

fn actor_request_review_json(review: &ActorRequestReview) -> serde_json::Value {
    serde_json::json!({
        "actor_id":review.identity.actor_id,
        "actor_ref":fact_sdk::reference::short_uuid_reference(review.identity.actor_id),
        "key_id":review.identity.key_id,
        "key_ref":fact_sdk::reference::short_uuid_reference(review.identity.key_id),
        "fingerprint":review.identity.fingerprint,
        "claims":review.request.claims,
        "requests":review.request.requests,
        "filename_mismatch":review.filename_mismatch
    })
}

fn format_actor_request_review(review: &ActorRequestReview) -> String {
    let mut lines = vec![
        format!(
            "actor      {}",
            fact_sdk::reference::short_uuid_reference(review.identity.actor_id)
        ),
        format!("claims     {}", format_actor_claims(&review.request.claims)),
        format!(
            "requests   {}",
            format_capability_list(&review.request.requests)
        ),
        format!("key        {}", review.identity.fingerprint),
    ];
    if let Some(mismatch) = &review.filename_mismatch {
        lines.push(format!("warning    {mismatch}"));
    }
    lines.join("\n")
}

fn format_actor_claims(claims: &actor_exchange::ActorClaims) -> String {
    let name = claims.display_name.as_deref().unwrap_or("unnamed");
    let alias = claims
        .alias
        .as_ref()
        .map(|alias| format!("  @{alias}"))
        .unwrap_or_default();
    let actor_type = claims.actor_type.as_deref().unwrap_or("unknown");
    format!("\"{name}\"{alias}  ({actor_type})")
}

fn format_capability_list(capabilities: &[String]) -> String {
    if capabilities.is_empty() {
        "-".to_owned()
    } else {
        capabilities.join(", ")
    }
}

fn request_fingerprint(bundle: &[u8]) -> String {
    fact_core::Hash::digest(bundle).hex()
}

fn token_record_json(record: &fact_http::BearerTokenRecord) -> serde_json::Value {
    serde_json::json!({
        "token_id":record.token_id,
        "actor_id":record.actor_id.to_string(),
        "ledger_id":record.ledger_id.map(|ledger| ledger.to_string()),
        "created_at":format_http_time(record.created_at),
        "expires_at":record.expires_at.map(format_http_time),
        "revoked_at":record.revoked_at.map(format_http_time),
        "last_used_at":record.last_used_at.map(format_http_time),
        "label":record.label
    })
}

fn format_http_time(value: time::OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("OffsetDateTime can be formatted as RFC3339")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PagerPolicy {
    Auto,
    Force,
    Never,
}

impl PagerPolicy {
    fn from_cli(cli: &Cli) -> Self {
        if cli.no_pager || cli.json {
            Self::Never
        } else if cli.pager {
            Self::Force
        } else {
            Self::Auto
        }
    }
}

fn print_or_page(text: &str, policy: PagerPolicy, auto_page: bool) -> io::Result<()> {
    let should_page = match policy {
        PagerPolicy::Never => false,
        PagerPolicy::Force => true,
        PagerPolicy::Auto => auto_page && io::stdout().is_terminal(),
    };
    if should_page {
        page_text(text)
    } else {
        print!("{text}");
        Ok(())
    }
}

fn page_text(text: &str) -> io::Result<()> {
    let pager = env::var("FACT_PAGER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var("PAGER")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "less -R".to_owned());
    let mut parts = pager.split_whitespace();
    let Some(program) = parts.next() else {
        print!("{text}");
        return Ok(());
    };
    let mut child = match ProcessCommand::new(program)
        .args(parts)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) if program != "more" => ProcessCommand::new("more").stdin(Stdio::piped()).spawn()?,
        Err(error) => return Err(error),
    };
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(text.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}

struct ShowHumanOptions {
    show_empty_conflicts: bool,
    show_empty_pending: bool,
    show_participants: bool,
    show_history: bool,
    show_content: bool,
}

fn format_show_overview(
    overview: &fact_sdk::workflow::ShowOverview,
    options: ShowHumanOptions,
) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{}  {}  {}\n",
        overview.proposition.reference,
        proposition_display_status(&overview.proposition),
        overview.proposition.summary
    ));

    if let Some(revision) = &overview.effective_revision {
        output.push_str("\nEffective revision\n");
        output.push_str(&format!(
            "  revision:      {}\n",
            revision["reference"].as_str().unwrap_or("-")
        ));
        output.push_str(&format!(
            "  created:       {}\n",
            revision["created_at"].as_str().unwrap_or("-")
        ));
        output.push_str(&format!(
            "  author:        {}\n",
            format_show_author(revision)
        ));
        if let Some(deliberation_id) = overview.proposition.deliberation_id {
            output.push_str(&format!(
                "  deliberation:  {}\n",
                short_uuid(deliberation_id)
            ));
        }
        if let Some(settlement_id) = overview.proposition.settlement_id {
            output.push_str(&format!("  settlement:    {}\n", short_uuid(settlement_id)));
        }
    }

    if !overview.tags.is_empty() {
        output.push_str("\nTags\n");
        output.push_str(&format!("  {}\n", overview.tags.join("  ")));
    }

    if !overview.conflicts.is_empty() || options.show_empty_conflicts {
        output.push_str("\nConflicts\n");
        if overview.conflicts.is_empty() {
            output.push_str("  no revision conflicts\n");
        } else {
            for group in &overview.conflicts {
                if let Some(common_ancestor) = group.common_ancestor_revision_id {
                    output.push_str(&format!(
                        "  common ancestor: {}\n",
                        short_uuid(common_ancestor)
                    ));
                }
                for revision in &group.conflicts {
                    let mut line = format!(
                        "  revision {}  {}",
                        short_uuid(revision.revision_id),
                        revision.status
                    );
                    if let Some(deliberation_id) = revision.deliberation_id {
                        line.push_str(&format!("  deliberation {}", short_uuid(deliberation_id)));
                    }
                    if let Some(settlement_id) = revision.settlement_id {
                        line.push_str(&format!("  settlement {}", short_uuid(settlement_id)));
                    }
                    output.push_str(&line);
                    output.push('\n');
                }
            }
        }
    }

    if overview.pending.current_actor_pending || options.show_empty_pending {
        output.push_str("\nPending\n");
        if overview.pending.actions.is_empty() {
            output.push_str("  no pending actions for you\n");
        } else {
            for action in &overview.pending.actions {
                output.push_str(&format!(
                    "  {}\n",
                    action["command"].as_str().unwrap_or("pending action")
                ));
            }
        }
    }

    if !overview.revisions.is_empty() {
        output.push_str("\nRevisions\n");
        for revision in &overview.revisions {
            let marker = if revision["highlighted"].as_bool() == Some(true) {
                "*"
            } else {
                " "
            };
            output.push_str(&format!(
                "{marker} {}  {}  {}  {}\n",
                revision["reference"].as_str().unwrap_or("-"),
                revision["status"].as_str().unwrap_or("-"),
                revision["created_at"].as_str().unwrap_or("-"),
                revision["summary"].as_str().unwrap_or("No summary")
            ));
        }
        if overview.page.revisions_truncated {
            output.push_str("  ... more revisions hidden; use --revisions N\n");
        }
    }

    if options.show_participants && !overview.deliberations.is_empty() {
        output.push_str("\nDeliberations\n");
        for deliberation in &overview.deliberations {
            output.push_str(&format!(
                "  {}  revision {}\n",
                deliberation["reference"].as_str().unwrap_or("-"),
                deliberation["body"]["revision_id"].as_str().unwrap_or("-")
            ));
            if let Some(participants) = deliberation["participants"].as_array() {
                for participant in participants {
                    output.push_str(&format!(
                        "    participant {}\n",
                        format_actor_reference_value(participant)
                    ));
                }
            }
        }
    }

    if !overview.comments.is_empty() {
        output.push_str("\nComments\n");
        for comment in &overview.comments {
            let marker = if comment["highlighted"].as_bool() == Some(true) {
                "*"
            } else {
                " "
            };
            output.push_str(&format!(
                "{marker} {}  {}  {}\n",
                comment["reference"].as_str().unwrap_or("-"),
                format_show_author(comment),
                comment["created_at"].as_str().unwrap_or("-")
            ));
            output.push_str(&format!(
                "    {}\n",
                comment["summary"].as_str().unwrap_or("No summary")
            ));
        }
        if overview.page.comments_truncated {
            output.push_str("  ... older comments hidden; use --comments N\n");
        }
    }

    if options.show_history && !overview.history.is_empty() {
        output.push_str("\nHistory\n");
        for item in &overview.history {
            output.push_str(&format!(
                "  {}  {}  {}  {}\n",
                item.reference, item.object_type, item.created_at, item.description
            ));
        }
        if overview.page.history_truncated {
            output.push_str("  ... more history hidden; use --limit N\n");
        }
    }

    output.push_str("\nNext\n");
    if !overview.conflicts.is_empty() {
        output.push_str(&format!(
            "  fact resolve {}\n",
            overview.proposition.reference
        ));
    } else if overview.pending.actions.is_empty() {
        output.push_str("  no pending actions for you\n");
    } else {
        for action in &overview.pending.actions {
            output.push_str(&format!(
                "  {}\n",
                action["command"].as_str().unwrap_or("pending action")
            ));
        }
    }

    if options.show_content {
        output.push_str("\nContent\n");
        if let Some(content) = &overview.content {
            output.push_str(&indent_show_content(content));
            if !content.ends_with('\n') {
                output.push('\n');
            }
        }
    }

    output
}

fn indent_show_content(content: &str) -> String {
    content
        .lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
        + if content.ends_with('\n') { "\n" } else { "" }
}

fn format_actor_value(value: &serde_json::Value) -> String {
    value
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(short_uuid)
        .unwrap_or_else(|| "-".to_owned())
}

fn format_show_author(value: &serde_json::Value) -> String {
    if value["author"].is_object() {
        return format_actor_reference_value(&value["author"]);
    }
    format_actor_value(&value["actor_id"])
}

fn format_actor_reference_value(value: &serde_json::Value) -> String {
    let display = value["display_name"].as_str();
    let alias = value["alias"].as_str();
    match (display, alias) {
        (Some(display), Some(alias)) => format!("{display} (@{alias})"),
        (Some(display), None) => display.to_owned(),
        (None, Some(alias)) => format!("@{alias}"),
        (None, None) => value["actor_ref"].as_str().unwrap_or("-").to_owned(),
    }
}

fn format_identity_import_result(
    result: &fact_sdk::workflow::ImportIdentityResult,
    directory: Option<&fact_sdk::workflow::ImportDirectoryResult>,
) -> String {
    let mut lines = vec![format!(
        "imported {} identity object(s); recognition and authority remain separate",
        result.imported
    )];
    if let Some(directory) = directory {
        lines.push(format!(
            "imported {} directory event(s), skipped {} ({} unresolved)",
            directory.imported, directory.skipped, directory.skipped_unresolved
        ));
    }
    if !result.actors.is_empty() {
        lines.push("actors:".to_owned());
        for actor in &result.actors {
            let status = if actor.already_present {
                "already present"
            } else {
                "newly imported"
            };
            let actor_label = match actor.display_name.as_deref() {
                Some(name) => format!("{} ({})", actor.actor_ref, name),
                None => actor.actor_ref.clone(),
            };
            lines.push(format!("  {actor_label}  {status}"));
        }
    }
    lines.join("\n")
}

fn format_directory_entry_show(entry: &fact_sdk::workflow::DirectoryEntry) -> String {
    fn optional(value: Option<&String>) -> &str {
        value.map(String::as_str).unwrap_or("(none)")
    }

    let key_ref = entry.key_ref.as_deref().unwrap_or("(none)");
    let key_id = entry
        .key_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "(none)".to_owned());

    format!(
        "Directory entry: {}\n\n\
Display name:  {}\n\
Alias:         {}\n\
Type:          {}\n\
Role:          {}\n\
Source:        {}\n\
Verified by:   {}\n\n\
Actor:         {}\n\
Actor ID:      {}\n\
Key:           {}\n\
Key ID:        {}\n",
        entry.alias.as_deref().unwrap_or(&entry.actor_ref),
        entry.display_name,
        optional(entry.alias.as_ref()),
        optional(entry.actor_type.as_ref()),
        optional(entry.role.as_ref()),
        optional(entry.source.as_ref()),
        optional(entry.verified_by.as_ref()),
        entry.actor_ref,
        entry.actor_id,
        key_ref,
        key_id,
    )
}

fn print_help(
    command_path: &[String],
    all: bool,
    pager: PagerPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    if !command_path.is_empty() {
        let mut args = Vec::with_capacity(command_path.len() + 2);
        args.push("fact".to_owned());
        args.extend(command_path.iter().cloned());
        args.push("--help".to_owned());
        match Cli::command().try_get_matches_from(args) {
            Ok(_) => {
                return Err(user_error(format!(
                    "unknown command: {}",
                    command_path.join(" ")
                )))
            }
            Err(error) if error.kind() == ErrorKind::DisplayHelp => {
                print!("{error}");
                return Ok(());
            }
            Err(error) => return Err(Box::new(error)),
        }
    }

    if all {
        print_or_page(&expanded_help_text(), pager, true)?;
    } else {
        print_or_page(&Cli::command().render_long_help().to_string(), pager, false)?;
    }
    Ok(())
}

fn expanded_help_text() -> String {
    r#"A simple, adaptable substrate for trusted knowledge.

Usage: fact [OPTIONS] <COMMAND>

Starting and Selecting Ledgers:
  clone           Copy a shared ledger into a local mirror
  from            Register an existing ledger database as read-only
  here            Initialize project-local Fact configuration
  init            Start a new local ledger for your facts
  new             Create a new local ledger without switching to it
  status          Show which local ledger is active
  use             Switch the ledger used by everyday commands

Propositions:
  echo            Print the current effective text of a proposition
  export          Save a proposition's current text to a file
  find            Find accepted propositions and optionally use one
  import          Create a proposition from Markdown, optionally deciding it immediately
  list            List propositions and their current status
  open            Display the current effective text of a proposition
  propose         Add a new proposition, optionally deciding it immediately
  search          Find propositions containing matching words
  show            Show an overview of a proposition and its related state

Revisions and History:
  archive         Archive a proposition while keeping its history
  history         Show the history of a proposition and its revisions
  revise          Create a new revision of a proposition
  revisions       List the revisions of a proposition
  withdraw        Withdraw a proposition while keeping its history

Discussion and Decisions:
  accept          Mark a proposition as accepted
  comment         Add a comment to a proposition or its discussion
  comments        List comments attached to a proposition or revision
  invite          Invite someone to join a proposition's discussion
  join            Join a discussion using an invitation
  leave           Leave a proposition's discussion
  pending         List propositions that still need a decision
  reject          Mark a proposition as rejected

Conflicts and Reconciliation:
  conflicts       List proposition revision conflicts
  reconcile       Create and inspect reconciliation propositions
  resolve         Resolve a proposition revision conflict

Organization:
  tags            Show, change, and search proposition tags

Identity and Directory:
  as              Create or switch the active user for the current ledger
  capabilities    List grantable permission capabilities
  directory       Manage ledger-scoped friendly identity directory entries
  identity        Manage local identity keys and authority records
  permission      Grant or remove permission to perform ledger actions
  persona         Manage reusable local signing personas
  profile         Manage reusable local actor profile metadata

Sync and Remotes:
  pull            Bring ledger data into a local ledger or file
  push            Send local ledger data to a file or configured remote
  remote          Manage the remotes saved in this local environment

Protocol and Administration:
  commitment      Build and verify compact object commitments
  conformance     Run implementation conformance checks
  decision        Record a participant decision
  deliberation    Inspect and manage formal discussions
  http            Run and administer a Facts HTTP collaboration server
  ledger          Manage local ledgers and configuration
  object          Validate, import, and export signed protocol objects
  proof           Add or remove objects from commitment proofs
  proposition     Inspect signed proposition objects
  query           Run low-level ledger searches
  settlement      Verify a completed settlement
  state           Rebuild local read models
  sync            Exchange ledger bundles with files or remotes

Options:
      --json     Print JSON for scripts and other programs
  -h, --help     Print help
  -V, --version  Print version

More:
  fact help COMMAND        Show help for one command
  fact COMMAND --help      Show help for one command
"#
    .to_owned()
}

fn validate_find_with_command(command_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if command_name.trim().is_empty() || command_name.split_whitespace().count() != 1 {
        return Err("--with accepts one command name, such as echo or revisions".into());
    }
    let command = Cli::command()
        .find_subcommand(command_name)
        .ok_or_else(|| format!("unknown command for --with: {command_name}"))?
        .clone();
    let first_positional = command
        .get_positionals()
        .next()
        .map(|arg| arg.get_id().as_str())
        .unwrap_or_default();
    if matches!(first_positional, "reference" | "proposition") {
        Ok(())
    } else {
        Err(format!(
            "--with command {command_name:?} must take a proposition reference as its first argument"
        )
        .into())
    }
}

fn forward_cli_command<I, S>(json: bool, args: I) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = ProcessCommand::new(std::env::current_exe()?);
    if json {
        command.arg("--json");
    }
    for arg in args {
        command.arg(arg.as_ref());
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("forwarded command exited with {status}").into())
    }
}

fn forward_cli_command_passthrough<I, S>(
    json: bool,
    args: I,
) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = ProcessCommand::new(std::env::current_exe()?);
    if json {
        command.arg("--json");
    }
    for arg in args {
        command.arg(arg.as_ref());
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[derive(Clone, Debug)]
struct ConfiguredRemote {
    url: String,
    ledger: Option<String>,
    genesis_hash: Option<String>,
    bearer_token: Option<String>,
}

#[derive(Clone, Debug)]
struct AddedRemote {
    name: String,
    url: String,
    ledger: Option<String>,
    scope: String,
}

#[derive(Clone, Debug)]
struct CloneSource {
    url: String,
    name_source: String,
    remote_name: Option<String>,
    ledger: Option<String>,
    genesis_hash: Option<String>,
    bearer_token: Option<String>,
    actor: Option<String>,
    claims: Option<actor_exchange::ActorClaims>,
    is_remote_url: bool,
    from_descriptor: bool,
}

#[derive(Clone, Debug)]
struct RemoteDescriptor {
    url: String,
    ledger_id: String,
    genesis_hash: String,
    token: Option<String>,
    namespace: Option<String>,
    actor: Option<String>,
    claims: Option<actor_exchange::ActorClaims>,
}

#[derive(Clone, Debug)]
struct RemoteLedgerMetadata {
    ledger_id: String,
    genesis_hash: Option<String>,
    namespace: Option<String>,
}

fn clone_source_from_args(
    environment: &UserEnvironment,
    source: Option<String>,
    remote: Option<String>,
    descriptor: Option<PathBuf>,
) -> Result<CloneSource, Box<dyn std::error::Error>> {
    match (source, remote, descriptor) {
        (Some(source), None, None) => {
            let matched_remote = if environment::is_remote_url(&source) {
                matching_remote(environment, &source)?
            } else {
                None
            };
            Ok(CloneSource {
                is_remote_url: environment::is_remote_url(&source),
                name_source: source.clone(),
                url: source,
                remote_name: matched_remote.as_ref().map(|remote| remote.name.clone()),
                ledger: matched_remote
                    .as_ref()
                    .and_then(|remote| remote.ledger.clone()),
                genesis_hash: matched_remote
                    .as_ref()
                    .and_then(|remote| remote.genesis_hash.clone()),
                bearer_token: matched_remote.and_then(|remote| remote.bearer_token),
                actor: None,
                claims: None,
                from_descriptor: false,
            })
        }
        (None, Some(remote_name), None) => {
            let remote = configured_remote(environment, Some(&remote_name))?;
            Ok(CloneSource {
                url: remote.url,
                name_source: remote_name.clone(),
                remote_name: Some(remote_name),
                ledger: remote.ledger,
                genesis_hash: remote.genesis_hash,
                bearer_token: remote.bearer_token,
                actor: None,
                claims: None,
                is_remote_url: true,
                from_descriptor: false,
            })
        }
        (None, None, Some(path)) => {
            let descriptor = read_remote_descriptor(&path)?;
            validate_remote_descriptor(&descriptor)?;
            verify_remote_descriptor(&descriptor)?;
            let remote_name = derive_remote_descriptor_name(&descriptor);
            let actor = descriptor.actor.clone();
            let claims = descriptor.claims.clone();
            let remote = save_remote_descriptor(environment, descriptor, Some(remote_name))?;
            Ok(CloneSource {
                url: remote.url,
                name_source: remote.name.clone(),
                remote_name: Some(remote.name),
                ledger: remote.ledger,
                genesis_hash: remote.genesis_hash,
                bearer_token: remote.bearer_token,
                actor,
                claims,
                is_remote_url: true,
                from_descriptor: true,
            })
        }
        (None, None, None) => {
            Err("fact clone requires SOURCE, --remote NAME, or --from FILE".into())
        }
        _ => Err("fact clone accepts only one of SOURCE, --remote NAME, or --from FILE".into()),
    }
}

fn configured_remote(
    environment: &UserEnvironment,
    requested: Option<&str>,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    let remotes = environment.load_remotes()?;
    if let Some(requested) = requested {
        return Ok(remotes
            .get(requested)
            .map(|remote| ConfiguredRemote {
                url: remote.url.clone(),
                ledger: remote.ledger.clone(),
                genesis_hash: remote.genesis_hash.clone(),
                bearer_token: remote.bearer_token.clone(),
            })
            .unwrap_or_else(|| ConfiguredRemote {
                url: requested.to_owned(),
                ledger: None,
                genesis_hash: None,
                bearer_token: None,
            }));
    }
    match remotes.values().collect::<Vec<_>>().as_slice() {
        [remote] => Ok(ConfiguredRemote {
            url: remote.url.clone(),
            ledger: remote.ledger.clone(),
            genesis_hash: remote.genesis_hash.clone(),
            bearer_token: remote.bearer_token.clone(),
        }),
        [] => Err("no remote is configured; add one with fact ledger remote add NAME URL".into()),
        _ => Err("multiple remotes are configured; pass --remote NAME or URL".into()),
    }
}

fn matching_remote(
    environment: &UserEnvironment,
    url: &str,
) -> Result<Option<fact_sdk::environment::RemoteEntry>, Box<dyn std::error::Error>> {
    Ok(environment
        .load_remotes()?
        .into_values()
        .find(|remote| same_remote_url(&remote.url, url)))
}

fn same_remote_url(left: &str, right: &str) -> bool {
    left.trim_end_matches('/') == right.trim_end_matches('/')
}

fn configured_remote_for_ledger(
    environment: &UserEnvironment,
    requested: Option<&str>,
    entry: &LedgerEntry,
) -> Result<ConfiguredRemote, Box<dyn std::error::Error>> {
    if let Some(requested) = requested {
        let remote = configured_remote(environment, Some(requested))?;
        if let Some(ledger) = &remote.ledger {
            if ledger != &entry.ledger_id {
                return Err(format!(
                    "remote {requested} points to ledger {ledger}, not active ledger {}",
                    entry.ledger_id
                )
                .into());
            }
        }
        return Ok(remote);
    }

    let remotes = environment.load_remotes()?;
    let matches = remotes
        .values()
        .filter(|remote| remote.ledger.as_deref() == Some(entry.ledger_id.as_str()))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [remote] => Ok(configured_remote_from_entry(remote)),
        [] => match remotes.values().collect::<Vec<_>>().as_slice() {
            [remote] if remote.ledger.is_none() => Ok(configured_remote_from_entry(remote)),
            [] => Err("no remote is configured; add one with fact remote add NAME URL".into()),
            _ => Err(format!(
                "no remote is configured for ledger {}; pass --remote NAME or add a ledger-scoped remote",
                entry.ledger_id
            )
            .into()),
        },
        _ => Err(format!(
            "multiple remotes are configured for ledger {}; pass --remote NAME",
            entry.ledger_id
        )
        .into()),
    }
}

fn configured_remote_from_entry(remote: &fact_sdk::environment::RemoteEntry) -> ConfiguredRemote {
    ConfiguredRemote {
        url: remote.url.clone(),
        ledger: remote.ledger.clone(),
        genesis_hash: remote.genesis_hash.clone(),
        bearer_token: remote.bearer_token.clone(),
    }
}

fn scoped_remotes<'a, I>(remotes: I, ledger: &str) -> Vec<&'a fact_sdk::environment::RemoteEntry>
where
    I: IntoIterator<Item = &'a fact_sdk::environment::RemoteEntry>,
{
    remotes
        .into_iter()
        .filter(|remote| remote.ledger.as_deref() == Some(ledger))
        .collect()
}

fn print_remote(remote: &fact_sdk::environment::RemoteEntry) {
    match &remote.ledger {
        Some(ledger) => match &remote.genesis_hash {
            Some(genesis_hash) => println!(
                "{}  {}  {}  {}",
                remote.name, remote.url, ledger, genesis_hash
            ),
            None => println!("{}  {}  {}", remote.name, remote.url, ledger),
        },
        None => println!("{}  {}", remote.name, remote.url),
    }
}

fn configure_remote_from_descriptor(
    environment: &UserEnvironment,
    file: &Path,
    name: Option<&str>,
) -> Result<fact_sdk::environment::RemoteEntry, Box<dyn std::error::Error>> {
    let descriptor = read_remote_descriptor(file)?;
    validate_remote_descriptor(&descriptor)?;
    verify_remote_descriptor(&descriptor)?;
    save_remote_descriptor(environment, descriptor, name.map(str::to_owned))
}

fn save_remote_descriptor(
    environment: &UserEnvironment,
    descriptor: RemoteDescriptor,
    name: Option<String>,
) -> Result<fact_sdk::environment::RemoteEntry, Box<dyn std::error::Error>> {
    let name = name.unwrap_or_else(|| derive_remote_descriptor_name(&descriptor));
    if !portable_name(&name) {
        return Err(user_error(format!("invalid remote name: {name}")));
    }
    let mut remotes = environment.load_remotes()?;
    let entry = fact_sdk::environment::RemoteEntry {
        name: name.clone(),
        url: descriptor.url,
        ledger: Some(descriptor.ledger_id),
        genesis_hash: Some(descriptor.genesis_hash),
        bearer_token: descriptor.token,
    };
    remotes.insert(name, entry.clone());
    environment.save_remotes(&remotes)?;
    Ok(entry)
}

fn read_remote_descriptor(file: &Path) -> Result<RemoteDescriptor, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(file)?)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| user_error("remote descriptor is missing its format marker"))?;
    let (descriptor, namespace, actor, claims) = match schema {
        "fact-remote-v0" => (value, None, None, None),
        "fact-remote-actor-response-v0" => {
            verify_remote_actor_response_grants(&value)?;
            let namespace = value
                .get("ledger")
                .and_then(|ledger| ledger.get("namespace"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let actor = value
                .get("actor")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let claims = value
                .get("claims")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?;
            let endpoint = value
                .get("endpoint")
                .cloned()
                .ok_or_else(|| user_error("remote actor response is missing endpoint"))?;
            (endpoint, namespace, actor, claims)
        }
        _ => return Err(user_error("unsupported remote descriptor format")),
    };
    let schema = descriptor
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| user_error("remote descriptor endpoint is missing its format marker"))?;
    if schema != "fact-remote-v0" {
        return Err(user_error("unsupported remote descriptor endpoint format"));
    }
    Ok(RemoteDescriptor {
        url: required_string(&descriptor, "url")?.to_owned(),
        ledger_id: required_string(&descriptor, "ledger_id")?.to_owned(),
        genesis_hash: required_string(&descriptor, "genesis_hash")?.to_owned(),
        token: descriptor
            .get("token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        namespace,
        actor,
        claims,
    })
}

fn required_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| user_error(format!("remote descriptor is missing {field}")))
}

fn validate_remote_descriptor(
    descriptor: &RemoteDescriptor,
) -> Result<(), Box<dyn std::error::Error>> {
    if !descriptor.url.starts_with("http://") && !descriptor.url.starts_with("https://") {
        return Err(user_error(
            "remote descriptor URL must use http:// or https://",
        ));
    }
    parse_uuid7(&descriptor.ledger_id, "ledger")?;
    parse_sha256_hex(&descriptor.genesis_hash, "genesis_hash")?;
    Ok(())
}

fn parse_sha256_hex(value: &str, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    fact_core::Hash::from_str(value)
        .map(|_| ())
        .map_err(|_| user_error(format!("{field} must be a lowercase SHA-256 hex hash")))
}

fn verify_remote_descriptor(
    descriptor: &RemoteDescriptor,
) -> Result<(), Box<dyn std::error::Error>> {
    let ledgers = discover_remote_ledger_metadata(&descriptor.url)?.ok_or_else(|| {
        user_error("remote descriptor could not be verified: remote ledger discovery failed")
    })?;
    let Some(served) = ledgers
        .iter()
        .find(|ledger| ledger.ledger_id == descriptor.ledger_id)
    else {
        return Err(user_error(format!(
            "remote descriptor mismatch: remote does not serve ledger {}; served ledger(s): {}",
            descriptor.ledger_id,
            ledgers
                .iter()
                .map(|ledger| ledger.ledger_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    match &served.genesis_hash {
        Some(genesis_hash) if genesis_hash == &descriptor.genesis_hash => Ok(()),
        Some(genesis_hash) => Err(user_error(format!(
            "remote descriptor genesis mismatch for ledger {}: descriptor has {}, remote serves {}",
            descriptor.ledger_id, descriptor.genesis_hash, genesis_hash
        ))),
        None => Err(user_error(format!(
            "remote descriptor could not be verified: remote did not report genesis_hash for ledger {}",
            descriptor.ledger_id
        ))),
    }
}

fn verify_remote_actor_response_grants(
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.get("bundle").is_some() {
        let response: actor_exchange::ActorResponse = serde_json::from_value(value.clone())?;
        if !actor_exchange::response_grants_match_bundle(&response).map_err(user_error)? {
            return Err(user_error(
                "remote actor response grant bundle does not match granted capabilities",
            ));
        }
        return Ok(());
    }
    for field in ["signed_grants", "grants"] {
        let Some(items) = value.get(field).and_then(serde_json::Value::as_array) else {
            continue;
        };
        for item in items {
            let encoded = item
                .as_str()
                .or_else(|| item.get("cose_sign1").and_then(serde_json::Value::as_str))
                .ok_or_else(|| user_error(format!("{field} contains an invalid grant payload")))?;
            let bytes = decode_base64url(encoded)
                .ok_or_else(|| user_error(format!("{field} contains invalid base64url")))?;
            fact_crypto::decode_sign1(&bytes)?;
        }
    }
    Ok(())
}

fn derive_remote_descriptor_name(descriptor: &RemoteDescriptor) -> String {
    if let Some(name) = descriptor_namespace_name(descriptor) {
        return name;
    }
    let without_scheme = descriptor
        .url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&descriptor.url);
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or("remote")
        .split('@')
        .next_back()
        .unwrap_or("remote")
        .split(':')
        .next()
        .unwrap_or("remote");
    let mut name = String::new();
    for byte in host.bytes() {
        if byte.is_ascii_alphanumeric() {
            name.push((byte as char).to_ascii_lowercase());
        } else if matches!(byte, b'-' | b'_') {
            name.push(byte as char);
        } else if !name.ends_with('-') {
            name.push('-');
        }
    }
    let name = name.trim_matches('-').to_owned();
    if portable_name(&name) {
        name
    } else {
        format!("remote-{}", ledger_short_reference(&descriptor.ledger_id))
    }
}

fn descriptor_namespace_name(descriptor: &RemoteDescriptor) -> Option<String> {
    let raw = descriptor.namespace.as_ref()?.rsplit('.').next()?;
    let name = portable_name_from_text(raw);
    portable_name(&name).then_some(name)
}

fn portable_name_from_text(value: &str) -> String {
    let mut name = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    name = name.trim_matches('-').to_owned();
    if name.is_empty() {
        "clone".to_owned()
    } else {
        name
    }
}

fn ledger_short_reference(ledger_id: &str) -> String {
    let compact = ledger_id.replace('-', "");
    format!("{}-{}", &compact[..5], &compact[compact.len() - 5..])
}

fn portable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn remote_add_ledger(
    environment: &UserEnvironment,
    url: &str,
    requested: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(ledger) = requested {
        return match environment.resolve_ledger_id(ledger) {
            Ok(ledger_id) => Ok(Some(ledger_id)),
            Err(local_error) => resolve_remote_advertised_ledger(url, ledger)
                .map(Some)
                .map_err(|remote_error| {
                    user_error(format!(
                        "{}; remote lookup also failed: {}",
                        user_facing_error(&local_error),
                        user_facing_error(remote_error.as_ref())
                    ))
                }),
        };
    }
    discover_single_remote_ledger(url)
}

fn resolve_remote_advertised_ledger(
    url: &str,
    requested: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(ledgers) = discover_remote_ledger_metadata(url)? else {
        return Err(user_error("remote ledger discovery failed"));
    };
    let matches = ledgers
        .iter()
        .filter(|ledger| {
            ledger.ledger_id == requested
                || ledger.namespace.as_deref() == Some(requested)
                || ledger_short_reference(&ledger.ledger_id) == requested
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [ledger] => Ok(ledger.ledger_id.clone()),
        [] => Err(user_error(format!(
            "remote does not advertise ledger {requested}; available ledgers: {}",
            remote_ledger_choices(&ledgers)
        ))),
        _ => Err(user_error(format!(
            "remote ledger reference {requested} is ambiguous; available ledgers: {}",
            remote_ledger_choices(&ledgers)
        ))),
    }
}

fn remote_ledger_choices(ledgers: &[RemoteLedgerMetadata]) -> String {
    ledgers
        .iter()
        .map(|ledger| match &ledger.namespace {
            Some(namespace) => format!("{} ({namespace})", ledger.ledger_id),
            None => ledger.ledger_id.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn discover_single_remote_ledger(url: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(ledger_ids) = discover_remote_ledgers(url)? else {
        return Ok(None);
    };
    match ledger_ids.as_slice() {
        [ledger] => Ok(Some(ledger.clone())),
        [] => Ok(None),
        ledgers => Err(format!(
            "remote serves multiple ledgers; pass --ledger with one of: {}",
            ledgers.join(", ")
        )
        .into()),
    }
}

fn discover_remote_ledgers(url: &str) -> Result<Option<Vec<String>>, Box<dyn std::error::Error>> {
    Ok(discover_remote_ledger_metadata(url)?.map(|ledgers| {
        ledgers
            .into_iter()
            .map(|ledger| ledger.ledger_id)
            .collect::<Vec<_>>()
    }))
}

fn discover_remote_ledger_metadata(
    url: &str,
) -> Result<Option<Vec<RemoteLedgerMetadata>>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let endpoint = format!("{}/facts/ledgers", url.trim_end_matches('/'));
    let response = match client.get(endpoint).send() {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let value: serde_json::Value = response.json()?;
    let body = value.get("body").unwrap_or(&value);
    let ledgers = body
        .get("ledgers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| user_error("remote ledger list response did not include ledgers"))?;
    let ledger_ids = ledgers
        .iter()
        .map(|ledger| {
            let ledger_id = ledger
                .get("ledger_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| user_error("remote ledger list entry is missing ledger_id"))?;
            let ledger_id = parse_uuid7(ledger_id, "ledger").map(|ledger| ledger.to_string())?;
            let genesis_hash = ledger
                .get("genesis_hash")
                .and_then(serde_json::Value::as_str)
                .map(|value| parse_sha256_hex(value, "genesis_hash").map(|_| value.to_owned()))
                .transpose()?;
            let namespace = ledger
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            Ok::<RemoteLedgerMetadata, Box<dyn std::error::Error>>(RemoteLedgerMetadata {
                ledger_id,
                genesis_hash,
                namespace,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(ledger_ids))
}

fn validate_remote_serves_ledger(
    remote: &str,
    ledger: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(ledger_ids) = discover_remote_ledgers(remote)? else {
        return Ok(());
    };
    if ledger_ids.is_empty()
        || ledger_ids
            .iter()
            .any(|candidate| candidate == &ledger.to_string())
    {
        return Ok(());
    }
    Err(format!(
        "remote serves ledger(s) {}, not local ledger {}; use `fact clone` to mirror a remote ledger; an empty local ledger cannot be turned into a mirror",
        ledger_ids.join(", "),
        ledger
    )
    .into())
}

fn add_remote_with_ledger(
    environment: &UserEnvironment,
    name: &str,
    url: &str,
    ledger: Option<String>,
) -> Result<AddedRemote, Box<dyn std::error::Error>> {
    let result = environment::add_remote(environment, name, url)?;
    let mut remotes = environment.load_remotes()?;
    if let Some(remote) = remotes.get_mut(name) {
        remote.ledger = ledger.clone();
    }
    environment.save_remotes(&remotes)?;
    Ok(AddedRemote {
        name: result.name,
        url: result.url.unwrap_or_else(|| url.to_owned()),
        ledger,
        scope: result.scope,
    })
}

fn clone_remote_to_create(
    environment: &UserEnvironment,
    name: &str,
    source: &CloneSource,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if !source.is_remote_url || source.remote_name.is_some() {
        return Ok(None);
    }
    let remotes = environment.load_remotes()?;
    if remotes
        .values()
        .any(|remote| same_remote_url(&remote.url, &source.url))
    {
        return Ok(None);
    }
    if remotes.contains_key(name) {
        return Err(format!(
            "remote already exists: {name}; pass --remote NAME to reuse it or choose another clone name"
        )
        .into());
    }
    Ok(Some(name.to_owned()))
}

fn save_clone_remote(
    environment: &UserEnvironment,
    name: &str,
    source: &CloneSource,
    ledger: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remotes = environment.load_remotes()?;
    remotes.insert(
        name.to_owned(),
        fact_sdk::environment::RemoteEntry {
            name: name.to_owned(),
            url: source.url.clone(),
            ledger: Some(ledger.to_owned()),
            genesis_hash: source.genesis_hash.clone(),
            bearer_token: None,
        },
    );
    environment.save_remotes(&remotes)?;
    Ok(())
}

fn record_remote_ledger_if_missing(
    environment: &UserEnvironment,
    name: &str,
    ledger: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remotes = environment.load_remotes()?;
    let Some(remote) = remotes.get_mut(name) else {
        return Ok(());
    };
    if remote.ledger.is_none() {
        remote.ledger = Some(ledger.to_owned());
        environment.save_remotes(&remotes)?;
    }
    Ok(())
}

fn personal_push(
    entry: &LedgerEntry,
    remote: &ConfiguredRemote,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if entry.read_only {
        return Err("cannot push from a read-only ledger".into());
    }
    let bundle = std::env::temp_dir().join(format!(
        "fact-personal-push-{}.bundle",
        uuid::Uuid::now_v7()
    ));
    let database = entry.database.to_string_lossy().into_owned();
    let ledger = entry.ledger_id.clone();
    let bundle_path = bundle.to_string_lossy().into_owned();
    let pull_args = [
        "sync",
        "pull",
        database.as_str(),
        ledger.as_str(),
        bundle_path.as_str(),
    ];
    forward_cli_command(false, pull_args)?;
    let mut push_args = vec![
        "sync".to_owned(),
        "push".to_owned(),
        database,
        bundle_path,
        "--remote".to_owned(),
        remote.url.clone(),
        "--ledger".to_owned(),
        ledger,
    ];
    if let Some(token) = &remote.bearer_token {
        push_args.push("--bearer-token".to_owned());
        push_args.push(token.clone());
    }
    let push_args = push_args.iter().map(String::as_str).collect::<Vec<_>>();
    let result = forward_cli_command(json, push_args);
    let _ = fs::remove_file(&bundle);
    result
}

fn personal_pull(
    entry: &LedgerEntry,
    remote: &ConfiguredRemote,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if entry.read_only {
        return Err("cannot pull into a read-only ledger".into());
    }
    let bundle = std::env::temp_dir().join(format!(
        "fact-personal-pull-{}.bundle",
        uuid::Uuid::now_v7()
    ));
    let database = entry.database.to_string_lossy().into_owned();
    let ledger = entry.ledger_id.clone();
    let bundle_path = bundle.to_string_lossy().into_owned();
    let mut pull_args = vec![
        "sync".to_owned(),
        "pull".to_owned(),
        database.clone(),
        ledger,
        bundle_path.clone(),
        "--remote".to_owned(),
        remote.url.clone(),
    ];
    if let Some(token) = &remote.bearer_token {
        pull_args.push("--bearer-token".to_owned());
        pull_args.push(token.clone());
    }
    let pull_args = pull_args.iter().map(String::as_str).collect::<Vec<_>>();
    forward_cli_command(false, pull_args)?;
    let import_args = ["object", "import", database.as_str(), bundle_path.as_str()];
    let result = forward_cli_command(json, import_args);
    let _ = fs::remove_file(&bundle);
    result
}

#[derive(Subcommand)]
enum LedgerRemoteCommand {
    #[command(about = "List remotes configured for this ledger")]
    List,
    #[command(about = "Add a remote for this ledger")]
    Add {
        #[arg(help = "A short name for the remote")]
        name: String,
        #[arg(help = "The remote ledger service URL")]
        url: String,
    },
    #[command(about = "Remove a ledger remote")]
    Remove {
        #[arg(help = "The configured remote name")]
        name: String,
    },
    #[command(about = "Rename a ledger remote")]
    Rename {
        #[arg(help = "The current remote name")]
        old_name: String,
        #[arg(help = "The new remote name")]
        new_name: String,
    },
}

fn ensure_active_entry(
    environment: &UserEnvironment,
    requested: Option<&str>,
) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
    Ok(environment.resolve(requested)?)
}

fn read_seed_for_write(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    match environment.read_seed(entry) {
        Ok(seed) => Ok(seed),
        Err(fact_sdk::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(user_error(format!(
                "local private key material is missing for ledger {} actor {}; run `fact status` and restore or rotate the identity key",
                entry.name, entry.actor_id
            )))
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_initial_admin_directory_entry(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    require_seed: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    if fact_sdk::workflow::show_directory_entry(entry, &entry.actor_id).is_ok() {
        return Ok(false);
    }
    let seed = match read_seed_for_write(environment, entry) {
        Ok(seed) => seed,
        Err(error) if !require_seed => {
            let _ = error;
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let actor_id = uuid::Uuid::parse_str(&entry.actor_id)?;
    let key_id = uuid::Uuid::parse_str(&entry.key_id)?;
    let default_profile = default_profile(environment)?;
    let persona = if default_profile.is_none() {
        persona_for_actor(environment, &entry.actor_id)?
    } else {
        None
    };
    let (metadata_source, display_name, alias, actor_type, role) =
        if let Some((name, profile)) = default_profile {
            (
                Some(format!("profile:{name}")),
                profile.display_name,
                profile.alias,
                profile.actor_type,
                profile.role.or_else(|| Some("admin".to_owned())),
            )
        } else if let Some((name, persona)) = persona {
            (
                Some(format!("persona:{name}")),
                persona.display_name,
                persona.alias,
                persona.actor_type,
                Some("admin".to_owned()),
            )
        } else {
            (
                Some("fact init".to_owned()),
                "Ledger Admin".to_owned(),
                None,
                "human".to_owned(),
                Some("admin".to_owned()),
            )
        };
    fact_sdk::workflow::add_directory_entry(
        entry,
        &seed,
        fact_sdk::workflow::DirectoryAddInput {
            display_name,
            actor_id: Some(actor_id),
            key_id: Some(key_id),
            alias,
            actor_type: Some(actor_type),
            role,
            source: metadata_source,
            verified_by: Some("genesis".to_owned()),
            with_identity: false,
            seed: None,
        },
    )?;
    Ok(true)
}

fn default_identity_export_file(
    entry: &LedgerEntry,
    actor: Option<uuid::Uuid>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let ledger_segment = if entry.name.is_empty() {
        let ledger_id = uuid::Uuid::parse_str(&entry.ledger_id)?;
        fact_sdk::reference::short_uuid_reference(ledger_id)
    } else {
        entry.name.clone()
    };
    let actor_id = actor
        .map(Ok)
        .unwrap_or_else(|| uuid::Uuid::parse_str(&entry.actor_id))?;
    let actor_segment = fact_sdk::reference::short_uuid_reference(actor_id);

    Ok(PathBuf::from(format!(
        "{ledger_segment}.identity.{actor_segment}.bundle"
    )))
}

fn identity_export_entry_for_actor(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    actor_id: uuid::Uuid,
) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
    let mut scoped = entry.clone();
    scoped.actor_id = actor_id.to_string();
    scoped.seed_file = environment.identity_dir.join(format!("{actor_id}.seed"));
    let store = fact_store::Store::open(&entry.database)?;
    if let Some((_, key_id)) = store.get_actor_key_binding_for_actor(actor_id.as_bytes())? {
        scoped.key_id = key_id.to_string();
    }
    Ok(scoped)
}

fn identity_bundle_actor_values(
    bundle: &[u8],
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let bundle =
        fact_commitment::decode_bundle(bundle).map_err(|error| user_error(error.to_string()))?;
    let mut actors = bundle
        .objects
        .iter()
        .filter_map(|object| {
            let payload = fact_crypto::decode_sign1(object).ok()?.payload;
            let value = serde_json::from_slice::<serde_json::Value>(&payload).ok()?;
            (value.get("object_type").and_then(serde_json::Value::as_str) == Some("actor"))
                .then_some(value)
        })
        .map(|value| {
            let actor_id = value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| uuid::Uuid::parse_str(value).ok())?;
            Some(serde_json::json!({
                "actor_id": actor_id,
                "actor_ref": fact_sdk::reference::short_uuid_reference(actor_id),
            }))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| user_error("identity bundle contains an invalid actor object"))?;
    actors.sort_by_key(|actor| {
        actor["actor_id"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default()
    });
    Ok(actors)
}

struct IdentityImportBundle {
    identity_bundle: Vec<u8>,
    directory_bundle: Option<Vec<u8>>,
}

#[derive(serde::Deserialize)]
struct IdentityExportEnvelope {
    schema: String,
    identity_bundle: String,
    directory_bundle: Option<String>,
}

fn read_identity_import_bundle(
    bytes: &[u8],
) -> Result<IdentityImportBundle, Box<dyn std::error::Error>> {
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Ok(IdentityImportBundle {
            identity_bundle: bytes.to_vec(),
            directory_bundle: None,
        });
    }
    let envelope: IdentityExportEnvelope = serde_json::from_slice(bytes)?;
    if envelope.schema != IDENTITY_EXPORT_SCHEMA {
        return Err(user_error("identity import expected an identity bundle"));
    }
    let identity_bundle = decode_base64url(&envelope.identity_bundle)
        .ok_or_else(|| user_error("identity_bundle contains invalid base64url"))?;
    let directory_bundle = envelope
        .directory_bundle
        .as_deref()
        .map(|value| {
            decode_base64url(value)
                .ok_or_else(|| user_error("directory_bundle contains invalid base64url"))
        })
        .transpose()?;
    Ok(IdentityImportBundle {
        identity_bundle,
        directory_bundle,
    })
}

fn identity_export_bundle_with_directory(
    entry: &LedgerEntry,
    identity_bundle: &[u8],
    actor_ids: &[uuid::Uuid],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let directory = fact_sdk::workflow::export_directory(entry)?;
    let directory_bundle = filter_directory_bundle_for_actors(&directory.bundle, actor_ids)?;
    let Some(directory_bundle) = directory_bundle else {
        return Ok(identity_bundle.to_vec());
    };
    Ok(serde_json::to_vec_pretty(&serde_json::json!({
        "schema": IDENTITY_EXPORT_SCHEMA,
        "identity_bundle": encode_base64url(identity_bundle),
        "directory_bundle": encode_base64url(&directory_bundle),
    }))?)
}

fn filter_directory_bundle_for_actors(
    bundle: &[u8],
    actor_ids: &[uuid::Uuid],
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = serde_json::from_slice(bundle)?;
    let Some(events) = value
        .get_mut("events")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Err(user_error("directory bundle has no events"));
    };
    events.retain(|event| {
        event
            .get("target_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some_and(|actor_id| actor_ids.contains(&actor_id))
    });
    if events.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::to_vec_pretty(&value)?))
}

fn identity_import_result_value(
    result: &fact_sdk::workflow::ImportIdentityResult,
    directory: Option<&fact_sdk::workflow::ImportDirectoryResult>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut value = serde_json::to_value(result)?;
    if let Some(directory) = directory {
        value["directory"] = serde_json::to_value(directory)?;
    }
    Ok(value)
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = bytes.get(index + 1).copied().unwrap_or(0);
        let b2 = bytes.get(index + 2).copied().unwrap_or(0);
        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if index + 1 < bytes.len() {
            output.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if index + 2 < bytes.len() {
            output.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
        index += 3;
    }
    output
}

mod fact_as {
    use super::*;

    pub struct Input {
        pub name: Option<String>,
        pub alias: Option<String>,
        pub self_actor: bool,
        pub actor_type: Option<String>,
        pub profile: Option<String>,
        pub role: Option<String>,
        pub source: Option<String>,
        pub verified_by: Option<String>,
        pub home: Option<Option<PathBuf>>,
        pub print_env: bool,
        pub use_home: bool,
        pub permission: Vec<String>,
        pub participate: bool,
        pub no_create: bool,
        pub update_directory: bool,
        pub ledger: Option<String>,
    }

    pub fn run(input: Input) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let environment = UserEnvironment::discover()?;
        let mut entry = match input.ledger.as_deref() {
            Some(ledger) => environment.resolve(Some(ledger))?,
            None => {
                let ledger_name = selected_ledger_name(&environment, None)?;
                environment.resolve(Some(&ledger_name))?
            }
        };
        let ledger_name = entry.name.clone();
        if reports_current_signer(&input) {
            return current_signer_value(&environment, &ledger_name, &entry);
        }
        let mut created_identity = false;
        let mut created_directory_entry = false;
        let mut updated_directory_entry = false;
        let mut switched = false;
        let mut permission_grants = Vec::new();
        let permissions =
            expanded_optional_capabilities(input.permission.clone(), input.participate);
        validate_capabilities(&permissions)?;
        if !permissions.is_empty() {
            ensure_can_grant_permissions(&entry)?;
        }
        let profile = input
            .profile
            .as_deref()
            .map(|name| named_profile(&environment, name).map(|profile| (name.to_owned(), profile)))
            .transpose()?;
        let profile_ref = profile
            .as_ref()
            .map(|(name, profile)| (name.as_str(), profile));

        let outcome = if input.self_actor {
            let display_name = input
                .name
                .clone()
                .or_else(|| profile_ref.map(|(_, profile)| profile.display_name.clone()))
                .ok_or_else(|| user_error("fact as --self requires a display name"))?;
            let alias = input
                .alias
                .clone()
                .or_else(|| profile_ref.and_then(|(_, profile)| profile.alias.clone()))
                .or_else(|| profile_ref.map(|(name, _)| name.to_owned()))
                .ok_or_else(|| user_error("fact as --self requires --alias"))?;
            if input.home.is_some() {
                return Err(user_error("--self does not create actor homes"));
            }
            if !permissions.is_empty() {
                return Err(user_error("--self does not grant permissions"));
            }
            let seed = read_seed_for_write(&environment, &entry)?;
            let actor_id = uuid::Uuid::parse_str(&entry.actor_id)?;
            let key_id = uuid::Uuid::parse_str(&entry.key_id)?;
            let existing = resolve_existing(&entry, &alias)?;
            if let Some(existing) = &existing {
                if existing.actor_id != actor_id {
                    return Err(user_error(format!(
                        "alias {alias} already belongs to {}",
                        existing.actor_ref
                    )));
                }
            }
            let current =
                fact_sdk::workflow::show_directory_entry(&entry, &actor_id.to_string()).ok();
            let result = fact_sdk::workflow::add_directory_entry(
                &entry,
                &seed,
                fact_sdk::workflow::DirectoryAddInput {
                    display_name,
                    actor_id: Some(actor_id),
                    key_id: Some(key_id),
                    alias: Some(alias),
                    actor_type: input
                        .actor_type
                        .or_else(|| profile_ref.map(|(_, profile)| profile.actor_type.clone()))
                        .or_else(|| current.as_ref().and_then(|entry| entry.actor_type.clone()))
                        .or_else(|| Some("human".to_owned())),
                    role: input
                        .role
                        .or_else(|| profile_ref.and_then(|(_, profile)| profile.role.clone()))
                        .or_else(|| current.as_ref().and_then(|entry| entry.role.clone())),
                    source: input
                        .source
                        .or_else(|| profile_ref.map(|(name, _)| format!("profile:{name}")))
                        .or_else(|| current.as_ref().and_then(|entry| entry.source.clone())),
                    verified_by: input
                        .verified_by
                        .or_else(|| current.as_ref().and_then(|entry| entry.verified_by.clone())),
                    with_identity: false,
                    seed: None,
                },
            )?;
            created_directory_entry = existing.is_none();
            updated_directory_entry = existing.is_some();
            ActorOutcome {
                display_name: result.display_name,
                actor_id: result.actor_id,
                key_id: result
                    .key_id
                    .ok_or_else(|| user_error("current identity has no signing key"))?,
                alias: result.alias,
                actor_type: result.actor_type,
                seed_file: entry.seed_file.clone(),
                self_mode: true,
            }
        } else {
            let (display_name, alias, alias_only) = requested_actor(&input, profile_ref)?;
            let existing = resolve_existing(&entry, &alias)?;
            if let Some(existing) = existing {
                if let Some(display_name) = &display_name {
                    if existing.display_name != *display_name && !input.update_directory {
                        return Err(user_error(format!(
                            "alias {alias} already uses display name {}; pass --update-directory to change it",
                            existing.display_name
                        )));
                    }
                    if let Some(actor_type) = &input.actor_type {
                        if existing.actor_type.as_deref() != Some(actor_type.as_str())
                            && !input.update_directory
                        {
                            return Err(user_error(format!(
                                "alias {alias} already uses actor type {}; pass --update-directory to change it",
                                existing.actor_type.as_deref().unwrap_or("unknown")
                            )));
                        }
                    }
                }
                let key_id = existing
                    .key_id
                    .ok_or_else(|| user_error("directory entry has no signing key"))?;
                let seed_file = local_seed_file(&environment, &entry, existing.actor_id, key_id)?;
                if !permissions.is_empty() {
                    let seed = read_seed_for_write(&environment, &entry)?;
                    let grant = fact_sdk::workflow::create_identity_grant(
                        &entry,
                        &seed,
                        &existing.actor_id.to_string(),
                        &permissions,
                    )?;
                    permission_grants.push(serde_json::to_value(grant)?);
                }
                if input.update_directory && display_name.is_some() {
                    let seed = read_seed_for_write(&environment, &entry)?;
                    let current = fact_sdk::workflow::show_directory_entry(
                        &entry,
                        &existing.actor_id.to_string(),
                    )
                    .ok();
                    let result = fact_sdk::workflow::add_directory_entry(
                        &entry,
                        &seed,
                        fact_sdk::workflow::DirectoryAddInput {
                            display_name: display_name.clone().unwrap_or(existing.display_name),
                            actor_id: Some(existing.actor_id),
                            key_id: Some(key_id),
                            alias: Some(alias.clone()),
                            actor_type: input.actor_type.clone().or_else(|| {
                                profile_ref
                                    .map(|(_, profile)| profile.actor_type.clone())
                                    .or_else(|| {
                                        current.as_ref().and_then(|entry| entry.actor_type.clone())
                                    })
                            }),
                            role: input
                                .role
                                .clone()
                                .or_else(|| {
                                    profile_ref.and_then(|(_, profile)| profile.role.clone())
                                })
                                .or_else(|| current.as_ref().and_then(|entry| entry.role.clone())),
                            source: input.source.clone().or_else(|| {
                                profile_ref
                                    .map(|(name, _)| format!("profile:{name}"))
                                    .or_else(|| {
                                        current.as_ref().and_then(|entry| entry.source.clone())
                                    })
                            }),
                            verified_by: input.verified_by.clone().or_else(|| {
                                current.as_ref().and_then(|entry| entry.verified_by.clone())
                            }),
                            with_identity: false,
                            seed: None,
                        },
                    )?;
                    updated_directory_entry = true;
                    ActorOutcome {
                        display_name: result.display_name,
                        actor_id: result.actor_id,
                        key_id,
                        alias: result.alias,
                        actor_type: result.actor_type,
                        seed_file,
                        self_mode: false,
                    }
                } else {
                    ActorOutcome {
                        display_name: existing.display_name,
                        actor_id: existing.actor_id,
                        key_id,
                        alias: existing.alias.or(Some(alias)),
                        actor_type: existing.actor_type,
                        seed_file,
                        self_mode: false,
                    }
                }
            } else {
                if input.no_create || alias_only {
                    return Err(user_error(format!("directory alias not found: {alias}")));
                }
                let display_name = display_name
                    .ok_or_else(|| user_error("creating an identity requires a display name"))?;
                let seed = read_seed_for_write(&environment, &entry)?;
                let result = fact_sdk::workflow::add_directory_entry(
                    &entry,
                    &seed,
                    fact_sdk::workflow::DirectoryAddInput {
                        display_name,
                        actor_id: None,
                        key_id: None,
                        alias: Some(alias.clone()),
                        actor_type: Some(
                            input
                                .actor_type
                                .clone()
                                .or_else(|| {
                                    profile_ref.map(|(_, profile)| profile.actor_type.clone())
                                })
                                .unwrap_or_else(|| "human".to_owned()),
                        ),
                        role: input
                            .role
                            .clone()
                            .or_else(|| profile_ref.and_then(|(_, profile)| profile.role.clone())),
                        source: input
                            .source
                            .clone()
                            .or_else(|| profile_ref.map(|(name, _)| format!("profile:{name}"))),
                        verified_by: input.verified_by.clone(),
                        with_identity: true,
                        seed: None,
                    },
                )?;
                let identity_seed = result.seed.ok_or_else(|| {
                    user_error("identity creation did not return private key material")
                })?;
                let seed_file = environment
                    .identity_dir
                    .join(format!("{}.seed", result.actor_id));
                environment.write_seed(&seed_file, &identity_seed)?;
                if !permissions.is_empty() {
                    let grant = fact_sdk::workflow::create_identity_grant(
                        &entry,
                        &seed,
                        &result.actor_id.to_string(),
                        &permissions,
                    )?;
                    permission_grants.push(serde_json::to_value(grant)?);
                }
                created_identity = true;
                created_directory_entry = true;
                ActorOutcome {
                    display_name: result.display_name,
                    actor_id: result.actor_id,
                    key_id: result
                        .key_id
                        .ok_or_else(|| user_error("new identity has no signing key"))?,
                    alias: result.alias,
                    actor_type: result.actor_type,
                    seed_file,
                    self_mode: false,
                }
            }
        };

        if !outcome.self_mode {
            if switching_from_only_admin(&entry, outcome.actor_id)? {
                eprintln!(
                    "warning: switching away from the only actor with admin capability in this ledger"
                );
            }
            entry = switch_actor(&environment, &ledger_name, entry, &outcome)?;
            switched = true;
        }

        let home_value = if let Some(home) = input.home {
            let path = match home {
                Some(path) => path,
                None => {
                    derived_actor_home(&environment, outcome.alias.as_deref().unwrap_or("actor"))
                }
            };
            let prepared = prepare_actor_home(&environment, &path, &ledger_name, &entry, &outcome)?;
            if input.use_home {
                let actor_home = UserEnvironment::from_root(prepared.path.clone());
                let _ = actor_home.resolve(Some(&ledger_name))?;
            }
            Some(serde_json::json!({
                "path":prepared.path,
                "created":prepared.created,
                "print_env":if input.print_env {
                    Some(format!("export FACT_HOME={}", shell_escape(&prepared.path)))
                } else {
                    None
                }
            }))
        } else {
            None
        };

        Ok(serde_json::json!({
            "switched":switched,
            "self":outcome.self_mode,
            "created_identity":created_identity,
            "created_directory_entry":created_directory_entry,
            "updated_directory_entry":updated_directory_entry,
            "created_home":home_value.as_ref().and_then(|home| home.get("created")).and_then(|value| value.as_bool()).unwrap_or(false),
            "created_permission_grants":permission_grants,
            "ledger":{
                "name":ledger_name,
                "ledger_id":entry.ledger_id,
                "database":entry.database
            },
            "actor":{
                "actor_id":outcome.actor_id,
                "actor_ref":fact_sdk::reference::short_uuid_reference(outcome.actor_id),
                "key_id":outcome.key_id,
                "key_ref":fact_sdk::reference::short_uuid_reference(outcome.key_id),
                "alias":outcome.alias,
                "display_name":outcome.display_name,
                "type":outcome.actor_type
            },
            "home":home_value
        }))
    }

    fn reports_current_signer(input: &Input) -> bool {
        input.name.is_none()
            && input.alias.is_none()
            && !input.self_actor
            && input.actor_type.is_none()
            && input.profile.is_none()
            && input.role.is_none()
            && input.source.is_none()
            && input.verified_by.is_none()
            && input.home.is_none()
            && !input.print_env
            && !input.use_home
            && input.permission.is_empty()
            && !input.participate
            && !input.no_create
            && !input.update_directory
    }

    fn current_signer_value(
        environment: &UserEnvironment,
        ledger_name: &str,
        entry: &LedgerEntry,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        if entry.actor_id.is_empty() || entry.key_id.is_empty() {
            return Ok(serde_json::json!({
                "report":true,
                "switched":false,
                "self":false,
                "created_identity":false,
                "created_directory_entry":false,
                "updated_directory_entry":false,
                "created_home":false,
                "created_permission_grants":[],
                "ledger":{
                    "name":ledger_name,
                    "ledger_id":entry.ledger_id,
                    "database":entry.database,
                    "read_only":entry.read_only
                },
                "actor":null,
                "no_current_signer":true,
                "home":null
            }));
        }
        let actor_id = uuid::Uuid::parse_str(&entry.actor_id)?;
        let key_id = uuid::Uuid::parse_str(&entry.key_id)?;
        let directory =
            fact_sdk::workflow::resolve_directory_reference(entry, &entry.actor_id).ok();
        let display_name = directory
            .as_ref()
            .map(|entry| entry.display_name.clone())
            .unwrap_or_else(|| {
                format!(
                    "actor {}",
                    fact_sdk::reference::short_uuid_reference(actor_id)
                )
            });
        let local_private_key_material =
            local_seed_file(environment, entry, actor_id, key_id).is_ok();
        Ok(serde_json::json!({
            "report":true,
            "switched":false,
            "self":false,
            "created_identity":false,
            "created_directory_entry":false,
            "updated_directory_entry":false,
            "created_home":false,
            "created_permission_grants":[],
            "ledger":{
                "name":ledger_name,
                "ledger_id":entry.ledger_id,
                "database":entry.database,
                "read_only":entry.read_only
            },
            "actor":{
                "actor_id":actor_id,
                "actor_ref":fact_sdk::reference::short_uuid_reference(actor_id),
                "key_id":key_id,
                "key_ref":fact_sdk::reference::short_uuid_reference(key_id),
                "alias":directory.as_ref().and_then(|entry| entry.alias.clone()),
                "display_name":display_name,
                "type":directory.as_ref().and_then(|entry| entry.actor_type.clone()),
                "local_private_key_material":local_private_key_material
            },
            "home":null
        }))
    }

    struct ActorOutcome {
        display_name: String,
        actor_id: uuid::Uuid,
        key_id: uuid::Uuid,
        alias: Option<String>,
        actor_type: Option<String>,
        seed_file: PathBuf,
        self_mode: bool,
    }

    struct PreparedHome {
        path: PathBuf,
        created: bool,
    }

    fn selected_ledger_name(
        environment: &UserEnvironment,
        requested: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(requested) = requested {
            return Ok(requested.to_owned());
        }
        environment
            .active_name()?
            .ok_or_else(|| user_error("no active ledger; run `fact init`"))
    }

    fn requested_actor(
        input: &Input,
        profile: Option<(&str, &ActorProfile)>,
    ) -> Result<(Option<String>, String, bool), Box<dyn std::error::Error>> {
        if let Some((profile_name, profile)) = profile {
            let display_name = input
                .name
                .clone()
                .unwrap_or_else(|| profile.display_name.clone());
            let alias = input
                .alias
                .clone()
                .or_else(|| profile.alias.clone())
                .unwrap_or_else(|| profile_name.to_owned());
            return Ok((Some(display_name), alias, false));
        }
        match (input.name.clone(), input.alias.clone()) {
            (Some(name), Some(alias)) => Ok((Some(name), alias, false)),
            (Some(alias), None) => Ok((None, alias, true)),
            (None, Some(alias)) => Ok((None, alias, true)),
            (None, None) => Err(user_error(
                "fact as requires an alias or display name with --alias",
            )),
        }
    }

    fn resolve_existing(
        entry: &LedgerEntry,
        alias: &str,
    ) -> Result<Option<fact_sdk::workflow::DirectoryResolveResult>, Box<dyn std::error::Error>>
    {
        match fact_sdk::workflow::resolve_directory_reference(entry, alias) {
            Ok(value) => Ok(Some(value)),
            Err(fact_sdk::Error::MissingObject(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn local_seed_file(
        environment: &UserEnvironment,
        entry: &LedgerEntry,
        actor_id: uuid::Uuid,
        key_id: uuid::Uuid,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let candidates = [
            (entry.actor_id == actor_id.to_string()).then_some(entry.seed_file.clone()),
            Some(environment.identity_dir.join(format!("{actor_id}.seed"))),
            Some(environment.identity_dir.join(format!("{key_id}.seed"))),
        ];
        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(user_error(format!(
            "local private key material is not available for {actor_id}"
        )))
    }

    fn ensure_can_grant_permissions(entry: &LedgerEntry) -> Result<(), Box<dyn std::error::Error>> {
        let has_admin = held_capabilities(entry)?
            .iter()
            .any(|capability| capability.name == "admin");
        if has_admin {
            Ok(())
        } else {
            Err(user_error(
                "your current identity does not have permission to do that in this ledger",
            ))
        }
    }

    fn switching_from_only_admin(
        entry: &LedgerEntry,
        next_actor: uuid::Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let current_actor = uuid::Uuid::parse_str(&entry.actor_id)?;
        if current_actor == next_actor {
            return Ok(false);
        }
        let store = fact_store::Store::open(&entry.database)?;
        let admins = store
            .list_identity_objects()?
            .into_iter()
            .filter(|(_, _, object_type)| object_type == "actor")
            .filter_map(|(actor_id, _, _)| {
                actor_capabilities_in_store(&store, entry, actor_id)
                    .ok()
                    .is_some_and(|capabilities| {
                        capabilities.iter().any(|capability| capability == "admin")
                    })
                    .then_some(actor_id)
            })
            .collect::<Vec<_>>();
        Ok(admins.as_slice() == [current_actor])
    }

    fn switch_actor(
        environment: &UserEnvironment,
        ledger_name: &str,
        entry: LedgerEntry,
        outcome: &ActorOutcome,
    ) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
        let mut entries = environment.load()?;
        let updated = LedgerEntry {
            actor_id: outcome.actor_id.to_string(),
            key_id: outcome.key_id.to_string(),
            seed_file: outcome.seed_file.clone(),
            ..entry
        };
        entries.insert(ledger_name.to_owned(), updated.clone());
        environment.save(&entries)?;
        Ok(updated)
    }

    fn prepare_actor_home(
        source: &UserEnvironment,
        requested_path: &Path,
        ledger_name: &str,
        entry: &LedgerEntry,
        outcome: &ActorOutcome,
    ) -> Result<PreparedHome, Box<dyn std::error::Error>> {
        let path = absolute_path(requested_path)?;
        let created = !path.exists();
        let actor_home = UserEnvironment::from_root(path.clone());
        actor_home.ensure_dirs()?;
        let seed = read_seed_file(&outcome.seed_file)?;
        let seed_file = actor_home
            .identity_dir
            .join(format!("{}.seed", outcome.actor_id));
        actor_home.write_seed(&seed_file, &seed)?;
        let mut entries = actor_home.load()?;
        entries.insert(
            ledger_name.to_owned(),
            LedgerEntry {
                name: ledger_name.to_owned(),
                ledger_id: entry.ledger_id.clone(),
                database: entry.database.clone(),
                actor_id: outcome.actor_id.to_string(),
                key_id: outcome.key_id.to_string(),
                seed_file,
                read_only: entry.read_only,
            },
        );
        actor_home.save(&entries)?;
        actor_home.set_active(ledger_name)?;
        let remotes = source.load_remotes()?;
        if !remotes.is_empty() {
            actor_home.save_remotes(&remotes)?;
        }
        Ok(PreparedHome { path, created })
    }

    fn read_seed_file(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| user_error("identity seed must be 32 bytes"))
    }

    fn absolute_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(env::current_dir()?.join(path))
        }
    }

    fn derived_actor_home(environment: &UserEnvironment, alias: &str) -> PathBuf {
        environment.root().join("actors").join(path_slug(alias))
    }

    fn path_slug(value: &str) -> String {
        let slug = value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                    character.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if slug.is_empty() {
            "actor".to_owned()
        } else {
            slug
        }
    }

    fn shell_escape(path: &Path) -> String {
        let value = path.to_string_lossy();
        if value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '-' | '_')
        }) {
            value.into_owned()
        } else {
            format!("'{}'", value.replace('\'', "'\\''"))
        }
    }
}

fn as_user_identity(
    input: fact_as::Input,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    fact_as::run(input)
}

fn clone_read_only_ledger(
    environment: &UserEnvironment,
    name: &str,
    source: &CloneSource,
    ledger: &str,
    actor: Option<CloneActorBinding>,
) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
    let clone_remote = clone_remote_to_create(environment, name, source)?;
    let bundle_path =
        std::env::temp_dir().join(format!("fact-clone-{}.bundle", uuid::Uuid::now_v7()));
    if source.is_remote_url {
        let database =
            std::env::temp_dir().join(format!("fact-clone-{}.sqlite", uuid::Uuid::now_v7()));
        let mut args = vec![
            "sync".to_owned(),
            "pull".to_owned(),
            "--remote".to_owned(),
            source.url.clone(),
        ];
        if let Some(token) = &source.bearer_token {
            args.push(format!("--bearer-token={token}"));
        }
        args.extend([
            "--".to_owned(),
            database
                .to_str()
                .ok_or("invalid temporary database path")?
                .to_owned(),
            ledger.to_owned(),
            bundle_path
                .to_str()
                .ok_or("invalid temporary bundle path")?
                .to_owned(),
        ]);
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let status = ProcessCommand::new(std::env::current_exe()?)
            .args(args)
            .stdout(Stdio::null())
            .status()?;
        let _ = fs::remove_file(database);
        if !status.success() {
            let _ = fs::remove_file(&bundle_path);
            return Err("remote clone pull failed".into());
        }
    } else {
        fs::copy(&source.url, &bundle_path)?;
    }
    let bytes = fs::read(&bundle_path)?;
    let _ = fs::remove_file(&bundle_path);
    let mut objects = environment::decode_clone_source_objects(&bytes)?;
    if let Some(actor) = &actor {
        objects.splice(
            0..0,
            local_actor_identity_objects_not_in(environment, actor, &objects)?,
        );
    }
    let entry =
        environment::clone_read_only_ledger_from_objects(environment, name, ledger, &objects, None)
            .map_err(|error| contextualize_clone_import_error(error, &objects))?;
    let entry = if let Some(actor) = actor {
        match bind_cloned_ledger_actor(environment, name, &entry, actor) {
            Ok(entry) => entry,
            Err(error) => {
                let _ = environment::delete_ledger(environment, name, true);
                return Err(error);
            }
        }
    } else {
        entry
    };
    apply_actor_response_claims_to_clone(environment, &entry, source)?;
    if let Some(remote_name) = clone_remote {
        save_clone_remote(environment, &remote_name, source, ledger)?;
    } else if let Some(remote_name) = &source.remote_name {
        record_remote_ledger_if_missing(environment, remote_name, ledger)?;
    }
    Ok(entry)
}

fn apply_actor_response_claims_to_clone(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    source: &CloneSource,
) -> Result<(), Box<dyn std::error::Error>> {
    if entry.read_only || source.actor.as_deref() != Some(entry.actor_id.as_str()) {
        return Ok(());
    }
    let Some(claims) = &source.claims else {
        return Ok(());
    };
    let Some(display_name) = claims.display_name.clone() else {
        return Ok(());
    };
    let actor_id = uuid::Uuid::parse_str(&entry.actor_id)?;
    let key_id = uuid::Uuid::parse_str(&entry.key_id)?;
    let seed = read_seed_for_write(environment, entry)?;
    fact_sdk::workflow::add_directory_entry(
        entry,
        &seed,
        fact_sdk::workflow::DirectoryAddInput {
            display_name,
            actor_id: Some(actor_id),
            key_id: Some(key_id),
            alias: claims.alias.clone(),
            actor_type: claims.actor_type.clone(),
            role: None,
            source: Some("actor-response-clone".to_owned()),
            verified_by: None,
            with_identity: false,
            seed: None,
        },
    )?;
    Ok(())
}

struct CloneActorBinding {
    input: String,
    actor_id: Option<uuid::Uuid>,
}

#[derive(Debug)]
struct CloneObjectInfo {
    id: String,
    object_type: String,
    ledger_id: Option<String>,
    actor_id: Option<String>,
    signing_key_id: Option<String>,
    dependencies: Vec<String>,
    receiving_actor_id: Option<String>,
    binding_actor_id: Option<String>,
    binding_key_id: Option<String>,
}

fn contextualize_clone_import_error(
    error: fact_sdk::Error,
    objects: &[Vec<u8>],
) -> Box<dyn std::error::Error> {
    let dependency_related = matches!(
        error,
        fact_sdk::Error::Store(
            fact_store::Error::MissingDependency
                | fact_store::Error::MissingKey
                | fact_store::Error::MissingLedger
                | fact_store::Error::InvalidLineage
        )
    );
    if !dependency_related {
        return error.into();
    }
    match clone_dependency_diagnostic(objects) {
        Some(diagnostic) => user_error(format!("{error}; {diagnostic}")),
        None => error.into(),
    }
}

fn clone_dependency_diagnostic(objects: &[Vec<u8>]) -> Option<String> {
    let infos = objects
        .iter()
        .filter_map(|object| clone_object_info(object).ok())
        .collect::<Vec<_>>();
    let ids = infos
        .iter()
        .map(|info| info.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut diagnostics = Vec::new();
    for info in &infos {
        if let Some(actor_id) = &info.receiving_actor_id {
            if !ids.contains(actor_id.as_str()) {
                diagnostics.push(format!(
                    "authorization grant {} references missing receiving actor identity {actor_id}; import or include the relevant identity bundle",
                    info.id
                ));
            }
        }
    }
    for info in &infos {
        for dependency in &info.dependencies {
            if !ids.contains(dependency.as_str()) {
                diagnostics.push(format!(
                    "missing dependency object {dependency} referenced by {} {}",
                    info.object_type, info.id
                ));
            }
        }
        if let Some(actor_id) = &info.actor_id {
            if !ids.contains(actor_id.as_str()) {
                diagnostics.push(format!(
                    "missing actor identity {actor_id} for signer of {} {}; import or include the relevant identity bundle",
                    info.object_type, info.id
                ));
            }
        }
        if let Some(key_id) = &info.signing_key_id {
            if !ids.contains(key_id.as_str()) {
                diagnostics.push(format!(
                    "missing key identity {key_id} for signer of {} {}; import or include the relevant identity bundle",
                    info.object_type, info.id
                ));
            }
        }
        if let Some(actor_id) = &info.binding_actor_id {
            if !ids.contains(actor_id.as_str()) {
                diagnostics.push(format!(
                    "actor-key binding {} references missing actor identity {actor_id}; import or include the relevant identity bundle",
                    info.id
                ));
            }
        }
        if let Some(key_id) = &info.binding_key_id {
            if !ids.contains(key_id.as_str()) {
                diagnostics.push(format!(
                    "actor-key binding {} references missing key identity {key_id}; import or include the relevant identity bundle",
                    info.id
                ));
            }
        }
    }
    let ledger_ids = infos
        .iter()
        .filter_map(|info| info.ledger_id.as_deref())
        .collect::<std::collections::HashSet<_>>();
    for ledger_id in ledger_ids {
        if !infos.iter().any(|info| {
            info.ledger_id.as_deref() == Some(ledger_id) && info.object_type == "genesis"
        }) {
            diagnostics.push(format!(
                "missing ledger-scoped genesis object for ledger {ledger_id}"
            ));
        }
    }
    diagnostics.dedup();
    diagnostics.into_iter().next()
}

fn clone_object_info(bytes: &[u8]) -> Result<CloneObjectInfo, Box<dyn std::error::Error>> {
    let payload = fact_crypto::decode_sign1(bytes)?.payload;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    let body = value.get("body").and_then(serde_json::Value::as_object);
    Ok(CloneObjectInfo {
        id: required_string(&value, "id")?.to_owned(),
        object_type: required_string(&value, "object_type")?.to_owned(),
        ledger_id: value
            .get("ledger_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        actor_id: value
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        signing_key_id: value
            .get("signing_key_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        dependencies: value
            .get("dependencies")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|dependency| {
                dependency
                    .get("object_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect(),
        receiving_actor_id: body
            .and_then(|body| body.get("receiving_actor_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        binding_actor_id: body
            .and_then(|body| body.get("actor_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        binding_key_id: body
            .and_then(|body| body.get("key_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

fn clone_actor_binding(
    environment: &UserEnvironment,
    actor: &str,
) -> Result<CloneActorBinding, Box<dyn std::error::Error>> {
    let actor_id = if let Ok(actor_id) = uuid::Uuid::parse_str(actor) {
        Some(actor_id)
    } else {
        match environment.resolve(None) {
            Ok(entry) => match fact_sdk::workflow::resolve_directory_actor_reference(&entry, actor)
            {
                Ok(actor_id) => Some(actor_id),
                Err(fact_sdk::Error::MissingObject(_)) => None,
                Err(error) => return Err(error.into()),
            },
            Err(_) => None,
        }
        .or_else(|| {
            local_actor_registry_entry(environment, actor)
                .ok()
                .and_then(|entry| uuid::Uuid::parse_str(&entry.actor_id).ok())
        })
    };
    Ok(CloneActorBinding {
        input: actor.to_owned(),
        actor_id,
    })
}

fn inferred_clone_actor_binding(
    environment: &UserEnvironment,
    source: &CloneSource,
) -> Result<Option<CloneActorBinding>, Box<dyn std::error::Error>> {
    let Some(actor) = source.actor.as_deref() else {
        return Ok(None);
    };
    let actor_id = uuid::Uuid::parse_str(actor)?;
    if local_actor_request_identity(environment, actor, Some(actor_id))?
        .is_some_and(|local| local.seed_file.exists())
    {
        Ok(Some(CloneActorBinding {
            input: actor.to_owned(),
            actor_id: Some(actor_id),
        }))
    } else {
        Ok(None)
    }
}

fn resolve_cloned_ledger_actor(
    entry: &LedgerEntry,
    actor: &str,
) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    if let Ok(actor_id) = uuid::Uuid::parse_str(actor) {
        return Ok(actor_id);
    }
    Ok(fact_sdk::workflow::resolve_directory_actor_reference(
        entry, actor,
    )?)
}

fn bind_cloned_ledger_actor(
    environment: &UserEnvironment,
    name: &str,
    entry: &LedgerEntry,
    actor: CloneActorBinding,
) -> Result<LedgerEntry, Box<dyn std::error::Error>> {
    let store = fact_store::Store::open(&entry.database)?;
    let actor_id = match actor.actor_id {
        Some(actor_id) => actor_id,
        None => resolve_cloned_ledger_actor(entry, &actor.input)?,
    };
    if store.get_cose_by_id_any(actor_id.as_bytes())?.is_none() {
        import_local_actor_identity_into_clone(environment, entry, &actor.input, actor_id)?;
    }
    let (_binding_id, key_id) = store
        .get_actor_key_binding_for_actor(actor_id.as_bytes())?
        .ok_or_else(|| {
            user_error(format!(
                "actor {actor_id} has no signing key binding in cloned ledger; clone without --as for read-only"
            ))
        })?;
    let seed_file = local_identity_seed_file(environment, actor_id, key_id)?;
    let capabilities = actor_capabilities_in_store(&store, entry, actor_id)?;
    if capabilities.is_empty() {
        return Err(user_error(format!(
            "actor {actor_id} has no write authority in cloned ledger; clone without --as for read-only"
        )));
    }
    let mut entries = environment.load()?;
    let updated = LedgerEntry {
        actor_id: actor_id.to_string(),
        key_id: key_id.to_string(),
        seed_file,
        read_only: false,
        ..entry.clone()
    };
    entries.insert(name.to_owned(), updated.clone());
    environment.save(&entries)?;
    Ok(updated)
}

fn local_actor_registry_entry(
    environment: &UserEnvironment,
    reference: &str,
) -> Result<ActorRegistryEntry, Box<dyn std::error::Error>> {
    let registry = load_actor_registry(environment)?;
    let stem = actor_artifact_stem(reference);
    let matches = registry
        .actors
        .iter()
        .filter(|(key, entry)| {
            key.as_str() == stem
                || entry.actor_id == reference
                || entry.name == reference
                || entry.alias.as_deref() == Some(reference)
        })
        .map(|(_, entry)| entry.clone())
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [entry] => Ok(entry.clone()),
        [] => Err(user_error(format!(
            "local actor identity not found: {reference}"
        ))),
        entries => Err(user_error(format!(
            "multiple local actor identities match {reference}: {}; use --as <actor-id>",
            entries
                .iter()
                .map(|entry| entry.actor_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn actor_request_identity_objects(
    actor: ActorRequestIdentity,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let actor_id = uuid::Uuid::parse_str(&actor.actor_id)?;
    let entry = actor_request_ledger_entry(&actor);
    let bundle = fact_sdk::workflow::export_identity_for_actor(&entry, actor_id)?.bundle;
    Ok(fact_commitment::decode_bundle(&bundle)
        .map_err(|error| user_error(error.to_string()))?
        .objects)
}

fn validate_local_actor_identity(
    reference: &str,
    actor_id: uuid::Uuid,
    expected_actor_id: Option<uuid::Uuid>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(expected_actor_id) = expected_actor_id {
        if actor_id != expected_actor_id {
            return Err(user_error(format!(
                "local actor {reference} is {actor_id}, not {expected_actor_id}; use --as <actor-id>"
            )));
        }
    }
    Ok(())
}

fn registry_actor_request_identity_for_reference(
    environment: &UserEnvironment,
    reference: &str,
) -> Result<ActorRequestIdentity, Box<dyn std::error::Error>> {
    local_actor_registry_entry(environment, reference)
        .map(|local| registry_actor_request_identity(environment, local))
}

fn local_actor_request_identity(
    environment: &UserEnvironment,
    reference: &str,
    actor_id: Option<uuid::Uuid>,
) -> Result<Option<ActorRequestIdentity>, Box<dyn std::error::Error>> {
    if let Some(local) = directory_actor_request_identity(environment, reference, None)? {
        let local_actor_id = uuid::Uuid::parse_str(&local.actor_id)?;
        validate_local_actor_identity(reference, local_actor_id, actor_id)?;
        return Ok(Some(local));
    }
    let registry = match registry_actor_request_identity_for_reference(environment, reference) {
        Ok(local) => Some(local),
        Err(_) => actor_id
            .map(|actor_id| {
                registry_actor_request_identity_for_reference(environment, &actor_id.to_string())
            })
            .transpose()?,
    };
    if let Some(local) = registry {
        let local_actor_id = uuid::Uuid::parse_str(&local.actor_id)?;
        validate_local_actor_identity(reference, local_actor_id, actor_id)?;
        return Ok(Some(local));
    }
    Ok(None)
}

fn import_local_actor_identity_into_clone(
    environment: &UserEnvironment,
    clone_entry: &LedgerEntry,
    reference: &str,
    actor_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let local = local_actor_request_identity(environment, reference, Some(actor_id))?
        .ok_or_else(|| user_error(format!("local actor identity not found: {reference}")))?;
    let bundle = fact_sdk::workflow::export_identity_for_actor(
        &actor_request_ledger_entry(&local),
        actor_id,
    )?
    .bundle;
    fact_sdk::workflow::import_identity(clone_entry, &bundle)?;
    Ok(())
}

fn local_actor_identity_objects(
    environment: &UserEnvironment,
    actor: &CloneActorBinding,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let Some(local) = local_actor_request_identity(environment, &actor.input, actor.actor_id)?
    else {
        return Ok(Vec::new());
    };
    actor_request_identity_objects(local)
}

fn local_actor_identity_objects_not_in(
    environment: &UserEnvironment,
    actor: &CloneActorBinding,
    existing: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let existing_ids = existing
        .iter()
        .filter_map(|object| object_id_from_cose(object).ok())
        .collect::<std::collections::HashSet<_>>();
    Ok(local_actor_identity_objects(environment, actor)?
        .into_iter()
        .filter(|object| {
            object_id_from_cose(object)
                .map(|object_id| !existing_ids.contains(&object_id))
                .unwrap_or(true)
        })
        .collect())
}

fn object_id_from_cose(bytes: &[u8]) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let payload = fact_crypto::decode_sign1(bytes)?.payload;
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| user_error("signed object is missing id"))?
        .parse()
        .map_err(|error| user_error(format!("signed object has invalid id: {error}")))
}

fn local_identity_seed_file(
    environment: &UserEnvironment,
    actor_id: uuid::Uuid,
    key_id: uuid::Uuid,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    for candidate in [
        environment.identity_dir.join(format!("{actor_id}.seed")),
        environment.identity_dir.join(format!("{key_id}.seed")),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(user_error(format!(
        "local private key material is not available for {actor_id}"
    )))
}

fn identity_actor_key_id(
    store: &fact_store::Store,
    actor_id: uuid::Uuid,
) -> Result<Option<uuid::Uuid>, Box<dyn std::error::Error>> {
    if let Some((_, key_id)) = store.get_actor_key_binding_for_actor(actor_id.as_bytes())? {
        return Ok(Some(key_id));
    }
    let actor_text = actor_id.to_string();
    let key_id = store
        .list_identity_objects()?
        .into_iter()
        .filter(|(_, _, object_type)| object_type == "actor_key_binding")
        .filter_map(|(binding_id, _, _)| {
            let bytes = store
                .get_cose_by_id_any(binding_id.as_bytes())
                .ok()
                .flatten()?;
            let payload = fact_crypto::decode_sign1(&bytes).ok()?.payload;
            let value = serde_json::from_slice::<serde_json::Value>(&payload).ok()?;
            let body = value.get("body")?;
            let binds_actor = body.get("actor_id").and_then(serde_json::Value::as_str)
                == Some(actor_text.as_str());
            let signing = body
                .get("permitted_purpose")
                .and_then(serde_json::Value::as_str)
                == Some("signing");
            if !binds_actor || !signing {
                return None;
            }
            let key_id = body.get("key_id").and_then(serde_json::Value::as_str)?;
            Some((binding_id, uuid::Uuid::parse_str(key_id).ok()?))
        })
        .max_by_key(|(binding_id, _)| *binding_id)
        .map(|(_, key_id)| key_id);
    Ok(key_id)
}

fn actor_capabilities_in_store(
    store: &fact_store::Store,
    entry: &LedgerEntry,
    actor_id: uuid::Uuid,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let ledger = uuid::Uuid::parse_str(&entry.ledger_id)?;
    let mut capabilities = Vec::new();
    for capability in GRANTABLE_CAPABILITIES {
        if !store
            .list_authority_grant_payloads(ledger.as_bytes(), actor_id.as_bytes(), capability.name)?
            .is_empty()
        {
            capabilities.push(capability.name.to_owned());
        }
    }
    Ok(capabilities)
}

fn recognize_user_identity(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    actor_text: &str,
    capabilities: &[String],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::create_identity_grant(entry, seed, actor_text, capabilities)?,
    )?)
}

fn expanded_capabilities(
    capabilities: Vec<String>,
    participate: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let expanded = expanded_optional_capabilities(capabilities, participate);
    if expanded.is_empty() {
        return Err(user_error(
            "at least one capability is required; pass --participate or --capability",
        ));
    }
    validate_capabilities(&expanded)?;
    Ok(expanded)
}

fn expanded_optional_capabilities(capabilities: Vec<String>, participate: bool) -> Vec<String> {
    let mut expanded = Vec::new();
    if participate {
        expanded.extend(
            PARTICIPATION_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned()),
        );
    }
    expanded.extend(capabilities);
    let mut seen = std::collections::BTreeSet::new();
    expanded.retain(|capability| seen.insert(capability.clone()));
    expanded
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    for capability in capabilities {
        if !is_grantable_capability(capability) {
            let mut message = format!(
                "unknown capability \"{capability}\"\n\nAllowed capabilities:\n  {ALLOWED_CAPABILITIES_TEXT}"
            );
            if capability == "revise" {
                message.push_str("\n\nNote: there is no separate \"revise\" capability.");
            }
            return Err(user_error(message));
        }
    }
    Ok(())
}

fn is_grantable_capability(capability: &str) -> bool {
    GRANTABLE_CAPABILITIES
        .iter()
        .any(|known| known.name == capability)
}

#[derive(Clone, Debug)]
struct HeldCapability {
    name: String,
    grant_refs: Vec<String>,
}

fn held_capabilities(
    entry: &LedgerEntry,
) -> Result<Vec<HeldCapability>, Box<dyn std::error::Error>> {
    let ledger = uuid::Uuid::parse_str(&entry.ledger_id)?;
    let actor = uuid::Uuid::parse_str(&entry.actor_id)?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut held = Vec::new();
    for capability in GRANTABLE_CAPABILITIES {
        let grant_refs = store
            .list_authority_grant_payloads(ledger.as_bytes(), actor.as_bytes(), capability.name)?
            .into_iter()
            .map(|row| fact_sdk::reference::short_uuid_reference(row.object_id))
            .collect::<Vec<_>>();
        if !grant_refs.is_empty() {
            held.push(HeldCapability {
                name: capability.name.to_owned(),
                grant_refs,
            });
        }
    }
    Ok(held)
}

fn print_capabilities(
    json: bool,
    active: Option<&(LedgerEntry, Vec<HeldCapability>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let held_names = active
        .map(|(_, held)| {
            held.iter()
                .map(|capability| capability.name.as_str())
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    let values = GRANTABLE_CAPABILITIES
        .iter()
        .map(|capability| {
            serde_json::json!({
                "name": capability.name,
                "description": capability.description,
                "privileged": capability.privileged,
                "held": held_names.contains(capability.name),
            })
        })
        .collect::<Vec<_>>();
    if json {
        let active_actor = active.map(|(entry, held)| {
            serde_json::json!({
                "ledger": entry.name,
                "ledger_id": entry.ledger_id,
                "actor_id": entry.actor_id,
                "actor_ref": uuid::Uuid::parse_str(&entry.actor_id)
                    .ok()
                    .map(fact_sdk::reference::short_uuid_reference),
                "capabilities": held.iter().map(|capability| capability.name.clone()).collect::<Vec<_>>(),
                "grants": held.iter()
                    .map(|capability| serde_json::json!({
                        "capability": capability.name,
                        "grant_refs": capability.grant_refs,
                    }))
                    .collect::<Vec<_>>(),
            })
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "capabilities": values,
                "active_actor": active_actor,
                "allowed": GRANTABLE_CAPABILITIES
                    .iter()
                    .map(|capability| capability.name)
                    .collect::<Vec<_>>(),
                "notes": [
                    "`admin` is highly privileged because it can authorize permission changes.",
                    "There is no separate `revise` capability at this time."
                ]
            }))?
        );
        return Ok(());
    }

    if let Some((entry, held)) = active {
        println!(
            "Active actor capabilities for {} ({})\n",
            fact_sdk::reference::short_uuid_reference(uuid::Uuid::parse_str(&entry.actor_id)?),
            entry.name
        );
        if held.is_empty() {
            println!("  none");
        } else {
            for capability in held {
                println!("  {}", capability.name);
            }
        }
        println!();
    }

    println!("Available capabilities\n");
    for capability in GRANTABLE_CAPABILITIES {
        let marker = if held_names.contains(capability.name) {
            "*"
        } else {
            " "
        };
        println!(
            "  {} {:<12}{}",
            marker, capability.name, capability.description
        );
    }
    println!();
    if active.is_some() {
        println!("* held by the active actor");
        println!();
    }
    println!("Notes");
    println!("  admin is highly privileged because it can authorize permission changes.");
    println!("  There is no separate revise capability at this time.");
    Ok(())
}

fn revoke_participation_user_grants(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    actor_text: &str,
    reason: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let ledger = uuid::Uuid::parse_str(&entry.ledger_id)?;
    let actor_id = fact_sdk::workflow::resolve_directory_actor_reference(entry, actor_text)?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut grants = std::collections::BTreeMap::<uuid::Uuid, Vec<String>>::new();
    for capability in PARTICIPATION_CAPABILITIES {
        for row in store.list_authority_grant_payloads(
            ledger.as_bytes(),
            actor_id.as_bytes(),
            capability,
        )? {
            if let std::collections::btree_map::Entry::Vacant(entry) = grants.entry(row.object_id) {
                entry.insert(authorization_grant_capabilities(&row.payload)?);
            }
        }
    }
    for (grant_id, capabilities) in &grants {
        if capabilities
            .iter()
            .any(|capability| !PARTICIPATION_CAPABILITIES.contains(&capability.as_str()))
        {
            return Err(user_error(format!(
                "grant {grant_id} mixes participation and non-participation capabilities; revoke it explicitly"
            )));
        }
    }
    let mut revocations = Vec::new();
    for grant_id in grants.keys() {
        revocations.push(revoke_user_grant(
            entry,
            seed,
            &grant_id.to_string(),
            reason,
        )?);
    }
    Ok(serde_json::json!({
        "participate":true,
        "actor_id":actor_id,
        "actor_ref":fact_sdk::reference::short_uuid_reference(actor_id),
        "capabilities":PARTICIPATION_CAPABILITIES,
        "revoked_count":revocations.len(),
        "revocations":revocations
    }))
}

fn authorization_grant_capabilities(
    payload: &[u8],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(payload)?;
    let capabilities = value
        .get("body")
        .and_then(|body| body.get("capabilities"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| user_error("authorization grant has no capabilities"))?
        .iter()
        .map(|capability| {
            capability
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| user_error("authorization grant capability is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(capabilities)
}

fn rotate_user_identity(
    environment: &UserEnvironment,
    entry: &LedgerEntry,
    seed: &[u8; 32],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let result = fact_sdk::workflow::rotate_identity_key(entry, seed)?;
    let new_seed_file = environment
        .identity_dir
        .join(format!("{}.seed", result.key_id));
    environment.write_seed(&new_seed_file, &result.new_seed)?;
    let mut entries = environment.load()?;
    let mut updated = entry.clone();
    updated.key_id = result.key_id.to_string();
    updated.seed_file = new_seed_file;
    entries.insert(updated.name.clone(), updated);
    environment.save(&entries)?;
    Ok(serde_json::to_value(result)?)
}

fn revoke_user_grant(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    reason: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::revoke_identity_grant(entry, seed, reference, reason)?,
    )?)
}

fn read_or_edit_markdown(
    file: Option<PathBuf>,
    message: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    read_or_edit_markdown_with_initial(file, message, None)
}

fn read_or_edit_markdown_with_initial(
    file: Option<PathBuf>,
    message: Option<&str>,
    initial: Option<&[u8]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if file.is_some() && message.is_some() {
        return Err("choose a file/stdin input or --message, not both".into());
    }
    if let Some(message) = message {
        let mut bytes = message.as_bytes().to_vec();
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        fact_canonical::validate_canonical_markdown(&bytes)?;
        return Ok(bytes);
    }
    if let Some(file) = file {
        if file == Path::new("-") {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes)?;
            fact_canonical::validate_canonical_markdown(&bytes)?;
            return Ok(bytes);
        }
        let bytes = fs::read(file)?;
        fact_canonical::validate_canonical_markdown(&bytes)?;
        return Ok(bytes);
    }
    let path = std::env::temp_dir().join(format!("fact-proposition-{}.md", uuid::Uuid::now_v7()));
    let placeholder = b"# Import a proposition\n\n";
    let starting_content = initial.unwrap_or(placeholder);
    fs::write(&path, starting_content)?;
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_owned());
    let status = ProcessCommand::new(editor).arg(&path).status()?;
    if !status.success() {
        let _ = fs::remove_file(&path);
        return Err("editor exited unsuccessfully".into());
    }
    let bytes = fs::read(&path)?;
    let _ = fs::remove_file(&path);
    if bytes.iter().all(u8::is_ascii_whitespace) || (initial.is_none() && bytes == placeholder) {
        return Err("empty proposition was not created".into());
    }
    fact_canonical::validate_canonical_markdown(&bytes)?;
    Ok(bytes)
}

fn create_user_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    markdown: &[u8],
    decision: Option<&str>,
) -> Result<PropositionResult, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::create_proposition(
        entry,
        seed,
        markdown,
        decision.map(|value| match value {
            "accepted" => fact_sdk::workflow::DecisionOutcome::Accepted,
            "rejected" => fact_sdk::workflow::DecisionOutcome::Rejected,
            _ => unreachable!("CLI only passes accepted or rejected"),
        }),
    )?)
}

fn create_user_reconciliation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ReconciliationCliInput,
) -> Result<ReconciliationResult, Box<dyn std::error::Error>> {
    if input.conflicts.is_empty() {
        return Err("at least one --conflict triple is required".into());
    }
    if input.resolved_tips.is_empty() {
        return Err("at least one --resolved-tip is required".into());
    }
    let conflicts = input
        .conflicts
        .iter()
        .map(|triple| parse_reconciliation_conflict(triple))
        .collect::<Result<Vec<_>, _>>()?;
    let resolved_tip_ids = input
        .resolved_tips
        .iter()
        .map(|value| parse_uuid7(value, "resolved tip"))
        .collect::<Result<Vec<_>, _>>()?;
    let markdown = read_optional_markdown(input.file, input.message.as_deref())?;
    Ok(fact_sdk::workflow::create_reconciliation_proposition(
        entry,
        seed,
        fact_sdk::workflow::ReconciliationInput {
            affected_proposition_id: parse_uuid7(&input.affected, "affected proposition")?,
            common_ancestor_revision_id: parse_uuid7(&input.common_ancestor, "common ancestor")?,
            conflicts,
            detecting_actor_id: parse_uuid7(&entry.actor_id, "actor")?,
            resolution_mode: input.mode,
            resolved_tip_ids,
            selected_revision_id: input
                .selected
                .as_deref()
                .map(|value| parse_uuid7(value, "selected revision"))
                .transpose()?,
            result_revision_id: input
                .result
                .as_deref()
                .map(|value| parse_uuid7(value, "result revision"))
                .transpose()?,
            markdown,
        },
    )?)
}

fn resolve_user_conflict(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    input: ResolveCliInput,
) -> Result<fact_sdk::workflow::ResolveConflictResult, Box<dyn std::error::Error>> {
    if input.pick.is_empty() && input.tool.is_some() && !input.merge {
        return Err("--tool requires --merge".into());
    }
    if !input.pick.is_empty() && !input.merge {
        return Err("--pick requires --merge".into());
    }
    let content_modes = usize::from(input.keep.is_some())
        + usize::from(input.merge)
        + usize::from(input.message.is_some())
        + usize::from(input.file.is_some());
    if content_modes > 1 {
        return Err("choose only one resolution content mode".into());
    }
    let selection_reference = input
        .reference
        .as_deref()
        .or(input.keep.as_deref())
        .or_else(|| {
            input
                .merge
                .then(|| input.pick.first())
                .flatten()
                .map(String::as_str)
        });
    let (content, display_mode, merged_revision_ids) = if let Some(keep) = input.keep.as_deref() {
        let revision_id = resolve_conflicting_revision(entry, input.reference.as_deref(), keep)?;
        (
            fact_sdk::workflow::ResolveContent::Keep { revision_id },
            "keep".to_owned(),
            Vec::new(),
        )
    } else if input.merge {
        let picked_revision_ids =
            resolve_merge_picks(entry, input.reference.as_deref(), &input.pick)?;
        let markdown = run_merge_tool(entry, &picked_revision_ids, input.tool.as_deref())?;
        (
            fact_sdk::workflow::ResolveContent::Derived { markdown },
            "merge".to_owned(),
            picked_revision_ids,
        )
    } else {
        let initial = if input.file.is_none() && input.message.is_none() {
            Some(resolve_editor_template(entry, selection_reference)?)
        } else {
            None
        };
        let mode = if input.message.is_some() {
            "message"
        } else if input.file.as_deref() == Some(Path::new("-")) {
            "stdin"
        } else if input.file.is_some() {
            "file"
        } else {
            "author"
        };
        (
            fact_sdk::workflow::ResolveContent::Derived {
                markdown: read_or_edit_markdown_with_initial(
                    input.file,
                    input.message.as_deref(),
                    initial.as_deref(),
                )?,
            },
            mode.to_owned(),
            Vec::new(),
        )
    };
    let mut outcome = fact_sdk::workflow::resolve_revision_conflict(
        entry,
        seed,
        fact_sdk::workflow::ResolveConflictInput {
            reference: selection_reference.map(str::to_owned),
            content,
        },
    )?;
    outcome.resolution_mode = display_mode;
    outcome.merged_revision_ids = merged_revision_ids;
    Ok(outcome)
}

fn resolve_conflict_group(
    entry: &LedgerEntry,
    reference: Option<&str>,
) -> Result<fact_sdk::workflow::RevisionConflictGroup, Box<dyn std::error::Error>> {
    let groups = fact_sdk::workflow::list_revision_conflicts(entry, reference, false)?;
    match groups.as_slice() {
        [group] => Ok(group.clone()),
        [] => Err("no revision conflicts".into()),
        _ => Err("multiple revision conflicts; run `fact conflicts` and pass a reference to `fact resolve`".into()),
    }
}

fn resolve_conflicting_revision(
    entry: &LedgerEntry,
    conflict_reference: Option<&str>,
    revision_reference: &str,
) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let group = resolve_conflict_group(entry, Some(revision_reference))?;
    if let Some(conflict_reference) = conflict_reference {
        let selected = resolve_conflict_group(entry, Some(conflict_reference))?;
        if selected.proposition_id != group.proposition_id {
            return Err("--keep references a revision in a different conflict".into());
        }
    }
    let matches = group
        .conflicts
        .iter()
        .filter(|revision| revision.matched_reference)
        .map(|revision| revision.revision_id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [revision_id] => Ok(*revision_id),
        [] => Err("--keep must reference one of the conflicting revisions".into()),
        _ => Err(format!(
            "that reference is ambiguous: {revision_reference}. Use a full revision ID"
        )
        .into()),
    }
}

fn resolve_merge_picks(
    entry: &LedgerEntry,
    conflict_reference: Option<&str>,
    picks: &[String],
) -> Result<Vec<uuid::Uuid>, Box<dyn std::error::Error>> {
    if picks.is_empty() {
        let group = resolve_conflict_group(entry, conflict_reference)?;
        if group.resolution_inputs.resolved_tips.len() != 2 {
            return Err("--merge requires at least two --pick values for this conflict".into());
        }
        return Ok(group.resolution_inputs.resolved_tips);
    }
    if picks.len() < 2 {
        return Err("--merge requires at least two --pick values".into());
    }
    let mut ids = Vec::new();
    for pick in picks {
        ids.push(resolve_conflicting_revision(
            entry,
            conflict_reference,
            pick,
        )?);
    }
    ids.sort();
    ids.dedup();
    if ids.len() < 2 {
        return Err("--merge requires at least two distinct picked revisions".into());
    }
    Ok(ids)
}

fn resolve_editor_template(
    entry: &LedgerEntry,
    reference: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let group = resolve_conflict_group(entry, reference)?;
    let mut text = String::from("# Reconciliation\n\n");
    text.push_str("<!--\n");
    text.push_str(&format!("proposition: {}\n", group.proposition_id));
    if let Some(common_ancestor) = group.common_ancestor_revision_id {
        text.push_str(&format!("common ancestor: {common_ancestor}\n"));
    }
    for revision in &group.conflicts {
        text.push_str(&format!("conflicting revision: {}\n", revision.revision_id));
    }
    text.push_str("-->\n\n");
    Ok(text.into_bytes())
}

fn run_merge_tool(
    entry: &LedgerEntry,
    revision_ids: &[uuid::Uuid],
    tool: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let command = tool
        .map(str::to_owned)
        .or_else(|| std::env::var("FACT_MERGE").ok())
        .ok_or("no merge tool configured; pass --tool or set FACT_MERGE")?;
    let temp = tempfile::tempdir()?;
    let mut args = Vec::new();
    for revision_id in revision_ids {
        let path = temp.path().join(format!("{revision_id}.md"));
        let content =
            fact_sdk::workflow::read_proposition_content(entry, &revision_id.to_string())?;
        fs::write(&path, content.content)?;
        args.push(path);
    }
    let output = temp.path().join("resolution.md");
    let status = ProcessCommand::new(command)
        .args(args.iter().map(PathBuf::as_path))
        .arg(&output)
        .status()?;
    if !status.success() {
        return Err("merge tool exited unsuccessfully".into());
    }
    let bytes = fs::read(&output)?;
    fact_canonical::validate_canonical_markdown(&bytes)?;
    Ok(bytes)
}

fn parse_reconciliation_conflict(
    triple: &str,
) -> Result<fact_sdk::workflow::ReconciliationConflictInput, Box<dyn std::error::Error>> {
    let parts = triple.split(':').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(
            format!("--conflict must be REVISION:DELIBERATION:SETTLEMENT, got {triple:?}").into(),
        );
    }
    Ok(fact_sdk::workflow::ReconciliationConflictInput {
        revision_id: parse_uuid7(parts[0], "conflict revision")?,
        deliberation_id: parse_uuid7(parts[1], "conflict deliberation")?,
        settlement_id: parse_uuid7(parts[2], "conflict settlement")?,
    })
}

fn read_optional_markdown(
    file: Option<PathBuf>,
    message: Option<&str>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if file.is_some() && message.is_some() {
        return Err("choose a file/stdin input or --message, not both".into());
    }
    if let Some(message) = message {
        let mut bytes = message.as_bytes().to_vec();
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        fact_canonical::validate_canonical_markdown(&bytes)?;
        return Ok(Some(bytes));
    }
    if let Some(file) = file {
        let bytes = if file == Path::new("-") {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes)?;
            bytes
        } else {
            fs::read(file)?
        };
        fact_canonical::validate_canonical_markdown(&bytes)?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn decide_user_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: Option<&str>,
    outcome: &str,
) -> Result<PropositionResult, Box<dyn std::error::Error>> {
    let outcome = match outcome {
        "accepted" => fact_sdk::workflow::DecisionOutcome::Accepted,
        "rejected" => fact_sdk::workflow::DecisionOutcome::Rejected,
        _ => unreachable!("CLI only passes accepted or rejected"),
    };
    Ok(fact_sdk::workflow::decide_proposition(
        entry, seed, reference, outcome,
    )?)
}

fn list_user_propositions(
    entry: &LedgerEntry,
    requested_status: Option<ListStatus>,
    all: bool,
    limit: usize,
    offset: usize,
    after: Option<String>,
) -> Result<Vec<PropositionListItem>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::list_propositions_page(
        entry,
        fact_sdk::workflow::ListPropositionsFilter {
            status: requested_status.map(sdk_list_status),
            all,
        },
        Some(fact_sdk::workflow::ListPropositionsPage {
            offset,
            limit: (limit != 0).then_some(limit),
            after,
        }),
    )?)
}

fn pending_for_actor(
    entry: &LedgerEntry,
) -> Result<Vec<PropositionListItem>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::pending_propositions(entry)?)
}

fn proposition_display_status(item: &PropositionListItem) -> String {
    fact_sdk::proposition::display_status(item)
}

fn decision_human_message(verb: &str, outcome: &PropositionResult) -> String {
    if outcome.settlement_id.is_none() {
        let pending = outcome.pending_participant_count.unwrap_or_default();
        return format!(
            "{} proposition {}\nDecision recorded: {}\nCurrent status: {}\nPending participant(s): {}\nCurrent summary: {}",
            verb,
            short_uuid(outcome.proposition_id),
            outcome
                .decision_id
                .map(short_uuid)
                .unwrap_or_else(|| "none".to_owned()),
            outcome.status,
            pending,
            outcome.summary
        );
    }
    format!(
        "{} proposition {}\nEffective revision: {}\nCurrent summary: {}",
        verb,
        short_uuid(outcome.proposition_id),
        short_uuid(outcome.revision_id),
        outcome.summary
    )
}

fn resolve_human_message(outcome: &fact_sdk::workflow::ResolveConflictResult) -> String {
    if let Some(result_revision_id) = outcome.result_revision_id {
        return format!(
            "Resolution revision created: {}\nResult revision created: {}\nPrevious conflicting revisions remain in history.\nResult and reconciliation are pending acceptance from {} participant(s).\n\nNext:\n  fact accept {}\n  fact accept {}\n  fact reject {}\n  fact reject {}",
            short_uuid(outcome.revision_id),
            short_uuid(result_revision_id),
            outcome.pending_participant_count,
            short_uuid(outcome.reconciliation_proposition_id),
            short_uuid(result_revision_id),
            short_uuid(outcome.reconciliation_proposition_id),
            short_uuid(result_revision_id),
        );
    }

    format!(
        "Resolution revision created: {}\nPrevious conflicting revisions remain in history.\nNew revision is pending acceptance from {} participant(s).\n\nNext:\n  fact accept {}\n  fact reject {}",
        short_uuid(outcome.revision_id),
        outcome.pending_participant_count,
        short_uuid(outcome.reconciliation_proposition_id),
        short_uuid(outcome.reconciliation_proposition_id)
    )
}

fn search_user_ledger(
    entry: &LedgerEntry,
    text: &str,
    status: Option<ListStatus>,
    effective: bool,
    page_size: usize,
) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::search_proposition_content(
        entry,
        text,
        status.map(sdk_list_status),
        effective,
        page_size,
    )?)
}

fn sdk_list_status(status: ListStatus) -> fact_sdk::workflow::ListPropositionStatus {
    match status {
        ListStatus::Pending => fact_sdk::workflow::ListPropositionStatus::Pending,
        ListStatus::Accepted => fact_sdk::workflow::ListPropositionStatus::Accepted,
        ListStatus::Rejected => fact_sdk::workflow::ListPropositionStatus::Rejected,
        ListStatus::Contested => fact_sdk::workflow::ListPropositionStatus::Contested,
        ListStatus::Withdrawn => fact_sdk::workflow::ListPropositionStatus::Withdrawn,
        ListStatus::Archived => fact_sdk::workflow::ListPropositionStatus::Archived,
    }
}

fn sdk_tag_match(match_mode: TagMatch) -> fact_sdk::workflow::TagSearchMatch {
    match match_mode {
        TagMatch::Any => fact_sdk::workflow::TagSearchMatch::Any,
        TagMatch::All => fact_sdk::workflow::TagSearchMatch::All,
    }
}

fn short_uuid(value: uuid::Uuid) -> String {
    fact_sdk::reference::short_uuid_reference(value)
}

fn short_uuid_string(value: &str) -> String {
    uuid::Uuid::parse_str(value)
        .map(short_uuid)
        .unwrap_or_else(|_| value.to_owned())
}

fn parse_tag_operation(action: &str) -> Result<fact_sdk::workflow::TagOperation, Box<dyn Error>> {
    match action {
        "show" | "list" | "read" => Ok(fact_sdk::workflow::TagOperation::Show),
        "add" | "create" => Ok(fact_sdk::workflow::TagOperation::Add),
        "remove" | "delete" | "rm" => Ok(fact_sdk::workflow::TagOperation::Remove),
        "set" | "replace" | "update" => Ok(fact_sdk::workflow::TagOperation::Set),
        "clear" => Ok(fact_sdk::workflow::TagOperation::Clear),
        _ => Err(
            format!("unknown tag action: {action}. Use show, add, remove, set, or clear").into(),
        ),
    }
}

fn history_user_ledger(
    entry: &LedgerEntry,
    reference: Option<&str>,
    page: Option<fact_sdk::workflow::HistoryPage>,
) -> Result<Vec<HistoryItem>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::history_ledger_page(
        entry, reference, page,
    )?)
}

fn list_user_revisions(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::proposition::list_revisions(entry, reference)?)
}

struct CommentReviewInput<'a> {
    entry: &'a LedgerEntry,
    reference: Option<&'a str>,
    revision: Option<&'a str>,
    mine: bool,
    author: Option<&'a str>,
    mentions_me: bool,
    since: Option<&'a str>,
    unresolved: bool,
    text: Option<&'a str>,
    limit: usize,
}

fn list_user_comments(
    input: CommentReviewInput<'_>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    if input.unresolved {
        return Err(user_error(
            "unresolved comment filtering is not available yet; comment lifecycle state is not first-class protocol data",
        ));
    }
    if input.limit == 0 {
        return Ok(Vec::new());
    }
    let author = resolve_comment_author(input.entry, input.author, input.mine)?;
    let mentioned_actor = if input.mentions_me {
        if input.entry.actor_id.is_empty() {
            return Err(user_error(
                "--mentions-me requires an active signing identity for this ledger",
            ));
        }
        Some(input.entry.actor_id.as_str())
    } else {
        None
    };
    let since = input.since.map(parse_comment_since).transpose()?;
    let text = input
        .text
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    let mut comments = if let Some(reference) = input.reference {
        if let Some(comment) = resolve_comment_reference_value(input.entry, reference)? {
            vec![comment]
        } else {
            fact_sdk::workflow::list_deliberation_comments(input.entry, reference, input.revision)?
                .into_iter()
                .map(|comment| {
                    let mut value = serde_json::to_value(comment)?;
                    value["proposition_id"] = serde_json::Value::Null;
                    value["proposition_ref"] = serde_json::Value::Null;
                    value["revision_id"] = serde_json::Value::Null;
                    value["revision_ref"] = serde_json::Value::Null;
                    value["content"] = serde_json::Value::Null;
                    Ok(value)
                })
                .collect::<Result<Vec<_>, serde_json::Error>>()?
        }
    } else {
        list_all_comment_review_values(input.entry)?
    };

    comments.retain(|comment| {
        comment_matches_author(comment, author)
            && comment_matches_since(comment, since.as_deref())
            && comment_matches_text(comment, text.as_deref())
            && comment_matches_mention(comment, mentioned_actor)
    });
    if input.reference.is_some() {
        comments.sort_by(|left, right| {
            left["created_at"]
                .as_str()
                .cmp(&right["created_at"].as_str())
                .then_with(|| left["object_id"].as_str().cmp(&right["object_id"].as_str()))
        });
    } else {
        comments.sort_by(|left, right| {
            right["created_at"]
                .as_str()
                .cmp(&left["created_at"].as_str())
                .then_with(|| right["object_id"].as_str().cmp(&left["object_id"].as_str()))
        });
    }
    comments.truncate(input.limit);
    Ok(comments)
}

fn list_all_comment_review_values(
    entry: &LedgerEntry,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let deliberations = store.list_deliberation_projecteds(ledger.as_bytes())?;
    let mut metadata = std::collections::BTreeMap::new();
    for deliberation in deliberations {
        metadata.insert(
            deliberation.deliberation_id,
            (deliberation.proposition_id, deliberation.revision_id),
        );
    }
    let rows =
        store.list_deliberation_objects_by_type(ledger.as_bytes(), "deliberation_comment")?;
    let mut comments = Vec::new();
    for row in rows {
        comments.push(comment_value_from_row(row, &metadata)?);
    }
    Ok(comments)
}

fn resolve_comment_reference_value(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let matches =
        store.resolve_object_reference(ledger.as_bytes(), reference, &["deliberation_comment"])?;
    let matched = match matches.as_slice() {
        [] => return Ok(None),
        [matched] => matched,
        _ => {
            return Err(user_error(format!(
                "that comment reference is ambiguous: {reference}"
            )))
        }
    };
    let Some(row) = store.object_payload_by_id(ledger.as_bytes(), matched.object_id.as_bytes())?
    else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
    let deliberation_id = value["body"]["deliberation_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let mut metadata = std::collections::BTreeMap::new();
    if let Some(deliberation_id) = deliberation_id {
        if let Some(deliberation) =
            store.deliberation_projected(ledger.as_bytes(), deliberation_id.as_bytes())?
        {
            metadata.insert(
                deliberation.deliberation_id,
                (deliberation.proposition_id, deliberation.revision_id),
            );
        }
    }
    Ok(Some(comment_value_from_row(row, &metadata)?))
}

fn comment_value_from_row(
    row: fact_store::ObjectPayloadRow,
    metadata: &std::collections::BTreeMap<uuid::Uuid, (uuid::Uuid, uuid::Uuid)>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
    let deliberation_id = value["body"]["deliberation_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let (proposition_id, revision_id) = deliberation_id
        .and_then(|id| metadata.get(&id).copied())
        .map_or((None, None), |(proposition, revision)| {
            (Some(proposition), Some(revision))
        });
    let content = value["body"]["content"]["bytes"]
        .as_str()
        .and_then(decode_base64url)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default();
    Ok(serde_json::json!({
        "object_id":row.object_id,
        "reference":fact_sdk::reference::short_uuid_reference(row.object_id),
        "object_type":row.object_type,
        "content_hash":row.content_hash.hex(),
        "created_at":value["created_at"],
        "actor_id":value["actor_id"],
        "proposition_id":proposition_id,
        "proposition_ref":proposition_id.map(fact_sdk::reference::short_uuid_reference),
        "revision_id":revision_id,
        "revision_ref":revision_id.map(fact_sdk::reference::short_uuid_reference),
        "deliberation_id":value["body"]["deliberation_id"],
        "parent_comment_id":value["body"]["parent_comment_id"],
        "summary":summary_for_comment_markdown(&content),
        "content":content,
    }))
}

fn resolve_comment_author(
    entry: &LedgerEntry,
    author: Option<&str>,
    mine: bool,
) -> Result<Option<uuid::Uuid>, Box<dyn std::error::Error>> {
    if mine && author.is_some() {
        return Err(user_error("use either --mine or --author, not both"));
    }
    if mine {
        if entry.actor_id.is_empty() {
            return Err(user_error(
                "--mine requires an active signing identity for this ledger",
            ));
        }
        return Ok(Some(parse_uuid7(&entry.actor_id, "actor")?));
    }
    author
        .map(|author| {
            parse_uuid7(author, "author")
                .or_else(|_| fact_sdk::workflow::resolve_directory_actor_reference(entry, author))
        })
        .transpose()
        .map_err(Into::into)
}

fn parse_comment_since(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = value.trim();
    if let Some(days) = trimmed.strip_suffix('d') {
        let days = days
            .parse::<i64>()
            .map_err(|_| user_error("--since duration must look like 7d"))?;
        let since = time::OffsetDateTime::now_utc() - time::Duration::days(days);
        return Ok(since.format(&time::format_description::well_known::Rfc3339)?);
    }
    if let Some(hours) = trimmed.strip_suffix('h') {
        let hours = hours
            .parse::<i64>()
            .map_err(|_| user_error("--since duration must look like 24h"))?;
        let since = time::OffsetDateTime::now_utc() - time::Duration::hours(hours);
        return Ok(since.format(&time::format_description::well_known::Rfc3339)?);
    }
    Ok(trimmed.to_owned())
}

fn comment_matches_author(comment: &serde_json::Value, author: Option<uuid::Uuid>) -> bool {
    author.is_none_or(|author| {
        comment["actor_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            == Some(author)
    })
}

fn comment_matches_since(comment: &serde_json::Value, since: Option<&str>) -> bool {
    since.is_none_or(|since| {
        comment["created_at"]
            .as_str()
            .is_some_and(|value| value >= since)
    })
}

fn comment_matches_text(comment: &serde_json::Value, text: Option<&str>) -> bool {
    text.is_none_or(|text| {
        comment["summary"]
            .as_str()
            .is_some_and(|summary| summary.to_ascii_lowercase().contains(text))
            || comment["content"]
                .as_str()
                .is_some_and(|content| content.to_ascii_lowercase().contains(text))
    })
}

fn comment_matches_mention(comment: &serde_json::Value, actor: Option<&str>) -> bool {
    actor.is_none_or(|actor| {
        comment["content"]
            .as_str()
            .is_some_and(|content| content.contains(actor))
            || comment["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains(actor))
    })
}

fn print_comments_review(comments: &[serde_json::Value], proposition_scoped: bool, content: bool) {
    if comments.is_empty() {
        println!("no comments");
        return;
    }
    let field = |comment: &serde_json::Value, name: &str| {
        comment[name]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| comment[name].to_string())
    };
    if content {
        for (index, comment) in comments.iter().enumerate() {
            if index > 0 {
                println!();
            }
            println!(
                "{}  {}  {}",
                field(comment, "reference"),
                field(comment, "actor_id"),
                field(comment, "created_at")
            );
            println!();
            print!("{}", comment["content"].as_str().unwrap_or(""));
        }
        return;
    }
    if proposition_scoped {
        for comment in comments {
            println!(
                "{}  {}  {}",
                field(comment, "reference"),
                field(comment, "actor_id"),
                field(comment, "summary")
            );
        }
        return;
    }
    let mut groups = std::collections::BTreeMap::<String, Vec<&serde_json::Value>>::new();
    let mut group_order = Vec::new();
    for comment in comments {
        let key = comment["proposition_ref"]
            .as_str()
            .or_else(|| comment["proposition_id"].as_str())
            .unwrap_or("unknown proposition")
            .to_owned();
        if !groups.contains_key(&key) {
            group_order.push(key.clone());
        }
        groups.entry(key).or_default().push(comment);
    }
    for key in group_order {
        println!("{key}");
        for comment in &groups[&key] {
            println!(
                "  {}  {}  {}  {}",
                field(comment, "reference"),
                field(comment, "actor_id"),
                field(comment, "created_at"),
                field(comment, "summary")
            );
        }
    }
}

fn summary_for_comment_markdown(content: &str) -> String {
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.trim_start_matches('#').trim().to_owned())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "No summary".to_owned())
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = Vec::new();
    for byte in value.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        bits = (bits << 6) | value;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(output)
}

fn resolve_user_content(
    entry: &LedgerEntry,
    reference: &str,
    selection: fact_sdk::workflow::ContentSelection,
) -> Result<(Vec<u8>, uuid::Uuid), Box<dyn std::error::Error>> {
    let resolved =
        fact_sdk::workflow::read_proposition_content_with_selection(entry, reference, selection)?;
    Ok((resolved.content, resolved.revision_id))
}

fn content_selection(pending: bool, latest: bool) -> fact_sdk::workflow::ContentSelection {
    match (pending, latest) {
        (true, false) => fact_sdk::workflow::ContentSelection::Pending,
        (false, true) => fact_sdk::workflow::ContentSelection::Latest,
        _ => fact_sdk::workflow::ContentSelection::Effective,
    }
}

fn resolve_latest_user_content(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(fact_sdk::proposition::latest_proposition_content(
        entry, reference,
    )?)
}

fn user_deliberation(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::read_deliberation(entry, reference)?,
    )?)
}

fn open_missing_user_deliberation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    Ok(
        fact_sdk::workflow::open_missing_deliberation(entry, seed, reference)?
            .map(serde_json::to_value)
            .transpose()?,
    )
}

fn list_user_deliberations(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    Ok(
        fact_sdk::workflow::list_proposition_deliberations(entry, reference)?
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

fn show_user_deliberation(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::show_deliberation(entry, reference)?)
}

fn create_user_comment(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    content: &[u8],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(fact_sdk::workflow::create_comment(
        entry, seed, reference, content,
    )?)?)
}

fn create_user_invitation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invited_actor: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::create_invitation(entry, seed, reference, invited_actor)?,
    )?)
}

#[derive(Clone, Copy)]
enum InvitationListScope {
    All,
    Sent,
    Received,
    Pending,
}

fn list_user_invitations(
    entry: &LedgerEntry,
    scope: InvitationListScope,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let invitations = fact_sdk::workflow::list_invitations(
        entry,
        fact_sdk::workflow::ListInvitationsFilter::default(),
    )?;
    let invitation_ids = invitations
        .iter()
        .filter_map(|invitation| uuid::Uuid::parse_str(&invitation.id).ok())
        .collect::<Vec<_>>();
    let statuses = invitation_lifecycle_statuses(entry, &invitation_ids)?;
    let accepted = accepted_invitation_ids(entry)?;
    let active_actor = uuid::Uuid::parse_str(&entry.actor_id)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let mut values = Vec::new();
    for invitation in invitations {
        let invited_actor = invitation_body_uuid(&invitation.body.fields, "invited_actor_id");
        let inviting_actor = invitation_body_uuid(&invitation.body.fields, "inviting_actor_id");
        let value = invitation_value(
            entry,
            &store,
            ledger,
            &invitation,
            statuses
                .get(&uuid::Uuid::parse_str(&invitation.id)?)
                .map(String::as_str),
            &accepted,
            active_actor,
        )?;
        let matches_scope = match scope {
            InvitationListScope::All => true,
            InvitationListScope::Sent => inviting_actor == Some(active_actor),
            InvitationListScope::Received => invited_actor == Some(active_actor),
            InvitationListScope::Pending => {
                invited_actor == Some(active_actor) && value["status"].as_str() == Some("active")
            }
        };
        if matches_scope {
            values.push(value);
        }
    }
    Ok(values)
}

fn show_user_invitation(
    entry: &LedgerEntry,
    reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let invitation = fact_sdk::workflow::read_invitation(entry, reference)?;
    let invitation_id = uuid::Uuid::parse_str(&invitation.id)?;
    let statuses = invitation_lifecycle_statuses(entry, &[invitation_id])?;
    let accepted = accepted_invitation_ids(entry)?;
    let active_actor = uuid::Uuid::parse_str(&entry.actor_id)?;
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    invitation_value(
        entry,
        &store,
        ledger,
        &invitation,
        statuses.get(&invitation_id).map(String::as_str),
        &accepted,
        active_actor,
    )
}

fn create_user_participant_join_from_invitation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    invitation_reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let invitation = show_user_invitation(entry, invitation_reference)?;
    let status = invitation["status"].as_str().unwrap_or("unknown");
    if status != "active" {
        return Err(user_error(format!(
            "that invitation is {status}; there are no join actions available"
        )));
    }
    let proposition_id = invitation["proposition_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| user_error("participant invitation has no proposition_id"))?;
    create_user_participant_join(
        entry,
        seed,
        &proposition_id.to_string(),
        invitation_reference,
    )
}

fn reject_user_invitation(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    invitation_reference: &str,
    reason: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::update_invitation_lifecycle(
            entry,
            seed,
            invitation_reference,
            "decline",
            reason,
        )?,
    )?)
}

fn invitation_value(
    entry: &LedgerEntry,
    store: &fact_store::Store,
    ledger: uuid::Uuid,
    invitation: &fact_sdk::models::ProtocolEnvelope<fact_sdk::models::ParticipantInvitationBody>,
    status: Option<&str>,
    accepted: &std::collections::BTreeSet<uuid::Uuid>,
    active_actor: uuid::Uuid,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let invitation_id = uuid::Uuid::parse_str(&invitation.id)?;
    let invited_actor = invitation_body_uuid(&invitation.body.fields, "invited_actor_id");
    let inviting_actor = invitation_body_uuid(&invitation.body.fields, "inviting_actor_id");
    let proposition_id = invitation_body_uuid(&invitation.body.fields, "proposition_id");
    let deliberation_id = invitation_body_uuid(&invitation.body.fields, "deliberation_id")
        .or_else(|| invitation_dependency_uuid(invitation, "deliberation"));
    let deliberation = deliberation_id
        .map(|id| store.deliberation_projected(ledger.as_bytes(), id.as_bytes()))
        .transpose()?
        .flatten();
    let proposition_id =
        proposition_id.or_else(|| deliberation.as_ref().map(|row| row.proposition_id));
    let revision_id = deliberation.as_ref().map(|row| row.revision_id);
    let lifecycle_status = invitation_status_label(status.unwrap_or("active"));
    let status = if accepted.contains(&invitation_id) {
        "accepted"
    } else if lifecycle_status == "active" && deliberation.as_ref().is_some_and(|row| row.settled) {
        "closed"
    } else {
        lifecycle_status
    };
    let direction = if invited_actor == Some(active_actor) {
        "received"
    } else if inviting_actor == Some(active_actor) {
        "sent"
    } else {
        "other"
    };
    let mut next_actions = Vec::new();
    if status == "active" && invited_actor == Some(active_actor) {
        let reference = fact_sdk::reference::short_uuid_reference(invitation_id);
        next_actions.push(format!("fact invitations accept {reference}"));
        next_actions.push(format!("fact invitations reject {reference}"));
        next_actions.push(format!("fact join {reference}"));
    }
    let proposition_summary = proposition_id.and_then(|id| {
        fact_sdk::workflow::show_proposition_overview(
            entry,
            fact_sdk::workflow::ShowOverviewInput {
                reference: id.to_string(),
                revision_limit: Some(0),
                comments_limit: Some(0),
                history_limit: Some(0),
                include_conflicts_all: false,
                include_history: false,
                include_content: false,
                include_participants: false,
            },
        )
        .ok()
        .map(|overview| overview.proposition.summary)
    });
    Ok(serde_json::json!({
        "object_id": invitation_id,
        "reference": fact_sdk::reference::short_uuid_reference(invitation_id),
        "object_type": invitation.object_type,
        "created_at": invitation.created_at,
        "actor_id": invitation.actor_id,
        "inviting_actor_id": inviting_actor,
        "invited_actor_id": invited_actor,
        "proposition_id": proposition_id,
        "proposition_ref": proposition_id.map(fact_sdk::reference::short_uuid_reference),
        "proposition_summary": proposition_summary,
        "revision_id": revision_id,
        "revision_ref": revision_id.map(fact_sdk::reference::short_uuid_reference),
        "deliberation_id": deliberation_id,
        "deliberation_ref": deliberation_id.map(fact_sdk::reference::short_uuid_reference),
        "status": status,
        "direction": direction,
        "next_actions": next_actions,
    }))
}

fn invitation_body_uuid(
    body: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Option<uuid::Uuid> {
    body.get(field)
        .and_then(|value| (!value.is_null()).then_some(value))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

fn invitation_dependency_uuid(
    invitation: &fact_sdk::models::ProtocolEnvelope<fact_sdk::models::ParticipantInvitationBody>,
    role: &str,
) -> Option<uuid::Uuid> {
    invitation
        .dependencies
        .iter()
        .find(|dependency| dependency.role == role)
        .and_then(|dependency| uuid::Uuid::parse_str(&dependency.object_id).ok())
}

fn invitation_lifecycle_statuses(
    entry: &LedgerEntry,
    invitation_ids: &[uuid::Uuid],
) -> Result<std::collections::BTreeMap<uuid::Uuid, String>, Box<dyn std::error::Error>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let rows = store.list_lifecycle_rows_for_targets(
        ledger.as_bytes(),
        "invitation_lifecycle",
        invitation_ids,
    )?;
    let mut entries =
        std::collections::BTreeMap::<uuid::Uuid, Vec<(uuid::Uuid, String, Vec<uuid::Uuid>)>>::new();
    for row in rows {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        let Some(invitation_id) = row.target_id.or_else(|| {
            value["body"]["invitation_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
        }) else {
            continue;
        };
        let predecessors = value["body"]["predecessor_lifecycle_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .filter_map(|value| uuid::Uuid::parse_str(value).ok())
            .collect::<Vec<_>>();
        entries.entry(invitation_id).or_default().push((
            row.object_id,
            row.operation,
            predecessors,
        ));
    }
    let mut statuses = std::collections::BTreeMap::new();
    for (invitation_id, values) in entries {
        let referenced = values
            .iter()
            .flat_map(|(_, _, predecessors)| predecessors.iter().copied())
            .collect::<std::collections::BTreeSet<_>>();
        let tips = values
            .into_iter()
            .filter(|(id, _, _)| !referenced.contains(id))
            .map(|(_, operation, _)| operation)
            .collect::<Vec<_>>();
        let status = match tips.as_slice() {
            [] => "active",
            [operation] => operation.as_str(),
            _ => "conflict",
        };
        statuses.insert(invitation_id, status.to_owned());
    }
    Ok(statuses)
}

fn accepted_invitation_ids(
    entry: &LedgerEntry,
) -> Result<std::collections::BTreeSet<uuid::Uuid>, Box<dyn std::error::Error>> {
    let ledger = parse_uuid7(&entry.ledger_id, "ledger")?;
    let store = fact_store::Store::open(&entry.database)?;
    let rows = store
        .list_deliberation_objects_by_type(ledger.as_bytes(), "deliberation_participant_change")?;
    let mut accepted = std::collections::BTreeSet::new();
    for row in rows {
        let value: serde_json::Value = serde_json::from_slice(&row.payload)?;
        if value["body"]["operation"].as_str() != Some("join") {
            continue;
        }
        if let Some(invitation_id) = value["body"]["invitation_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        {
            accepted.insert(invitation_id);
        }
    }
    Ok(accepted)
}

fn invitation_status_label(status: &str) -> &str {
    match status {
        "decline" => "rejected",
        "revoke" => "revoked",
        "supersede" => "superseded",
        other => other,
    }
}

fn format_invitations_list(invitations: &[serde_json::Value]) -> String {
    if invitations.is_empty() {
        return "no invitations".to_owned();
    }
    invitations
        .iter()
        .map(|invitation| {
            format!(
                "{}  {}  {}  {}  {}",
                invitation["reference"].as_str().unwrap_or("-"),
                invitation["direction"].as_str().unwrap_or("-"),
                invitation["status"].as_str().unwrap_or("-"),
                invitation["proposition_ref"].as_str().unwrap_or("-"),
                invitation["proposition_summary"]
                    .as_str()
                    .unwrap_or("No summary")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_invitation_show(invitation: &serde_json::Value) -> String {
    let mut output = format!(
        "Invitation {}\n\n\
Status:       {}\n\
Direction:    {}\n\
Proposition:  {}  {}\n\
Revision:     {}\n\
Deliberation: {}\n\
From:         {}\n\
To:           {}\n\
Created:      {}\n",
        invitation["reference"].as_str().unwrap_or("-"),
        invitation["status"].as_str().unwrap_or("-"),
        invitation["direction"].as_str().unwrap_or("-"),
        invitation["proposition_ref"].as_str().unwrap_or("-"),
        invitation["proposition_summary"]
            .as_str()
            .unwrap_or("No summary"),
        invitation["revision_ref"].as_str().unwrap_or("-"),
        invitation["deliberation_ref"].as_str().unwrap_or("-"),
        invitation["inviting_actor_id"]
            .as_str()
            .map(short_actor_id)
            .unwrap_or_else(|| "-".to_owned()),
        invitation["invited_actor_id"]
            .as_str()
            .map(short_actor_id)
            .unwrap_or_else(|| "-".to_owned()),
        invitation["created_at"].as_str().unwrap_or("-"),
    );
    let actions = invitation["next_actions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if actions.is_empty() {
        output.push_str("\nNext:\n  no invitation actions available\n");
    } else {
        output.push_str("\nNext:\n");
        for action in actions {
            if let Some(action) = action.as_str() {
                output.push_str(&format!("  {action}\n"));
            }
        }
    }
    output
}

fn short_actor_id(value: &str) -> String {
    uuid::Uuid::parse_str(value)
        .map(fact_sdk::reference::short_uuid_reference)
        .unwrap_or_else(|_| value.to_owned())
}

fn create_user_participant_join(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    invitation_reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::join_deliberation(entry, seed, reference, invitation_reference)?,
    )?)
}

fn create_user_participant_leave(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        fact_sdk::workflow::leave_deliberation(entry, seed, reference)?,
    )?)
}

fn create_user_lifecycle(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    operation: &str,
    reason: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let result = match operation {
        "withdraw" => fact_sdk::workflow::withdraw_proposition(entry, seed, reference, reason)?,
        "restore" => fact_sdk::workflow::restore_proposition(entry, seed, reference, reason)?,
        "archive" => fact_sdk::workflow::archive_proposition(entry, seed, reference, reason)?,
        "unarchive" => fact_sdk::workflow::unarchive_proposition(entry, seed, reference, reason)?,
        _ => return Err(format!("unsupported proposition lifecycle operation {operation}").into()),
    };
    Ok(serde_json::to_value(result)?)
}

fn open_user_content(
    entry: &LedgerEntry,
    reference: &str,
    selection: fact_sdk::workflow::ContentSelection,
) -> Result<(), Box<dyn std::error::Error>> {
    let (content, _) = resolve_user_content(entry, reference, selection)?;
    let Some(editor) = std::env::var("VISUAL")
        .ok()
        .or_else(|| std::env::var("EDITOR").ok())
    else {
        io::stdout().write_all(&content)?;
        return Ok(());
    };
    let path = std::env::temp_dir().join(format!("fact-open-{}.md", uuid::Uuid::now_v7()));
    fs::write(&path, &content)?;
    let status = ProcessCommand::new(editor).arg(&path).status()?;
    let _ = fs::remove_file(&path);
    if !status.success() {
        return Err("editor exited unsuccessfully".into());
    }
    Ok(())
}

fn revise_user_proposition(
    entry: &LedgerEntry,
    seed: &[u8; 32],
    reference: &str,
    markdown: &[u8],
) -> Result<PropositionResult, Box<dyn std::error::Error>> {
    Ok(fact_sdk::workflow::update_proposition_content(
        entry, seed, reference, markdown,
    )?)
}

fn read_hashes(path: &PathBuf) -> Result<Vec<fact_core::Hash>, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::parse)
        .collect::<Result<Vec<fact_core::Hash>, _>>()?)
}

fn with_bearer_token(
    request: reqwest::blocking::RequestBuilder,
    bearer_token: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    match bearer_token {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

fn fetch_remote_dependencies(
    remote: &str,
    ledger: uuid::Uuid,
    objects: &mut Vec<(fact_core::Hash, Vec<u8>)>,
    known: &std::collections::HashSet<fact_core::Hash>,
    bearer_token: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = format!("{remote}/facts/ledgers/{ledger}/object-fetches");
    let client = reqwest::blocking::Client::new();
    let mut present = objects
        .iter()
        .map(|(hash, _)| *hash)
        .collect::<std::collections::HashSet<_>>();
    let mut pending = objects
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    let mut inspected = std::collections::HashSet::new();

    while let Some(bytes) = pending.pop() {
        let requested =
            fact_sdk::sync::missing_dependency_hashes(&[bytes], &present, known, &mut inspected)?;
        if requested.is_empty() {
            continue;
        }
        let body = fact_sdk::sync::encode_fetch_request(&requested)?;
        let request = client
            .post(&endpoint)
            .header("content-type", "application/fact+json")
            .header("facts-protocol-version", "0")
            .header("facts-ledger", ledger.to_string())
            .header(
                "content-digest",
                fact_sdk::sync::content_digest_header(&body),
            )
            .body(body);
        let response = with_bearer_token(request, bearer_token).send()?;
        let status = response.status();
        let response_body = response.bytes()?.to_vec();
        if !status.is_success() {
            return Err(format!(
                "remote dependency fetch failed ({status}): {}",
                String::from_utf8_lossy(&response_body)
            )
            .into());
        }
        let response_value: serde_json::Value = serde_json::from_slice(&response_body)?;
        let fetched_objects = fact_sdk::sync::validate_fetched_objects(
            &requested,
            fact_sdk::sync::decode_remote_response_objects(&response_value, "fetch")?,
        )?;
        for (hash, cose_bytes) in fetched_objects {
            if present.insert(hash) {
                pending.push(cose_bytes.clone());
                objects.push((hash, cose_bytes));
            }
        }
    }
    Ok(())
}

fn parse_uuid7(value: &str, field: &str) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let uuid = uuid::Uuid::parse_str(value)?;
    if uuid.get_version_num() != 7 || uuid.to_string() != value {
        return Err(format!("{field} must be lowercase canonical UUIDv7").into());
    }
    Ok(uuid)
}

fn resolve_ledger_uuid(value: &str) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let environment = UserEnvironment::discover()?;
    let ledger = environment.resolve_ledger_id(value)?;
    parse_uuid7(&ledger, "ledger")
}
