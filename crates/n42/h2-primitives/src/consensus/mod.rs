mod h2_v4;
mod messages;

pub use h2_v4::{
    H2V4ChainIdentity, commit_signing_message as h2_v4_commit_signing_message,
    new_view_signing_message as h2_v4_new_view_signing_message,
    proposal_signing_message as h2_v4_proposal_signing_message,
    timeout_signing_message as h2_v4_timeout_signing_message,
    vote_signing_message as h2_v4_vote_signing_message,
};
pub use messages::{
    CONSENSUS_PROTOCOL_VERSION, CommitVote, ConsensusMessage, Decide, NewView, PrepareQC, Proposal,
    QuorumCertificate, TimeoutCertificate, TimeoutMessage, ValidatorChange, ValidatorIndex,
    VersionedMessage, ViewNumber, Vote,
};
