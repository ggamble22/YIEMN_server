//! User photo icons: processing, storage and moderation.

pub mod moderation;
pub mod photo;
pub mod store;

pub use moderation::{ModerationVerdict, Moderator};
pub use store::PhotoStore;
