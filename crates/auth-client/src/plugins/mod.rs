//! Modular client plugins for `AuthClient`.

pub mod admin;
pub mod one_time_token;

pub use admin::{AdminClientExt, AdminClientHandle, AdminClientPlugin};
pub use one_time_token::{
    OneTimeTokenClientExt, OneTimeTokenClientHandle, OneTimeTokenClientPlugin,
};
