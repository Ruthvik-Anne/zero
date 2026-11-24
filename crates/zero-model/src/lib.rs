//! `zero-model` — providers, streaming, error mapping, and the conformance suite.
//!
//! Contract (`architecture.md` §5): must not read config files directly.

pub mod conformance;
pub mod errors;
pub mod ollama;
pub mod openai;
pub mod provider;
pub mod scripted;

pub use ollama::{OllamaConfig, OllamaProvider, ToolSupport};
pub use openai::{OpenAiConfig, OpenAiProvider};
pub use provider::{
    Capabilities, Collector, CompletionRequest, Control, EventSink, Message, Provider, ProviderEvent,
    ProviderResponse, RetryClass, RetryPolicy, Role, StopReason, ToolCall, ToolSchema, Usage,
};
pub use scripted::{ScriptTurn, ScriptedProvider};
