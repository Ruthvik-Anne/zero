//! Live smoke tests, behind flags. Without the flags these print a skip reason
//! and pass; they never run network traffic in the default suite.
//!
//!   ZERO_LIVE_OPENAI=1 OPENAI_API_KEY=sk-... cargo test -p zero-model --test live
//!   ZERO_LIVE_OLLAMA=1 OLLAMA_HOST=http://127.0.0.1:11434 OLLAMA_MODEL=llama3.1 \
//!     cargo test -p zero-model --test live

use zero_model::{
    Collector, CompletionRequest, Message, OpenAiConfig, OpenAiProvider, OllamaConfig,
    OllamaProvider, Provider,
};

#[test]
fn live_openai_smoke() {
    if std::env::var("ZERO_LIVE_OPENAI").as_deref() != Ok("1") {
        println!("skipped: set ZERO_LIVE_OPENAI=1 and OPENAI_API_KEY to run");
        return;
    }
    let Ok(key) = std::env::var("OPENAI_API_KEY") else {
        println!("skipped: OPENAI_API_KEY is not set");
        return;
    };
    let model = std::env::var("ZERO_LIVE_MODEL").unwrap_or_else(|_| "gpt-4o-mini".into());
    let config = OpenAiConfig::new("https://api.openai.com/v1", key, model.clone());
    let mut provider = OpenAiProvider::new(config).unwrap();
    let mut request = CompletionRequest::new(model, vec![Message::user("Reply with the word `pong`.")]);
    request.max_tokens = Some(16);
    let response = provider.complete(&request, &mut Collector::default()).unwrap();
    println!("live openai: {:?}", response.text);
    assert!(!response.text.is_empty());
}

#[test]
fn live_ollama_smoke() {
    if std::env::var("ZERO_LIVE_OLLAMA").as_deref() != Ok("1") {
        println!("skipped: set ZERO_LIVE_OLLAMA=1 with a running Ollama to run");
        return;
    }
    let base = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
    let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.1".into());
    let mut provider = OllamaProvider::new(OllamaConfig::new(base, model.clone())).unwrap();
    let support = provider.probe_tools().unwrap();
    println!("live ollama tools: {support:?}");
    let response = provider
        .complete(&CompletionRequest::new(model, vec![Message::user("Reply with `pong`.")]), &mut Collector::default())
        .unwrap();
    println!("live ollama: {:?}", response.text);
    assert!(!response.text.is_empty());
}
