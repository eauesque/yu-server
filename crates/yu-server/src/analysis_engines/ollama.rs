use std::{path::Path, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;

use super::{
    http_client::{build_pinned_client, check_image_size_limits, read_response_capped},
    prompts,
    result_parse::{parse_analysis_result, parse_trends_result},
    AnalysisEngine, AnalysisResult, AnalyzeContext, AnalyzeMode, EngineError,
};

const TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RETRIES: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_secs(3);
const MAX_DIM: u32 = 1536;
const MAX_RESPONSE_BYTES: usize = 20 * 1024 * 1024;

pub struct OllamaEngine {
    pub base_url: String,
    pub model: String,
    pub language: String,
}

impl OllamaEngine {
    fn is_non_retryable(message: &str) -> bool {
        message.contains("not running")
            || message.contains("not found")
            || message.contains("Cannot connect")
    }

    async fn call_api_once(&self, messages: &serde_json::Value) -> Result<String, EngineError> {
        let client = build_pinned_client(&self.base_url, true, TIMEOUT).await?;
        let response = client
            .post(format!("{}/api/chat", self.base_url.trim_end_matches('/')))
            .json(&json!({"model": self.model, "messages": messages, "stream": true}))
            .send()
            .await
            .map_err(|error| Self::classify_transport_error(&error, &self.base_url))?;
        let status = response.status();
        let body = read_response_capped(response, MAX_RESPONSE_BYTES).await?;
        if !status.is_success() {
            if status.as_u16() == 404 {
                return Err(EngineError::msg(format!(
                    "Model not found: {}. Run: ollama pull {}",
                    self.model, self.model
                )));
            }
            if status.as_u16() == 503 || body.to_lowercase().contains("loading model") {
                return Err(EngineError::msg(format!(
                    "Ollama is loading model '{}'. Please wait and retry, or run: ollama run {}",
                    self.model, self.model
                )));
            }
            return Err(EngineError::msg(format!(
                "Ollama API error (HTTP {}): {}",
                status.as_u16(),
                &body[..body.len().min(300)]
            )));
        }
        let mut content = String::new();
        for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let Some(chunk) = value.pointer("/message/content").and_then(|v| v.as_str()) {
                content.push_str(chunk);
            }
            if value.get("done").and_then(|v| v.as_bool()) == Some(true) {
                break;
            }
        }
        if content.is_empty() {
            Err(EngineError::msg("Ollama returned empty response"))
        } else {
            Ok(content)
        }
    }

    fn classify_transport_error(error: &reqwest::Error, base_url: &str) -> EngineError {
        if error.is_connect() {
            EngineError::msg(format!(
                "Ollama is not running at {base_url}. Start Ollama first: ollama serve"
            ))
        } else if error.is_timeout() {
            EngineError::msg(format!(
                "Ollama response timeout ({}s). The model may be too slow or not loaded.",
                TIMEOUT.as_secs()
            ))
        } else {
            EngineError::msg(format!("Cannot connect to Ollama at {base_url}: {error}"))
        }
    }

    async fn call_api(&self, messages: &serde_json::Value) -> Result<String, EngineError> {
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            match self.call_api_once(messages).await {
                Ok(response) => return Ok(response),
                Err(error) if Self::is_non_retryable(&error.to_string()) => return Err(error),
                Err(error) => {
                    last_error = Some(error);
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| EngineError::msg("Ollama request failed")))
    }
}

#[async_trait]
impl AnalysisEngine for OllamaEngine {
    async fn analyze_image(
        &self,
        image_path: &Path,
        ctx: &AnalyzeContext,
    ) -> Result<AnalysisResult, EngineError> {
        let image_data = encode_image_for_ollama(image_path)?;
        let system = if ctx.mode == AnalyzeMode::Ocr {
            "You are an OCR assistant. Read text from images accurately and return JSON."
                .to_string()
        } else {
            prompts::get_system_prompt(&ctx.language, ctx.mode)
        };
        let messages = json!([
            {"role": "system", "content": system},
            {"role": "user", "content": prompts::build_image_prompt(&ctx.existing_tags, ctx.existing_prompt.as_deref(), &ctx.language, ctx.mode), "images": [image_data]},
        ]);
        let raw = self.call_api(&messages).await?;
        if ctx.mode == AnalyzeMode::Ocr {
            return Ok(AnalysisResult {
                raw_response: raw,
                ..Default::default()
            });
        }
        Ok(parse_analysis_result(&raw))
    }

    async fn analyze_trends(
        &self,
        prompts_in: &[String],
    ) -> Result<serde_json::Value, EngineError> {
        let prompt_texts = prompts_in
            .iter()
            .take(50)
            .map(|value| value.chars().take(200).collect::<String>())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if prompt_texts.is_empty() {
            return Ok(json!({"error": "No prompts to analyze"}));
        }
        let raw = self.call_api(&json!([{"role": "user", "content": prompts::build_trends_prompt(&prompt_texts, &self.language)}])).await?;
        Ok(parse_trends_result(&raw))
    }

    fn name(&self) -> String {
        format!("Ollama Vision ({})", self.model)
    }
}

fn encode_image_for_ollama(image_path: &Path) -> Result<String, EngineError> {
    let extension = image_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let native = matches!(extension.as_str(), "png" | "jpg" | "jpeg");
    let image = check_image_size_limits(image_path)?
        .decode()
        .map_err(|error| EngineError::msg(format!("Failed to decode image: {error}")))?;
    let needs_resize = image.width().max(image.height()) > MAX_DIM;
    if native && !needs_resize {
        return std::fs::read(image_path)
            .map(|bytes| STANDARD.encode(bytes))
            .map_err(|error| EngineError::msg(format!("Failed to read image file: {error}")));
    }
    let output = if needs_resize {
        image.resize(MAX_DIM, MAX_DIM, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let format = if matches!(extension.as_str(), "jpg" | "jpeg") {
        image::ImageFormat::Jpeg
    } else {
        image::ImageFormat::Png
    };
    let mut bytes = std::io::Cursor::new(Vec::new());
    output
        .write_to(&mut bytes, format)
        .map_err(|error| EngineError::msg(format!("Failed to encode image: {error}")))?;
    Ok(STANDARD.encode(bytes.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_only_match_the_python_error_substrings() {
        for message in ["not running", "model not found", "Cannot connect to Ollama"] {
            assert!(OllamaEngine::is_non_retryable(message));
        }
        assert!(!OllamaEngine::is_non_retryable("HTTP 500"));
    }
}
