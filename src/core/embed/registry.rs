//! Port of `core/embed/registry.ts` — ordered format-handler lookup with a universal fallback.

use crate::core::embed::fallback::FallbackHandler;
use crate::core::types::FormatHandler;

#[derive(Default)]
pub struct FormatHandlerRegistry {
    handlers: Vec<Box<dyn FormatHandler>>,
    fallback: FallbackHandler,
}

impl FormatHandlerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler; earlier registrations win.
    pub fn register(&mut self, handler: Box<dyn FormatHandler>) -> &mut Self {
        self.handlers.push(handler);
        self
    }

    /// First handler that claims the bytes, else the universal-trailer fallback.
    pub fn resolve(&self, bytes: &[u8], mime_type: Option<&str>) -> &dyn FormatHandler {
        for h in &self.handlers {
            if h.can_handle(bytes, mime_type) {
                return h.as_ref();
            }
        }
        &self.fallback
    }

    pub fn list_handlers(&self) -> Vec<String> {
        let mut names: Vec<String> = self.handlers.iter().map(|h| h.name().to_string()).collect();
        names.push(self.fallback.name().to_string());
        names
    }
}
