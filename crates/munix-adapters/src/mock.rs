use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use serde_json::Value;

use crate::{AdapterError, ModelAdapter, ModelReply, ModelRequest};

/// Scripted adapter for tests: returns the queued results in order and records every request.
#[derive(Debug)]
pub struct MockAdapter {
    script: Mutex<VecDeque<Result<Value, AdapterError>>>,
    seen: Mutex<Vec<ModelRequest>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl MockAdapter {
    pub fn new(script: Vec<Result<Value, AdapterError>>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Every request received so far, oldest first.
    pub fn seen(&self) -> Vec<ModelRequest> {
        lock(&self.seen).clone()
    }
}

impl ModelAdapter for MockAdapter {
    fn name(&self) -> String {
        "mock".to_string()
    }

    fn complete_json(&self, req: &ModelRequest) -> Result<ModelReply, AdapterError> {
        lock(&self.seen).push(req.clone());
        match lock(&self.script).pop_front() {
            Some(Ok(value)) => Ok(ModelReply {
                value,
                model: "mock".to_string(),
            }),
            Some(Err(e)) => Err(e),
            None => Err(AdapterError::Unavailable(
                "the mock script is exhausted".to_string(),
            )),
        }
    }
}
