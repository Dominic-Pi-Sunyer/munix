//! A [`Detector`] that asks the loopback guard sidecar (`guard/server.py`, Llama Prompt Guard 2) for scores.
//!
//! Wire format: `POST <url>` with `{"texts": [..]}` returns `{"scores": [..]}`, one injection probability per text.
//! The sidecar binds `127.0.0.1` only. Any transport error, timeout, non-200 status or malformed body is a
//! [`DetectError`], which the caller treats as a flag.

use std::time::Duration;

use munix_core::detect::{DetectError, Detector};
use serde::Deserialize;
use serde_json::json;

/// The largest reply body read from the sidecar.
pub const MAX_REPLY_BYTES: u64 = 64 * 1024;

pub struct GuardDetector {
    name: String,
    url: String,
    timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    scores: Vec<f32>,
}

impl GuardDetector {
    /// `url` must be `http://127.0.0.1:<port>/score` or `http://localhost:<port>/score` (a loopback host, `http`,
    /// a port, path `/score`); anything else is `None`, so a config typo can't send page text off the machine.
    /// `name` is what the ledger records (e.g. `Llama-Prompt-Guard-2-22M`).
    pub fn new(name: &str, url: &str, timeout: Duration) -> Option<GuardDetector> {
        let rest = url.strip_prefix("http://")?;
        let (host_port, path) = rest.split_once('/')?;
        if path != "score" {
            return None;
        }
        let (host, port) = host_port.split_once(':')?;
        if host != "127.0.0.1" && host != "localhost" {
            return None;
        }
        // Digits only (no sign, no whitespace), 1..=65535, no leading-zero tricks beyond what `u16` accepts.
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        match port.parse::<u16>() {
            Ok(p) if p >= 1 => {}
            _ => return None,
        }
        Some(GuardDetector {
            name: name.to_owned(),
            url: url.to_owned(),
            timeout,
        })
    }
}

impl Detector for GuardDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn score(&self, texts: &[&str]) -> Result<Vec<f32>, DetectError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let body = json!({ "texts": texts }).to_string();
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .max_redirects_will_error(false)
                .proxy(None)
                .timeout_global(Some(self.timeout))
                .build(),
        );
        let mut resp = agent
            .post(&self.url)
            .content_type("application/json")
            .send(body.as_str())
            .map_err(|_| DetectError::Unavailable)?;
        if resp.status().as_u16() != 200 {
            return Err(DetectError::Unavailable);
        }
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => DetectError::BadReply,
                _ => DetectError::Unavailable,
            })?;
        serde_json::from_slice::<Reply>(&bytes)
            .map(|reply| reply.scores)
            .map_err(|_| DetectError::BadReply)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    const T: Duration = Duration::from_secs(5);

    /// Serves one canned reply per request on a random loopback port; records request bodies.
    fn serve(status: u16, body: String) -> (String, Arc<Mutex<Vec<String>>>) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let seen = bodies.clone();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let mut text = String::new();
                let _ = std::io::Read::read_to_string(request.as_reader(), &mut text);
                seen.lock().unwrap().push(text);
                let response =
                    tiny_http::Response::from_string(body.clone()).with_status_code(status);
                let _ = request.respond(response);
            }
        });
        (format!("http://127.0.0.1:{port}/score"), bodies)
    }

    fn detector(url: &str) -> GuardDetector {
        GuardDetector::new("guard", url, T).unwrap()
    }

    #[test]
    fn good_reply_gives_scores_and_sends_the_texts() {
        let (url, bodies) = serve(200, r#"{"scores":[0.25,0.75]}"#.to_owned());
        let d = detector(&url);
        assert_eq!(d.name(), "guard");
        assert_eq!(d.score(&["a", "b"]), Ok(vec![0.25, 0.75]));
        let sent = bodies.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&sent[0]).unwrap(),
            json!({"texts": ["a", "b"]})
        );
    }

    #[test]
    fn empty_input_makes_no_request() {
        let (url, bodies) = serve(200, r#"{"scores":[]}"#.to_owned());
        assert_eq!(detector(&url).score(&[]), Ok(vec![]));
        assert!(bodies.lock().unwrap().is_empty());
    }

    #[test]
    fn non_200_is_unavailable() {
        let (url, _) = serve(500, r#"{"scores":[0.1]}"#.to_owned());
        assert_eq!(detector(&url).score(&["a"]), Err(DetectError::Unavailable));
    }

    #[test]
    fn nothing_listening_is_unavailable() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let d = detector(&format!("http://127.0.0.1:{port}/score"));
        assert_eq!(d.score(&["a"]), Err(DetectError::Unavailable));
    }

    #[test]
    fn garbage_body_is_a_bad_reply() {
        let (url, _) = serve(200, "not json".to_owned());
        assert_eq!(detector(&url).score(&["a"]), Err(DetectError::BadReply));
    }

    #[test]
    fn wrong_shape_is_a_bad_reply() {
        for body in [
            r#"{"scores":"x"}"#,
            r#"{"scores":[0.1],"extra":1}"#,
            r"{}",
            r"[0.1]",
        ] {
            let (url, _) = serve(200, body.to_owned());
            assert_eq!(
                detector(&url).score(&["a"]),
                Err(DetectError::BadReply),
                "{body}"
            );
        }
    }

    #[test]
    fn oversized_body_is_a_bad_reply() {
        let big = format!(
            r#"{{"scores":[{}]}}"#,
            vec!["0.1"; (MAX_REPLY_BYTES as usize) / 3].join(",")
        );
        assert!(big.len() as u64 > MAX_REPLY_BYTES);
        let (url, _) = serve(200, big);
        assert_eq!(detector(&url).score(&["a"]), Err(DetectError::BadReply));
    }

    #[test]
    fn length_and_range_are_left_to_the_caller() {
        let (url, _) = serve(200, r#"{"scores":[7.0]}"#.to_owned());
        assert_eq!(detector(&url).score(&["a", "b"]), Ok(vec![7.0]));
    }

    #[test]
    fn url_validation() {
        for ok in [
            "http://127.0.0.1:8080/score",
            "http://localhost:1/score",
            "http://localhost:65535/score",
        ] {
            assert!(GuardDetector::new("n", ok, T).is_some(), "{ok}");
        }
        for bad in [
            "",
            "https://127.0.0.1:8080/score",
            "http://127.0.0.1/score",
            "http://127.0.0.1:/score",
            "http://127.0.0.1:0/score",
            "http://127.0.0.1:65536/score",
            "http://127.0.0.1:+80/score",
            "http://127.0.0.1:80/other",
            "http://127.0.0.1:80/score/",
            "http://127.0.0.1:80/score?x=1",
            "http://127.0.0.1:80/score#f",
            "http://user@127.0.0.1:80/score",
            "http://user:pw@localhost:80/score",
            "http://127.0.0.1.evil.test:80/score",
            "http://localhost.evil.test:80/score",
            "http://example.com:80/score",
            "http://0.0.0.0:80/score",
            "http://[::1]:80/score",
            "http://127.0.0.1:80",
            "http://127.0.0.1:80score",
            "http://127.0.0.1:8 0/score",
            "http://LOCALHOST:80/score",
            " http://127.0.0.1:80/score",
        ] {
            assert!(GuardDetector::new("n", bad, T).is_none(), "{bad}");
        }
    }
}
