//! Token-gated JSON API for programmatic clients.
//!
//! - `GET /api/v1/health` answers `{"ok":true}` without calling Reddit.
//! - `GET /api/v1/raw/{path}.json?{query}` returns Reddit's JSON for
//!   `{path}?{query}` as fetched by `client::json`, i.e. through the same
//!   spoofed OAuth client the HTML frontend uses. `raw_json=1` is appended
//!   unless the query already sets `raw_json`.
//!
//! The raw route answers 404 unless `REDLIB_API_TOKEN` is set to a non-empty
//! value, and then requires `Authorization: Bearer $REDLIB_API_TOKEN`.
//! Every response is JSON with `Cache-Control: no-store`; failures are
//! `{"error": <code>, "status": <http status>}`.
//!
//! This file is the whole feature apart from `pub mod api;` in `lib.rs` and two
//! routes in `main.rs`, so the fork rebases cleanly onto upstream.

use crate::client::json;
use crate::utils::error;
use hyper::{header, Body, Request, Response, Uri};
use log::warn;
use percent_encoding::percent_decode_str;
use serde_json::{json as json_value, Value};
use std::sync::LazyLock;

const RAW_PREFIX: &str = "/api/v1/raw";

static API_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| std::env::var("REDLIB_API_TOKEN").ok().filter(|t| !t.is_empty()));

/// `client::json` reports these refusals with exactly these strings.
const FORBIDDEN: [&str; 5] = ["private", "banned", "quarantined", "gated", "suspended"];

/// An HTTP status and the machine-readable `error` code sent with it.
#[derive(Debug, PartialEq, Eq)]
struct ApiError(u16, &'static str);

const NOT_FOUND: ApiError = ApiError(404, "not_found");
const UNAUTHORIZED: ApiError = ApiError(401, "unauthorized");
const BAD_PATH: ApiError = ApiError(400, "bad_path");

pub async fn health(_req: Request<Body>) -> Result<Response<Body>, String> {
	Ok(respond(200, &json_value!({ "ok": true })))
}

pub async fn raw(req: Request<Body>) -> Result<Response<Body>, String> {
	let authorization = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
	let target = match check(API_TOKEN.as_deref(), authorization, req.uri()) {
		Ok(target) => target,
		Err(e) => return Ok(error_response(e)),
	};

	Ok(match json(target, false).await {
		Ok(value) => respond(200, &value),
		Err(msg) => {
			let e = classify(&msg);
			warn!("api: {} for {}: {msg}", e.0, req.uri().path());
			error_response(e)
		}
	})
}

/// The catch-all route. Unmatched paths under `/api/`, in any letter case
/// (the reverse proxy in front matches case-insensitively), get a JSON 404
/// instead of Redlib's HTML error page.
pub async fn fallback(req: Request<Body>) -> Result<Response<Body>, String> {
	if is_api_path(req.uri().path()) {
		Ok(error_response(NOT_FOUND))
	} else {
		error(req, "Nothing here").await
	}
}

fn is_api_path(path: &str) -> bool {
	let path = path.trim_start_matches('/');
	path.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("api/")) || path.eq_ignore_ascii_case("api")
}

/// Gates a raw request and returns the Reddit API path (with query) to fetch.
/// The path comes from the request URI as sent, not the router's normalised copy.
fn check(token: Option<&str>, authorization: Option<&str>, uri: &Uri) -> Result<String, ApiError> {
	let Some(token) = token.filter(|t| !t.is_empty()) else {
		return Err(NOT_FOUND);
	};
	if !authorization.and_then(bearer).is_some_and(|provided| token_eq(provided.as_bytes(), token.as_bytes())) {
		return Err(UNAUTHORIZED);
	}
	reddit_path(uri.path(), uri.query()).ok_or(BAD_PATH)
}

/// The credentials of an `Authorization: Bearer <token>` header.
fn bearer(authorization: &str) -> Option<&str> {
	let (scheme, credentials) = authorization.trim().split_once(' ')?;
	scheme.eq_ignore_ascii_case("bearer").then_some(credentials.trim())
}

/// Compares without short-circuiting, so timing does not reveal how much of a guess matched.
fn token_eq(a: &[u8], b: &[u8]) -> bool {
	let mut diff = a.len() ^ b.len();
	for i in 0..a.len().max(b.len()) {
		diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
	}
	diff == 0
}

/// Maps a request path under `/api/v1/raw` and its query to a Reddit API
/// path, or `None` if the path is not a plain `.json` path.
fn reddit_path(path: &str, query: Option<&str>) -> Option<String> {
	let path = path.strip_prefix(RAW_PREFIX)?;
	if !path.starts_with('/') || !path.ends_with(".json") {
		return None;
	}

	// Reject traversal and backslashes, also when percent-encoded (once or twice).
	let once = percent_decode_str(path).decode_utf8_lossy();
	let twice = percent_decode_str(&once).decode_utf8_lossy();
	if [path, &*once, &*twice].into_iter().any(|p| p.contains("..") || p.contains('\\')) {
		return None;
	}

	let query = query.unwrap_or_default();
	let has_raw_json = query.split('&').any(|pair| pair.split('=').next() == Some("raw_json"));
	Some(match (query.is_empty(), has_raw_json) {
		(true, _) => format!("{path}?raw_json=1"),
		(false, true) => format!("{path}?{query}"),
		(false, false) => format!("{path}?{query}&raw_json=1"),
	})
}

/// Maps an error string from `client::json` to a status and error code.
fn classify(msg: &str) -> ApiError {
	if let Some(reason) = FORBIDDEN.into_iter().find(|r| *r == msg) {
		return ApiError(403, reason);
	}
	if msg.contains("rate limit") || msg.to_ascii_lowercase().contains("too many requests") {
		return ApiError(429, "rate_limited");
	}
	// Reddit's network-security block is an HTML page where JSON was expected
	if msg.starts_with("Failed to parse page JSON") {
		return ApiError(502, "blocked");
	}
	if msg.starts_with("Reddit error 404 ") {
		return NOT_FOUND;
	}
	ApiError(502, "upstream")
}

fn error_response(ApiError(status, error): ApiError) -> Response<Body> {
	respond(status, &json_value!({ "error": error, "status": status }))
}

fn respond(status: u16, body: &Value) -> Response<Body> {
	Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, "application/json")
		.header(header::CACHE_CONTROL, "no-store")
		.body(body.to_string().into())
		.unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use super::*;

	const TOKEN: &str = "s3cret-token";

	fn uri(s: &str) -> Uri {
		s.parse().unwrap()
	}

	#[test]
	fn token_compare() {
		assert!(token_eq(b"s3cret", b"s3cret"));
		assert!(!token_eq(b"s3cret", b"s3creT"));
		assert!(!token_eq(b"s3cret", b"t3cret"));
		assert!(!token_eq(b"s3cret", b"s3cre"));
		assert!(!token_eq(b"s3cret", b"s3cret!"));
		assert!(!token_eq(b"s3cret", b""));
		assert!(!token_eq(b"", b"s3cret"));
		// Equal, but `check` never gets here with an empty token
		assert!(token_eq(b"", b""));
	}

	#[test]
	fn bearer_header() {
		assert_eq!(bearer("Bearer abc"), Some("abc"));
		assert_eq!(bearer("bearer abc"), Some("abc"));
		assert_eq!(bearer("  Bearer   abc  "), Some("abc"));
		assert_eq!(bearer("Basic abc"), None);
		assert_eq!(bearer("Bearer"), None);
		assert_eq!(bearer("abc"), None);
	}

	#[test]
	fn disabled_without_token() {
		let u = uri("/api/v1/raw/r/rust/hot.json");
		assert_eq!(check(None, Some("Bearer x"), &u), Err(NOT_FOUND));
		assert_eq!(check(Some(""), Some("Bearer "), &u), Err(NOT_FOUND));
		assert_eq!(check(Some(""), None, &u), Err(NOT_FOUND));
		// Even a bad path is a 404 while disabled
		assert_eq!(check(None, None, &uri("/api/v1/raw/r/rust/about")), Err(NOT_FOUND));
	}

	#[test]
	fn requires_bearer_token() {
		let u = uri("/api/v1/raw/r/rust/hot.json");
		let auth = format!("Bearer {TOKEN}");
		assert_eq!(check(Some(TOKEN), None, &u), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some("Bearer wrong"), &u), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some("Bearer "), &u), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some(TOKEN), &u), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some(&format!("Basic {TOKEN}")), &u), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some(&format!("Bearer {TOKEN}x")), &u), Err(UNAUTHORIZED));
		// Auth is checked before the path, so a bad path without a token is a 401
		assert_eq!(check(Some(TOKEN), None, &uri("/api/v1/raw/r/rust/about")), Err(UNAUTHORIZED));
		assert_eq!(check(Some(TOKEN), Some(&auth), &u), Ok("/r/rust/hot.json?raw_json=1".into()));
		assert_eq!(check(Some(TOKEN), Some(&auth), &uri("/api/v1/raw/r/rust/about")), Err(BAD_PATH));
	}

	#[test]
	fn accepts_json_paths() {
		let ok = [
			("/api/v1/raw/r/popular/hot.json", None, "/r/popular/hot.json?raw_json=1"),
			("/api/v1/raw/r/rust/about.json", Some(""), "/r/rust/about.json?raw_json=1"),
			("/api/v1/raw/.json", None, "/.json?raw_json=1"),
			("/api/v1/raw/r/rust+linux/new.json", None, "/r/rust+linux/new.json?raw_json=1"),
			("/api/v1/raw/r/rust/comments/abc123.json", None, "/r/rust/comments/abc123.json?raw_json=1"),
			(
				"/api/v1/raw/r/rust/comments/abc123/some_title/def456.json",
				None,
				"/r/rust/comments/abc123/some_title/def456.json?raw_json=1",
			),
			("/api/v1/raw/r/de/comments/abc/f%C3%BCr_alle.json", None, "/r/de/comments/abc/f%C3%BCr_alle.json?raw_json=1"),
			("/api/v1/raw/by_id/t3_a,t3_b.json", None, "/by_id/t3_a,t3_b.json?raw_json=1"),
			("/api/v1/raw/r/a.b/x.json", None, "/r/a.b/x.json?raw_json=1"),
		];
		for (path, query, expected) in ok {
			assert_eq!(reddit_path(path, query).as_deref(), Some(expected), "{path}");
		}
	}

	#[test]
	fn query_passthrough() {
		let p = "/api/v1/raw/r/popular/hot.json";
		assert_eq!(reddit_path(p, Some("limit=5")).as_deref(), Some("/r/popular/hot.json?limit=5&raw_json=1"));
		assert_eq!(
			reddit_path(p, Some("after=t3_x&limit=25&geo_filter=GLOBAL")).as_deref(),
			Some("/r/popular/hot.json?after=t3_x&limit=25&geo_filter=GLOBAL&raw_json=1")
		);
		assert_eq!(reddit_path(p, Some("raw_json=1&limit=5")).as_deref(), Some("/r/popular/hot.json?raw_json=1&limit=5"));
		assert_eq!(reddit_path(p, Some("limit=5&raw_json=0")).as_deref(), Some("/r/popular/hot.json?limit=5&raw_json=0"));
		// A key that merely starts with raw_json is not raw_json
		assert_eq!(reddit_path(p, Some("raw_jsonx=1")).as_deref(), Some("/r/popular/hot.json?raw_jsonx=1&raw_json=1"));
		// `.json` is checked on the path, not the query
		assert_eq!(reddit_path("/api/v1/raw/r/rust/about", Some("x=.json")), None);
	}

	#[test]
	fn rejects_bad_paths() {
		let bad = [
			// Not under the prefix, or no leading slash after it
			"/r/rust/hot.json",
			"/api/v1/rawr/rust/hot.json",
			"/api/v1/raw",
			"/api/v1/raw/",
			// Not .json
			"/api/v1/raw/r/rust/about",
			"/api/v1/raw/r/rust/about.json/",
			"/api/v1/raw/r/rust/about.jsonx",
			"/api/v1/raw/r/rust/about%2Ejson",
			// Traversal
			"/api/v1/raw/r/rust/../x.json",
			"/api/v1/raw/../x.json",
			"/api/v1/raw/r/rust/..json",
			"/api/v1/raw/r/rust/%2e%2e/x.json",
			"/api/v1/raw/r/rust/%2E%2E/x.json",
			"/api/v1/raw/r/rust/.%2e/x.json",
			"/api/v1/raw/r/rust/%2e./x.json",
			"/api/v1/raw/r/rust/%252e%252e/x.json",
			// Backslashes
			"/api/v1/raw/r/rust\\x.json",
			"/api/v1/raw/r/rust/%5cx.json",
			"/api/v1/raw/r/rust/%5Cx.json",
			"/api/v1/raw/r/rust/%255cx.json",
		];
		for path in bad {
			assert_eq!(reddit_path(path, None), None, "{path}");
		}
	}

	#[test]
	fn api_paths_any_case() {
		for path in ["/api/v1/raw", "/API/V1/health", "/Api/v1/raw/r/rust/hot.json", "//api/v1/x", "/api/", "/api", "/aPi"] {
			assert!(is_api_path(path), "{path}");
		}
		for path in ["/", "/apix", "/apis/x", "/r/api/hot", "/rapi/", "/ap", ""] {
			assert!(!is_api_path(path), "{path}");
		}
	}

	#[test]
	fn error_mapping() {
		for reason in FORBIDDEN {
			assert_eq!(classify(reason), ApiError(403, reason));
		}
		// Reasons are matched exactly, never inside a message that quotes a path
		assert_eq!(classify("Couldn't send request to Reddit: timeout | /r/private/hot.json"), ApiError(502, "upstream"));
		assert_eq!(
			classify("Reddit rate limit exceeded. Try refreshing in a few seconds. Rate limit will reset in: 120"),
			ApiError(429, "rate_limited")
		);
		assert_eq!(classify("Reddit rate limit exceeded"), ApiError(429, "rate_limited"));
		assert_eq!(classify("Reddit returned 429 Too Many Requests for comments | x"), ApiError(429, "rate_limited"));
		assert_eq!(
			classify("Failed to parse page JSON data: expected value at line 1 column 1 | /r/x/comments/y.json"),
			ApiError(502, "blocked")
		);
		assert_eq!(classify("Reddit error 404 \"null\": \"Not Found\" | /r/x/about.json"), NOT_FOUND);
		assert_eq!(classify("Reddit error 400 \"null\": \"Bad Request\" | /x.json"), ApiError(502, "upstream"));
		assert_eq!(classify("Reddit is having issues, check if there's an outage"), ApiError(502, "upstream"));
		assert_eq!(classify("OAuth token has expired. Please refresh the page!"), ApiError(502, "upstream"));
		assert_eq!(classify(""), ApiError(502, "upstream"));
	}

	#[tokio::test]
	async fn error_body_shape() {
		let res = error_response(ApiError(403, "private"));
		assert_eq!(res.status(), 403);
		assert_eq!(res.headers()[header::CONTENT_TYPE], "application/json");
		assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
		let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
		assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json_value!({ "error": "private", "status": 403 }));
	}

	#[tokio::test]
	async fn health_is_ok() {
		let res = health(Request::new(Body::empty())).await.unwrap();
		assert_eq!(res.status(), 200);
		assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
		let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
		assert_eq!(&body[..], br#"{"ok":true}"#);
	}
}
