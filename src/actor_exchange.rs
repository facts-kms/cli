use std::collections::BTreeSet;

pub const REQUEST_SCHEMA: &str = "fact-remote-actor-request-v0";
pub const RESPONSE_SCHEMA: &str = "fact-remote-actor-response-v0";
pub const REQUEST_BEGIN: &str = "-----BEGIN FACT REMOTE ACTOR REQUEST-----";
pub const REQUEST_END: &str = "-----END FACT REMOTE ACTOR REQUEST-----";
pub const RESPONSE_BEGIN: &str = "-----BEGIN FACT REMOTE ACTOR RESPONSE-----";
pub const RESPONSE_END: &str = "-----END FACT REMOTE ACTOR RESPONSE-----";

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorClaims {
    pub display_name: Option<String>,
    pub alias: Option<String>,
    pub actor_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorRequest {
    pub schema: String,
    pub actor: uuid::Uuid,
    pub claims: ActorClaims,
    pub requests: Vec<String>,
    pub bundle: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ResponseLedger {
    pub id: uuid::Uuid,
    pub genesis_hash: String,
    pub namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ResponseEndpoint {
    pub schema: String,
    pub url: String,
    pub ledger_id: String,
    pub genesis_hash: String,
    pub token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ActorResponse {
    pub schema: String,
    pub outcome: String,
    pub actor: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<ActorClaims>,
    pub ledger: ResponseLedger,
    pub granted: Vec<String>,
    pub endpoint: ResponseEndpoint,
    pub in_reply_to: String,
    pub bundle: String,
}

pub fn encode_actor_request(
    actor: uuid::Uuid,
    claims: ActorClaims,
    requests: Vec<String>,
    bundle: &[u8],
) -> ActorRequest {
    ActorRequest {
        schema: REQUEST_SCHEMA.to_owned(),
        actor,
        claims,
        requests,
        bundle: encode_base64url(bundle),
    }
}

pub fn encode_actor_response(
    actor: uuid::Uuid,
    claims: Option<ActorClaims>,
    ledger: ResponseLedger,
    granted: Vec<String>,
    endpoint: ResponseEndpoint,
    in_reply_to: String,
    bundle: &[u8],
) -> ActorResponse {
    ActorResponse {
        schema: RESPONSE_SCHEMA.to_owned(),
        outcome: "granted".to_owned(),
        actor,
        claims,
        ledger,
        granted,
        endpoint,
        in_reply_to,
        bundle: encode_base64url(bundle),
    }
}

pub fn request_json(request: &ActorRequest, wrapped: bool) -> Result<Vec<u8>, serde_json::Error> {
    artifact_json(request, wrapped.then_some((REQUEST_BEGIN, REQUEST_END)))
}

pub fn response_json(
    response: &ActorResponse,
    wrapped: bool,
) -> Result<Vec<u8>, serde_json::Error> {
    artifact_json(response, wrapped.then_some((RESPONSE_BEGIN, RESPONSE_END)))
}

pub fn parse_request(bytes: &[u8]) -> Result<ActorRequest, String> {
    let value = artifact_value(bytes, REQUEST_BEGIN, REQUEST_END)?;
    let schema = schema_name(&value)?;
    if schema != REQUEST_SCHEMA {
        return Err("expected a remote actor request artifact".to_owned());
    }
    let request: ActorRequest = serde_json::from_value(value).map_err(|error| error.to_string())?;
    decode_base64url(&request.bundle)
        .ok_or_else(|| "request bundle contains invalid base64url".to_owned())?;
    Ok(request)
}

pub fn parse_response(bytes: &[u8]) -> Result<ActorResponse, String> {
    let value = artifact_value(bytes, RESPONSE_BEGIN, RESPONSE_END)?;
    let schema = schema_name(&value)?;
    if schema != RESPONSE_SCHEMA {
        return Err("expected a remote actor response artifact".to_owned());
    }
    let response: ActorResponse =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    if response.outcome != "granted" {
        return Err(format!(
            "unsupported actor response outcome {}",
            response.outcome
        ));
    }
    decode_base64url(&response.bundle)
        .ok_or_else(|| "response bundle contains invalid base64url".to_owned())?;
    Ok(response)
}

pub fn request_bundle(request: &ActorRequest) -> Result<Vec<u8>, String> {
    decode_base64url(&request.bundle)
        .ok_or_else(|| "request bundle contains invalid base64url".to_owned())
}

pub fn response_bundle(response: &ActorResponse) -> Result<Vec<u8>, String> {
    decode_base64url(&response.bundle)
        .ok_or_else(|| "response bundle contains invalid base64url".to_owned())
}

pub fn response_grants_match_bundle(response: &ActorResponse) -> Result<bool, String> {
    let bundle = response_bundle(response)?;
    let bundle = fact_commitment::decode_bundle(&bundle).map_err(|error| error.to_string())?;
    let expected = response
        .granted
        .iter()
        .cloned()
        .collect::<BTreeSet<String>>();
    let mut actual = BTreeSet::new();
    for object in bundle.objects {
        let payload = fact_crypto::decode_sign1(&object)
            .map_err(|error| error.to_string())?
            .payload;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
        if value.get("object_type").and_then(serde_json::Value::as_str)
            != Some("authorization_grant")
        {
            continue;
        }
        let body = value
            .get("body")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "authorization grant has no body".to_owned())?;
        if body
            .get("receiving_actor_id")
            .and_then(serde_json::Value::as_str)
            != Some(response.actor.to_string().as_str())
        {
            continue;
        }
        if let Some(capabilities) = body
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
        {
            for capability in capabilities {
                if let Some(capability) = capability.as_str() {
                    actual.insert(capability.to_owned());
                }
            }
        }
    }
    Ok(actual == expected)
}

fn artifact_json<T: serde::Serialize>(
    value: &T,
    delimiters: Option<(&str, &str)>,
) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    Ok(match delimiters {
        Some((begin, end)) => format!("{begin}\n{json}\n{end}\n").into_bytes(),
        None => json.into_bytes(),
    })
}

fn artifact_value(bytes: &[u8], begin: &str, end: &str) -> Result<serde_json::Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let trimmed = text.trim();
    let json = if trimmed.starts_with(begin) {
        trimmed
            .strip_prefix(begin)
            .and_then(|value| value.trim().strip_suffix(end))
            .map(str::trim)
            .ok_or_else(|| format!("missing {end}"))?
    } else {
        trimmed
    };
    serde_json::from_str(json).map_err(|error| error.to_string())
}

fn schema_name(value: &serde_json::Value) -> Result<String, String> {
    value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "artifact is missing its format marker".to_owned())
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index < bytes.len() {
        let b0 = bytes[index];
        let b1 = bytes.get(index + 1).copied().unwrap_or(0);
        let b2 = bytes.get(index + 2).copied().unwrap_or(0);
        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if index + 1 < bytes.len() {
            output.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if index + 2 < bytes.len() {
            output.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
        index += 3;
    }
    output
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = Vec::new();
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        bits = (bits << 6) | value;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_request_round_trips_wrapped_and_reindented_bundle() {
        let actor = uuid::Uuid::now_v7();
        let request = encode_actor_request(
            actor,
            ActorClaims {
                display_name: Some("Al Newkirk".into()),
                alias: Some("alnewkirk".into()),
                actor_type: Some("human".into()),
            },
            vec!["propose".into(), "comment".into()],
            b"FACTBNDL bytes",
        );
        let wrapped = request_json(&request, true).unwrap();
        let parsed = parse_request(&wrapped).unwrap();
        assert_eq!(parsed.schema, REQUEST_SCHEMA);
        assert_eq!(parsed.actor, actor);
        assert_eq!(request_bundle(&parsed).unwrap(), b"FACTBNDL bytes");
        let spaced_bundle = format!("{}\n{}", &request.bundle[..8], &request.bundle[8..]);
        assert_eq!(decode_base64url(&spaced_bundle).unwrap(), b"FACTBNDL bytes");
    }

    #[test]
    fn actor_response_rejects_wrong_artifact_type() {
        let request = encode_actor_request(
            uuid::Uuid::now_v7(),
            ActorClaims {
                display_name: None,
                alias: None,
                actor_type: None,
            },
            Vec::new(),
            b"bundle",
        );
        let error = parse_response(&request_json(&request, false).unwrap()).unwrap_err();
        assert!(error.contains("expected a remote actor response artifact"));
        assert!(!error.contains("fact-remote-actor"));
    }
}
