use candid::{define_function, CandidType, Deserialize};
use serde_bytes::ByteBuf;

pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Token {}

define_function!(pub StreamingCallbackFunction : (Token) -> (StreamingCallbackHttpResponse) query);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum StreamingStrategy {
    Callback {
        callback: StreamingCallbackFunction,
        token: Token,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    pub body: ByteBuf,
    pub token: Option<Token>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
    pub certificate_version: Option<u16>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: ByteBuf,
    pub upgrade: Option<bool>,
    pub streaming_strategy: Option<StreamingStrategy>,
}

pub fn http_request(req: HttpRequest) -> HttpResponse {
    let parts: Vec<&str> = req.url.split('?').collect();
    match parts[0] {
        "/prepare" => HttpResponse {
            status_code: 200,
            headers: req.headers,
            body: ByteBuf::from(vec![]),
            upgrade: Some(true),
            streaming_strategy: None,
        },
        _ => {
            let headers = vec![(
                "Content-Type".to_string(),
                "text/plain; version=0.0.4".to_string(),
            )];
            HttpResponse {
                status_code: 200,
                headers,
                body: ByteBuf::from(format!("Invalid Request")),
                upgrade: Some(true),
                streaming_strategy: None,
            }
        }
    }
}
