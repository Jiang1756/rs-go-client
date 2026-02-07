//! 免密连接票据验证模块
//!
//! 该模块实现了对 API Server 签发的免密连接票据的验证逻辑。
//! 使用 Ed25519 签名算法进行离线验签。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::hbbs_http::{create_http_client_with_url, HbbHttpResponse};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hbb_common::{
    config::{keys, Config, LocalConfig},
    log,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 票据前缀
const TICKET_PREFIX: &str = "TICKET:v1:";
const TICKET_PUBLIC_KEY_OPTION: &str = "ticket-public-key";

#[derive(Debug, Deserialize)]
struct TicketPublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
struct TicketResponse {
    pub ticket: String,
    #[serde(default)]
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
struct TicketRequest {
    target_id: String,
}

/// 票据载荷结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketPayload {
    /// 主控端设备 ID
    pub src_id: String,
    /// 被控端设备 ID  
    pub dst_id: String,
    /// 过期时间戳 (Unix 秒)
    pub exp: i64,
    /// 随机数
    pub nonce: String,
    /// 签发时间戳
    pub iat: i64,
}

/// 票据验证器
pub struct TicketVerifier {
    /// Ed25519 公钥
    public_key: Option<VerifyingKey>,
}

fn build_api_url(api_server: &str, path: &str) -> Option<String> {
    let base = api_server.trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    Some(format!("{base}{path}"))
}

fn fetch_ticket_public_key(api_server: &str) -> Option<String> {
    let url = build_api_url(api_server, "/api/ticket/pubkey")?;
    log::debug!("开始获取票据公钥: {}", url);
    let client = create_http_client_with_url(&url);
    let resp = client.get(&url).timeout(Duration::from_secs(5)).send();
    match resp {
        Ok(resp) => match HbbHttpResponse::<TicketPublicKeyResponse>::try_from(resp) {
            Ok(HbbHttpResponse::Data(data)) if !data.public_key.is_empty() => {
                log::debug!("获取票据公钥成功: len={}", data.public_key.len());
                Some(data.public_key)
            }
            Ok(HbbHttpResponse::Error(err)) => {
                log::warn!("获取票据公钥失败: {}", err);
                None
            }
            Ok(_) => None,
            Err(err) => {
                log::warn!("票据公钥响应解析失败: {}", err);
                None
            }
        },
        Err(err) => {
            log::warn!("票据公钥请求错误: {}", err);
            None
        }
    }
}

fn request_ticket(api_server: &str, access_token: &str, target_id: &str) -> Option<String> {
    let url = build_api_url(api_server, "/api/ticket")?;
    log::debug!(
        "开始请求票据: url={} target_id={} token_len={}",
        url,
        target_id,
        access_token.len()
    );
    let client = create_http_client_with_url(&url);
    let resp = client
        .post(&url)
        .timeout(Duration::from_secs(8))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&TicketRequest {
            target_id: target_id.to_owned(),
        })
        .send();
    match resp {
        Ok(resp) => match HbbHttpResponse::<TicketResponse>::try_from(resp) {
            Ok(HbbHttpResponse::Data(data)) if !data.ticket.is_empty() => {
                log::debug!(
                    "获取票据成功: len={} expires_in={}",
                    data.ticket.len(),
                    data.expires_in
                );
                Some(data.ticket)
            }
            Ok(HbbHttpResponse::Error(err)) => {
                log::warn!("获取票据失败: {}", err);
                None
            }
            Ok(_) => None,
            Err(err) => {
                log::warn!("票据响应解析失败: {}", err);
                None
            }
        },
        Err(err) => {
            log::warn!("票据请求错误: {}", err);
            None
        }
    }
}

fn get_cached_public_key() -> String {
    let key = crate::get_builtin_option(TICKET_PUBLIC_KEY_OPTION);
    if !key.is_empty() {
        log::debug!("票据公钥使用内置配置");
        return key;
    }
    LocalConfig::get_option(TICKET_PUBLIC_KEY_OPTION)
}

pub fn get_ticket_public_key() -> String {
    let cached = get_cached_public_key();
    if !cached.is_empty() {
        log::debug!("票据公钥使用本地缓存");
        return cached;
    }
    let api_server = Config::get_option(keys::OPTION_API_SERVER);
    if api_server.is_empty() {
        log::debug!("票据公钥获取跳过: 未配置 api-server");
        return String::new();
    }
    if let Some(key) = fetch_ticket_public_key(&api_server) {
        if !key.is_empty() {
            LocalConfig::set_option(TICKET_PUBLIC_KEY_OPTION.to_owned(), key.clone());
        }
        log::debug!("票据公钥从 API 获取完成");
        return key;
    }
    String::new()
}

pub fn try_request_ticket(target_id: &str) -> Option<String> {
    if target_id.is_empty() {
        log::debug!("票据请求跳过: target_id 为空");
        return None;
    }
    let api_server = Config::get_option(keys::OPTION_API_SERVER);
    if api_server.is_empty() {
        log::debug!("票据请求跳过: 未配置 api-server");
        return None;
    }
    let access_token = LocalConfig::get_option("access_token");
    if access_token.is_empty() {
        log::debug!("票据请求跳过: access_token 为空");
        return None;
    }
    let target_id = target_id.split('@').next().unwrap_or(target_id);
    log::debug!("票据请求准备完成: target_id={}", target_id);
    request_ticket(&api_server, &access_token, target_id)
}

impl TicketVerifier {
    /// 创建新的票据验证器
    pub fn new() -> Self {
        Self { public_key: None }
    }

    /// 使用十六进制字符串设置公钥
    /// 公钥应从 API Server 获取并内置到客户端
    pub fn set_public_key_hex(&mut self, hex_key: &str) -> Result<(), String> {
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| format!("解码公钥失败: {}", e))?;
        
        if key_bytes.len() != 32 {
            return Err(format!("公钥长度无效: 期望 32 字节, 实际 {} 字节", key_bytes.len()));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| format!("解析公钥失败: {}", e))?;
        
        self.public_key = Some(verifying_key);
        Ok(())
    }

    /// 验证票据
    /// 
    /// # 参数
    /// - `ticket`: 票据字符串 (格式: TICKET:v1:<base64url(payload)>.<base64url(signature)>)
    /// - `my_device_id`: 本机设备 ID (用于验证 dst_id)
    /// 
    /// # 返回
    /// - `Ok(TicketPayload)`: 验证成功，返回载荷
    /// - `Err(String)`: 验证失败，返回错误信息
    pub fn verify(&self, ticket: &str, my_device_id: &str) -> Result<TicketPayload, String> {
        // 检查公钥是否已设置
        let public_key = self.public_key.as_ref()
            .ok_or_else(|| "公钥未设置".to_string())?;

        // 检查票据格式
        if !ticket.starts_with(TICKET_PREFIX) {
            return Err("票据格式无效: 缺少前缀".to_string());
        }

        let content = &ticket[TICKET_PREFIX.len()..];
        
        // 分割载荷和签名
        let dot_pos = content.rfind('.')
            .ok_or_else(|| "票据格式无效: 缺少签名分隔符".to_string())?;
        
        let payload_b64 = &content[..dot_pos];
        let signature_b64 = &content[dot_pos + 1..];

        // 解码载荷
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)
            .map_err(|e| format!("解码载荷失败: {}", e))?;

        // 解码签名
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64)
            .map_err(|e| format!("解码签名失败: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!("签名长度无效: 期望 64 字节, 实际 {} 字节", signature_bytes.len()));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // 验证签名
        public_key.verify(&payload_bytes, &signature)
            .map_err(|_| "签名验证失败".to_string())?;

        // 解析载荷
        let payload: TicketPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("解析载荷失败: {}", e))?;

        // 检查过期时间 (允许 30 秒时钟偏差)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        if payload.exp < now - 30 {
            return Err("票据已过期".to_string());
        }

        // 检查目标设备 ID
        if !my_device_id.is_empty() && payload.dst_id != my_device_id {
            return Err(format!("目标设备 ID 不匹配: 期望 {}, 实际 {}", my_device_id, payload.dst_id));
        }

        log::info!("票据验证成功: src_id={}, dst_id={}", payload.src_id, payload.dst_id);
        Ok(payload)
    }
}

/// 检查密码是否为票据格式
pub fn is_ticket(password: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(password) {
        s.starts_with(TICKET_PREFIX)
    } else {
        false
    }
}

/// 尝试验证票据
/// 
/// # 参数
/// - `password`: 密码字节数组 (可能是票据)
/// - `my_device_id`: 本机设备 ID
/// - `public_key_hex`: API Server 的公钥 (十六进制)
/// 
/// # 返回
/// - `Some(TicketPayload)`: 验证成功
/// - `None`: 不是票据或验证失败
pub fn try_verify_ticket(password: &[u8], my_device_id: &str, public_key_hex: &str) -> Option<TicketPayload> {
    let ticket_str = match std::str::from_utf8(password) {
        Ok(s) => s,
        Err(_) => return None,
    };

    if !ticket_str.starts_with(TICKET_PREFIX) {
        return None;
    }

    let mut verifier = TicketVerifier::new();
    if let Err(e) = verifier.set_public_key_hex(public_key_hex) {
        log::warn!("设置票据公钥失败: {}", e);
        return None;
    }

    match verifier.verify(ticket_str, my_device_id) {
        Ok(payload) => Some(payload),
        Err(e) => {
            log::warn!("票据验证失败: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ticket() {
        assert!(is_ticket(b"TICKET:v1:abc.def"));
        assert!(!is_ticket(b"password123"));
        assert!(!is_ticket(b""));
    }
}
