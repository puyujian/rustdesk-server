//! 订阅验证模块
//!
//! 提供订阅状态检查和 relay 白名单管理功能
//! - hbbs: 通过 token 检查订阅状态，写入 relay 白名单
//! - hbbr: 消费 relay 白名单验证

use hbb_common::log;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// API 服务器地址
/// 优先读取 API_SERVER，其次读取 RUSTDESK_API_RUSTDESK_API_SERVER
pub static API_SERVER: Lazy<String> = Lazy::new(|| {
    env::var("API_SERVER")
        .or_else(|_| env::var("RUSTDESK_API_RUSTDESK_API_SERVER"))
        .unwrap_or_else(|_| "http://127.0.0.1:21114".to_string())
});

/// 内部 API 密钥 (可选)
pub static INTERNAL_KEY: Lazy<String> = Lazy::new(|| {
    env::var("RUSTDESK_API_INTERNAL_KEY").unwrap_or_default()
});

/// 全局 HTTP 客户端 (复用连接池)
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(API_TIMEOUT_MS))
        .pool_max_idle_per_host(5)
        .build()
        .expect("Failed to build HTTP client")
});

/// 订阅状态缓存: token_hash -> (is_active, cached_at)
static SUBSCRIPTION_CACHE: Lazy<RwLock<HashMap<String, (bool, Instant)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// 缓存 TTL - 订阅有效 (秒)
const CACHE_TTL_ACTIVE_SECS: u64 = 300; // 5 分钟

/// 缓存 TTL - 订阅无效 (秒) - 更短以便续费后快速生效
const CACHE_TTL_INACTIVE_SECS: u64 = 60; // 1 分钟

/// API 超时 (毫秒)
const API_TIMEOUT_MS: u64 = 500;

/// API 响应结构
#[derive(Deserialize, Debug)]
struct ApiResponse {
    code: i32,
    data: Option<serde_json::Value>,
}

/// 订阅检查响应数据
#[derive(Deserialize, Debug)]
struct SubscriptionData {
    active: bool,
    payment_enabled: bool,
}

/// Relay 消费响应数据
#[derive(Deserialize, Debug)]
struct RelayConsumeData {
    allowed: bool,
}

/// Relay Allow 响应数据
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct RelayAllowData {
    uuid: String,
}

// ============ 辅助函数 ============

/// 计算 token 的 SHA-256 hash 作为缓存 key
fn hash_token(token: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // 使用 DefaultHasher 计算 hash (比 SHA-256 轻量，足够用于缓存 key)
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("t:{:016x}", hasher.finish())
}

/// 获取缓存 TTL
fn get_cache_ttl(is_active: bool) -> Duration {
    if is_active {
        Duration::from_secs(CACHE_TTL_ACTIVE_SECS)
    } else {
        Duration::from_secs(CACHE_TTL_INACTIVE_SECS)
    }
}

// ============ hbbs 使用的函数 ============

/// 通过 token 检查订阅状态 (用于 hbbs PunchHoleRequest)
///
/// 返回 true 表示订阅有效或支付功能未启用
pub async fn check_subscription_by_token(token: &str) -> bool {
    // 生成缓存 key (使用 token 的 hash)
    let cache_key = hash_token(token);

    // 1. 查缓存 (读时清理过期条目)
    {
        let cache = SUBSCRIPTION_CACHE.read().unwrap();
        if let Some(&(is_active, cached_at)) = cache.get(&cache_key) {
            let ttl = get_cache_ttl(is_active);
            if cached_at.elapsed() < ttl {
                log::debug!("Subscription cache hit: active={}", is_active);
                return is_active;
            }
        }
    }

    // 过期则删除 (需要写锁)
    {
        let mut cache = SUBSCRIPTION_CACHE.write().unwrap();
        if let Some(&(is_active, cached_at)) = cache.get(&cache_key) {
            let ttl = get_cache_ttl(is_active);
            if cached_at.elapsed() >= ttl {
                cache.remove(&cache_key);
            }
        }
    }

    // 2. 调用 API (使用 POST body 传递 token，避免泄露到日志)
    let result = call_subscription_check_api(token).await;

    // 3. 更新缓存
    {
        let mut cache = SUBSCRIPTION_CACHE.write().unwrap();
        cache.insert(cache_key, (result, Instant::now()));
    }

    result
}

/// 写入 relay 白名单 (用于 hbbs RequestRelay 时调用)
///
/// uuid: relay 会话 uuid
/// slots: 允许消费次数 (默认 2)
/// ttl_sec: 过期时间秒数 (默认 120)
pub async fn allow_relay(uuid: &str, slots: i32, ttl_sec: i32) -> bool {
    let url = format!("{}/api/internal/relay/allow", *API_SERVER);

    let body = serde_json::json!({
        "uuid": uuid,
        "slots": slots,
        "ttl_sec": ttl_sec
    });

    let mut req = HTTP_CLIENT.post(&url).json(&body);

    // 添加内部鉴权头
    if !INTERNAL_KEY.is_empty() {
        req = req.header("X-Internal-Key", INTERNAL_KEY.as_str());
    }

    match req.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                // 解析响应检查 code
                match resp.json::<ApiResponse>().await {
                    Ok(api_resp) => {
                        if api_resp.code == 0 || api_resp.code == 200 {
                            log::debug!("Relay allow success: uuid={}", uuid);
                            return true;
                        }
                        log::error!("Relay allow failed: code={}", api_resp.code);
                        false
                    }
                    Err(e) => {
                        log::error!("Relay allow parse error: {}", e);
                        false
                    }
                }
            } else {
                log::error!("Relay allow failed: status={}", resp.status());
                false
            }
        }
        Err(e) => {
            log::error!("Relay allow API call failed: {}", e);
            false
        }
    }
}

// ============ hbbr 使用的函数 ============

/// 消费 relay 白名单 (用于 hbbr RequestRelay)
///
/// 返回 true 表示允许 relay
pub async fn consume_relay(uuid: &str) -> bool {
    let url = format!("{}/api/internal/relay/consume", *API_SERVER);

    let body = serde_json::json!({
        "uuid": uuid
    });

    let mut req = HTTP_CLIENT.post(&url).json(&body);

    // 添加内部鉴权头
    if !INTERNAL_KEY.is_empty() {
        req = req.header("X-Internal-Key", INTERNAL_KEY.as_str());
    }

    match req.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<ApiResponse>().await {
                    Ok(api_resp) => {
                        // 检查 code
                        if api_resp.code != 0 && api_resp.code != 200 {
                            log::error!("Relay consume failed: code={}", api_resp.code);
                            return false;
                        }
                        if let Some(data) = api_resp.data {
                            if let Ok(consume_data) = serde_json::from_value::<RelayConsumeData>(data) {
                                log::debug!("Relay consume: uuid={} allowed={}", uuid, consume_data.allowed);
                                return consume_data.allowed;
                            }
                        }
                        log::error!("Relay consume: invalid response data");
                        false
                    }
                    Err(e) => {
                        log::error!("Relay consume: parse error: {}", e);
                        false
                    }
                }
            } else {
                log::error!("Relay consume failed: status={}", resp.status());
                false
            }
        }
        Err(e) => {
            log::error!("Relay consume API call failed: {}", e);
            // API 不可用时拒绝 (保守策略)
            false
        }
    }
}

// ============ 内部辅助函数 ============

/// 调用订阅检查 API (使用 POST body 传递 token)
async fn call_subscription_check_api(token: &str) -> bool {
    let url = format!("{}/api/internal/subscription/check", *API_SERVER);

    // 使用 POST body 传递 token，避免泄露到 URL/日志
    let body = serde_json::json!({
        "token": token
    });

    let mut req = HTTP_CLIENT.post(&url).json(&body);

    // 添加内部鉴权头
    if !INTERNAL_KEY.is_empty() {
        req = req.header("X-Internal-Key", INTERNAL_KEY.as_str());
    }

    match req.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<ApiResponse>().await {
                    Ok(api_resp) => {
                        // 检查 code
                        if api_resp.code != 0 && api_resp.code != 200 {
                            log::error!("Subscription API failed: code={}", api_resp.code);
                            return handle_api_failure(token);
                        }
                        if let Some(data) = api_resp.data {
                            if let Ok(sub_data) = serde_json::from_value::<SubscriptionData>(data) {
                                // 支付未启用时视为放行
                                if !sub_data.payment_enabled {
                                    log::debug!("Payment disabled, allowing access");
                                    return true;
                                }
                                log::debug!("Subscription check: active={}", sub_data.active);
                                return sub_data.active;
                            }
                        }
                        log::error!("Subscription API: invalid response data");
                        handle_api_failure(token)
                    }
                    Err(e) => {
                        log::error!("Subscription API parse error: {}", e);
                        handle_api_failure(token)
                    }
                }
            } else {
                log::error!("Subscription API status: {}", resp.status());
                handle_api_failure(token)
            }
        }
        Err(e) => {
            log::error!("Subscription API call failed: {}", e);
            handle_api_failure(token)
        }
    }
}

/// API 失败时的处理策略
fn handle_api_failure(token: &str) -> bool {
    // 尝试使用旧缓存
    let cache_key = hash_token(token);
    let cache = SUBSCRIPTION_CACHE.read().unwrap();
    if let Some(&(is_active, _)) = cache.get(&cache_key) {
        log::warn!("Using stale cache for subscription check");
        return is_active;
    }
    // 无缓存时拒绝 (保守策略)
    log::warn!("No cache available, denying access");
    false
}

/// 清理过期缓存 (可由外部定时调用)
pub fn cleanup_caches() {
    let now = Instant::now();

    // 清理订阅缓存 (保留 2 倍 TTL 以支持 stale cache)
    let mut cache = SUBSCRIPTION_CACHE.write().unwrap();
    cache.retain(|_, (is_active, cached_at)| {
        let max_ttl = if *is_active {
            CACHE_TTL_ACTIVE_SECS * 2
        } else {
            CACHE_TTL_INACTIVE_SECS * 2
        };
        now.duration_since(*cached_at) < Duration::from_secs(max_ttl)
    });
}
