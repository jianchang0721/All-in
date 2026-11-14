package com.gaeul.allin;

import com.gaeul.allin.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ZCode 领取赠送额度的人机验证通道。
 *
 * <p>上游 {@code /api/v1/zcode-plan/billing/claim} 从 11-07 起在
 * {@code client/configs} 里把 {@code captcha.enabled} 打开：没有
 * {@code X-Aliyun-Captcha-Verify-Param} 的领取一律回 3007。上游社区插件
 * ({@code @magpie-community/opencode-zcode-auth} 0.1.61) 的注释写明，这个证明由
 * **官方客户端的 renderer 跑阿里云验证码 SDK 生成**，而且「invisibly as a rule」
 * —— 是无感验证，不是要人解谜题。网关缺的不是「答案」，而是**没有运行官方 SDK**。
 *
 * <p>本类不伪造、不绕过验证：只把 {@code configs.captcha} 下发的
 * {@code prefix / sceneId / region} 交给页面，由本应用的 WebView 加载阿里云官方
 * SDK 完成验证，再把 SDK 回调的 {@code captchaVerifyParam} 原样回传给原生侧，
 * 由 {@link ZCodeAuth#giftClaim} 放进请求头。token 只在内存里按账号短时存放，
 * 不落盘、不写日志、不进任何回复。
 */
public final class ZCodeCaptcha {

    private ZCodeCaptcha() {}

    /** 官方 Web/H5 SDK（实测 HTTP 200，226 KB）。 */
    public static final String SDK_URL =
            "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
    public static final String HEADER = "X-Aliyun-Captcha-Verify-Param";
    public static final String PAGE_PATH = "/api/zcode/captcha";
    public static final String TOKEN_PATH = "/api/zcode/captcha-token";

    /** 配置里这三个值会进 JS 字符串，只允许 SDK 参数字符集。 */
    private static final Pattern SAFE = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");
    private static final long TOKEN_TTL_MS = 5L * 60_000L;
    private static final int MAX_TOKENS = 64;
    private static final int MAX_TOKEN_CHARS = 8192;

    public interface Clock { long now(); }
    private static volatile Clock clock = new Clock() { public long now() { return System.currentTimeMillis(); } };
    /** 仅给测试注入时钟；null 恢复系统时钟。 */
    public static void setTestClock(Clock c) { clock = c == null ? new Clock() { public long now() { return System.currentTimeMillis(); } } : c; }

    /** 从 client/configs 的 {@code configs.captcha} 解析出的验证参数。 */
    public static final class Config {
        public final boolean enabled;
        public final String prefix, sceneId, region;
        public final boolean complete;
        Config(boolean enabled, String prefix, String sceneId, String region) {
            this.enabled = enabled;
            this.prefix = prefix == null ? "" : prefix;
            this.sceneId = sceneId == null ? "" : sceneId;
            this.region = region == null ? "" : region;
            this.complete = !this.prefix.isEmpty() && !this.sceneId.isEmpty() && !this.region.isEmpty();
        }
    }

    /** 解析配置；缺字段/类型不对时 enabled 按保守的 true 处理（不猜成「不用校验」）。 */
    public static Config config(JSONObject clientConfigs) {
        JSONObject cfg = clientConfigs == null ? null : clientConfigs.optJSONObject("configs");
        JSONObject c = cfg == null ? null : cfg.optJSONObject("captcha");
        if (c == null) return new Config(false, "", "", "");
        boolean enabled = c.optBoolean("enabled", true);
        return new Config(enabled, safe(c.optString("prefix", "")),
                safe(c.optString("sceneId", "")), safe(c.optString("region", "cn")));
    }

    /** 非法值一律丢弃，避免把上游文档里的任意字符串拼进 JS/HTML。 */
    static String safe(String raw) {
        if (raw == null || !SAFE.matcher(raw).matches()) return "";
        return raw;
    }

    /** 面板用：只返回非敏感的公开参数，不含任何凭据。 */
    public static JSONObject descriptor(Config c) {
        JSONObject out = new JSONObject();
        try {
            out.put("ok", c != null && c.complete);
            out.put("enabled", c != null && c.enabled);
            out.put("sdkUrl", SDK_URL);
            out.put("header", HEADER);
            out.put("tokenPath", TOKEN_PATH);
            if (c != null && c.complete) {
                out.put("prefix", c.prefix).put("sceneId", c.sceneId).put("region", c.region);
            } else {
                out.put("error", "ZCode 没有下发完整的验证码参数，请在官方 ZCode 客户端里领取");
            }
        } catch (Exception ignored) { }
        return out;
    }

    // ------------------------------------------------------------------ token store

    private static final class Stored {
        final String token; final long at;
        Stored(String token, long at) { this.token = token; this.at = at; }
    }
    private static final LinkedHashMap<String, Stored> TOKENS = new LinkedHashMap<String, Stored>();

    /** 账号隔离：只存 jwt+device 的摘要，绝不存明文。 */
    private static String scope(String jwt, String device) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            byte[] a = (jwt == null ? "" : jwt).getBytes(StandardCharsets.UTF_8);
            byte[] b = (device == null ? "" : device).getBytes(StandardCharsets.UTF_8);
            d.update(new byte[]{(byte)(a.length >>> 24), (byte)(a.length >>> 16), (byte)(a.length >>> 8), (byte)a.length});
            d.update(a); d.update(b);
            StringBuilder hex = new StringBuilder(64);
            for (byte x : d.digest()) hex.append(String.format(Locale.ROOT, "%02x", x & 255));
            return hex.toString();
        } catch (Exception e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }

    /** 存一次验证结果；只接受 SDK 回调的紧凑 token，拒绝空/超长/控制字符。 */
    public static synchronized boolean store(String jwt, String device, String token) {
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_CHARS) return false;
        for (int i = 0; i < token.length(); i++) {
            char ch = token.charAt(i);
            if (ch < 0x20 || ch > 0x7e) return false;
        }
        long now = clock.now();
        prune(now);
        if (TOKENS.size() >= MAX_TOKENS) TOKENS.remove(TOKENS.keySet().iterator().next());
        TOKENS.put(scope(jwt, device), new Stored(token, now));
        return true;
    }

    /** 取一次并消费：一个证明只用于一次领取，避免重放。 */
    public static synchronized String consume(String jwt, String device) {
        long now = clock.now();
        prune(now);
        Stored s = TOKENS.remove(scope(jwt, device));
        if (s == null || now < s.at || now - s.at >= TOKEN_TTL_MS) return "";
        return s.token;
    }

    /** 面板轮询用：验证是否已就绪，但不消费。 */
    public static synchronized boolean ready(String jwt, String device) {
        long now = clock.now();
        prune(now);
        Stored s = TOKENS.get(scope(jwt, device));
        return s != null && now >= s.at && now - s.at < TOKEN_TTL_MS;
    }

    private static void prune(long now) {
        Iterator<Map.Entry<String, Stored>> it = TOKENS.entrySet().iterator();
        while (it.hasNext()) {
            Stored s = it.next().getValue();
            if (now < s.at || now - s.at >= TOKEN_TTL_MS) it.remove();
        }
    }

    /** 只给测试：清空内存态。 */
    public static synchronized void clear() { TOKENS.clear(); }
}
