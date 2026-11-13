package com.gaeul.allin;

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

/**
 * ZCode（智谱 GLM Coding Plan）付费 Plan 出站请求的客户端身份。
 *
 * <p>背景：智谱的 {@code open.bigmodel.cn/api/coding/paas/v4} 与
 * {@code api.z.ai/api/anthropic} 对客户端有指纹门。请求若不带 ZCode Desktop 的
 * 身份头组（只有 {@code Authorization} 与 {@code Content-Type}，User-Agent 是
 * Android 的 {@code Dalvik/...} 或下游客户端的 {@code claude-cli/...}），上游会回
 * 403 并提示「非官方客户端」，或被静默降载。赠送额度通道
 * {@link ZCodeGift#openStream} 已经整组复制了桌面客户端的头，付费 Plan 的两条共享
 * 出站构造器此前没有，这是 403 的直接原因。
 *
 * <p>本类只产头、不改请求体、不碰 {@code zcode.z.ai} 的 JWT/验证码通道。注入发生在
 * 所有规则头之后，因此签名 quirks 文档即使改写了 {@code User-Agent} 也会被这里的
 * 身份覆盖；鉴权与协议头（{@code Authorization} / {@code x-api-key} /
 * {@code anthropic-version} / {@code anthropic-beta} / {@code Content-Type}）不在
 * 本类写入或剥离的范围内。
 *
 * <p>版本号与 {@link ZCodeAuth#APP_VERSION} 同源，保持登录、余额、领取、赠送额度
 * 与付费 Plan 自称同一个客户端版本。平台字段与 {@link ZCodeGift#platform()} 同源。
 *
 * <p><b>OS 指纹必须抹掉 Android 标记</b>：官方客户端是桌面 Electron，其
 * {@code X-Os-Version} 不可能是 Android 内核串（如
 * {@code 5.10.168-android13-...}）。上游在指纹里看到 {@code android} 就按
 * 「非官方 / 异常客户端」拦掉（405/3012 或 403）。{@link ZCodeGift#osRelease()}
 * 已经这样处理，本类必须同口径，否则付费 Plan 通道会重演同一个 403。
 */
final class ZCodeIdentity {

    private ZCodeIdentity() {}

    static final String APP_VERSION = ZCodeAuth.APP_VERSION;

    private static final String UA = "ZCode/" + APP_VERSION;
    /** ai-sdk 的 Anthropic 栈与 OpenAI/CC 栈 UA 不同，取自 ZCode Desktop 抓包。 */
    static final String UA_ANTHROPIC = UA + " ai-sdk/anthropic/3.0.81";
    static final String UA_OPENAI = UA + " ai-sdk/provider-utils/4.0.27 runtime/node.js/24";

    /** 与 ZCode 指纹冲突、且可能由下游客户端或规则文档带进来的身份头。 */
    private static final Set<String> CONFLICT_NAMES = Collections.unmodifiableSet(
            new LinkedHashSet<String>(Arrays.asList(
                    "user-agent", "x-app", "x-claude-code-session-id", "x-client-request-id",
                    "anthropic-dangerous-direct-browser-access", "originator", "version",
                    "session_id", "conversation_id", "x-title", "http-referer", "referer",
                    "x-zcode-app-version", "x-zcode-agent", "x-release-channel",
                    "x-platform", "x-os-category", "x-os-version")));

    private static final String[] CONFLICT_PREFIXES = {
            "x-stainless-", "x-codex-", "x-claude-code-", "x-zcode-", "x-query-id",
            "x-request-id", "x-session-id", "x-client-"
    };

    /**
     * 一次请求要带的完整 ZCode Desktop 身份头组。
     *
     * @param accountScope 稳定账号标识，用于派生恒定的 {@code x-session-id}
     * @param anthropic    true 走原生 Anthropic Messages，false 走 OpenAI Chat Completions
     * @param stream       是否流式，决定 {@code Accept}
     */
    static Map<String, String> headers(String accountScope, boolean anthropic, boolean stream) {
        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("User-Agent", anthropic ? UA_ANTHROPIC : UA_OPENAI);
        h.put("X-ZCode-App-Version", APP_VERSION);
        h.put("X-ZCode-Agent", "glm");
        h.put("X-Title", "Z Code@electron");
        h.put("X-Release-Channel", "production");
        h.put("HTTP-Referer", "https://zcode.z.ai");
        h.put("X-Client-Language", clientLanguage());
        h.put("X-Client-Timezone", timezone());
        h.put("X-Platform", platform());
        h.put("X-Os-Category", "linux");
        h.put("X-Os-Version", osRelease());
        // 每请求随机，避免同一账号的请求在服务端被折叠成一次会话。
        h.put("x-request-id", UUID.randomUUID().toString());
        h.put("x-zcode-trace-id", UUID.randomUUID().toString());
        h.put("x-query-id", UUID.randomUUID().toString());
        // 按账号稳定派生：同一账号多次请求共享同一会话指纹。
        h.put("x-session-id", sessionId(accountScope));
        h.put("x-zcode-session-type", "main");
        h.put("x-zcode-query-source", "main_turn");
        h.put("Accept", stream ? "text/event-stream" : "application/json");
        return h;
    }

    /** 把身份头整组写到已建好连接的最后一步；只写身份头，不覆盖鉴权与协议头。 */
    static void apply(HttpURLConnection conn, String accountScope, boolean anthropic, boolean stream) {
        if (conn == null) return;
        for (Map.Entry<String, String> e : headers(accountScope, anthropic, stream).entrySet()) {
            conn.setRequestProperty(e.getKey(), e.getValue());
        }
    }

    /**
     * 过滤规则文档/透传头里与本指纹冲突的身份头，供 {@code applyQuirkHeaders} 之前调用。
     * 保留 {@code authorization} / {@code x-api-key} / {@code content-type} /
     * {@code anthropic-version} / {@code anthropic-beta} / {@code accept} 等非身份头。
     */
    static Map<String, String> stripConflicts(Map<String, String> in) {
        if (in == null || in.isEmpty()) return Collections.emptyMap();
        Map<String, String> out = new LinkedHashMap<String, String>();
        for (Map.Entry<String, String> e : in.entrySet()) {
            String name = e.getKey() == null ? "" : e.getKey().trim().toLowerCase(Locale.ROOT);
            if (name.isEmpty() || conflicts(name)) continue;
            out.put(e.getKey(), e.getValue());
        }
        return out;
    }

    static boolean conflicts(String lowerName) {
        if (lowerName == null) return false;
        if (CONFLICT_NAMES.contains(lowerName)) return true;
        for (String prefix : CONFLICT_PREFIXES) if (lowerName.startsWith(prefix)) return true;
        return false;
    }

    /** 同一账号恒定；只把账号标识的 SHA-256 摘要放进请求头，绝不外发明文。 */
    static String sessionId(String accountScope) {
        String scope = accountScope == null || accountScope.trim().isEmpty()
                ? "default" : accountScope.trim();
        byte[] seed = ("allin-zcode-session:" + scope).getBytes(StandardCharsets.UTF_8);
        byte[] digest;
        try {
            digest = java.security.MessageDigest.getInstance("SHA-256").digest(seed);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            return UUID.nameUUIDFromBytes(seed).toString();
        }
        long msb = 0L, lsb = 0L;
        for (int i = 0; i < 8; i++) msb = (msb << 8) | (digest[i] & 0xffL);
        for (int i = 8; i < 16; i++) lsb = (lsb << 8) | (digest[i] & 0xffL);
        msb = (msb & ~(0xfL << 12)) | (5L << 12);              // UUID version 5
        lsb = (lsb & (Long.MAX_VALUE >>> 1)) | Long.MIN_VALUE;  // RFC 4122 variant
        return new UUID(msb, lsb).toString();
    }

    /** 与 {@link ZCodeGift#platform()} 同口径：linux-&lt;arch&gt;。 */
    static String platform() {
        String arch = System.getProperty("os.arch", "");
        if (arch == null) arch = "";
        if (arch.contains("aarch64") || arch.contains("arm64")) arch = "arm64";
        else if (arch.contains("x86_64") || arch.contains("amd64")) arch = "x64";
        return "linux-" + arch;
    }

    /** 与上游 marketingHeaders / gift 请求一致：只认 zh-CN 与 en-US。 */
    private static String clientLanguage() {
        try {
            java.util.Locale l = java.util.Locale.getDefault();
            return l != null && "zh".equalsIgnoreCase(l.getLanguage()) ? "zh-CN" : "en-US";
        } catch (Throwable ignored) {
            return "en-US";
        }
    }

    private static String timezone() {
        try {
            TimeZone tz = TimeZone.getDefault();
            return tz == null ? "unknown" : tz.getID();
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    /**
     * 与 {@link ZCodeGift#osRelease()} 同口径：Android 内核串含 {@code android}，
     * 桌面客户端不可能有，抹成一个干净的桌面 Linux 内核版本。
     */
    static String maskedOsVersion(String raw) {
        if (raw == null || raw.isEmpty() || raw.toLowerCase(Locale.ROOT).contains("android")) {
            return "6.2.0";
        }
        return raw;
    }

    private static String osRelease() {
        return maskedOsVersion(System.getProperty("os.version", ""));
    }

    /** 403 且正文点明客户端身份时，给面板一句能直接照做的提示。 */
    static boolean isUnofficialClient(int status, String body) {
        if (status < 400 || status >= 500 || body == null || body.isEmpty()) return false;
        String s = body.toLowerCase(Locale.ROOT);
        return s.contains("非官方客户端") || s.contains("非官方") || s.contains("unofficial client")
                || s.contains("official client") || s.contains("unsupported client")
                || s.contains("client not allowed") || s.contains("请使用官方客户端");
    }

    static String hint() {
        return "上游判定为非官方客户端：本版本已为 ZCode 出站请求补齐 ZCode Desktop "
                + APP_VERSION + " 身份头组。若仍是 403，请在供应商高级设置里核对 "
                + "baseUrl（open.bigmodel.cn/api/coding/paas/v4 或 api.z.ai/api/anthropic），"
                + "并用官方 ZCode 客户端确认该账号的 Coding Plan 有效。";
    }
}
