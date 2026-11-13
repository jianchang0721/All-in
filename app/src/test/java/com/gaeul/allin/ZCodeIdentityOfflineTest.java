package com.gaeul.allin;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** ZCode 付费 Plan 出站客户端指纹的离线回归：不联网、不读账号、不依赖 Android 运行时。 */
public final class ZCodeIdentityOfflineTest {

    private static void ok(boolean b) { if (!b) throw new AssertionError(); }

    public static void main(String[] args) throws Exception {
        final String scope = "device-a|account-b";
        Map<String, String> cc = ZCodeIdentity.headers(scope, false, false);
        Map<String, String> anth = ZCodeIdentity.headers(scope, true, true);

        // 1. 两条协议面都带完整指纹头组
        String[] required = {
                "User-Agent", "X-ZCode-App-Version", "X-ZCode-Agent", "X-Title",
                "X-Release-Channel", "HTTP-Referer", "X-Client-Language",
                "X-Client-Timezone", "X-Platform", "X-Os-Category", "X-Os-Version",
                "x-request-id", "x-zcode-trace-id", "x-query-id", "x-session-id",
                "x-zcode-session-type", "x-zcode-query-source", "Accept"
        };
        for (String key : required) {
            ok(cc.containsKey(key) && !cc.get(key).isEmpty());
            ok(anth.containsKey(key) && !anth.get(key).isEmpty());
        }

        // 2. 两套 SDK 栈 UA 不同，版本号同源，且与 login/gift 的 APP_VERSION 一致
        ok(ZCodeIdentity.UA_OPENAI.equals(cc.get("User-Agent")));
        ok(ZCodeIdentity.UA_ANTHROPIC.equals(anth.get("User-Agent")));
        ok(!ZCodeIdentity.UA_OPENAI.equals(ZCodeIdentity.UA_ANTHROPIC));
        ok(ZCodeIdentity.UA_OPENAI.startsWith("ZCode/" + ZCodeIdentity.APP_VERSION));
        ok(ZCodeIdentity.UA_ANTHROPIC.startsWith("ZCode/" + ZCodeIdentity.APP_VERSION));
        ok(ZCodeIdentity.APP_VERSION.equals(ZCodeAuth.APP_VERSION));
        ok(ZCodeIdentity.APP_VERSION.equals(cc.get("X-ZCode-App-Version")));
        ok("glm".equals(cc.get("X-ZCode-Agent")));
        ok("Z Code@electron".equals(cc.get("X-Title")));
        ok("production".equals(cc.get("X-Release-Channel")));
        ok("https://zcode.z.ai".equals(cc.get("HTTP-Referer")));
        ok("main".equals(cc.get("x-zcode-session-type")));
        ok(ZCodeIdentity.platform().startsWith("linux-"));
        ok(ZCodeIdentity.platform().equals(cc.get("X-Platform")));
        // 付费 Plan 通道必须与 gift 通道同口径抹掉 Android 内核标记，否则仍是 403
        ok("6.2.0".equals(ZCodeIdentity.maskedOsVersion("linux-kernel-android13")));
        ok("6.2.0".equals(ZCodeIdentity.maskedOsVersion("LINUX-KERNEL-ANDROID13")));
        ok("6.2.0".equals(ZCodeIdentity.maskedOsVersion(null)));
        ok("6.2.0".equals(ZCodeIdentity.maskedOsVersion("")));
        ok("5.15-generic".equals(ZCodeIdentity.maskedOsVersion("5.15-generic")));
        ok(!cc.get("X-Os-Version").toLowerCase(Locale.ROOT).contains("android"));
        ok(!anth.get("X-Os-Version").toLowerCase(Locale.ROOT).contains("android"));

        // 3. 不写鉴权与协议头：不能覆盖调用方已设置的凭据
        for (String forbidden : new String[]{"Authorization", "authorization", "x-api-key",
                "anthropic-version", "anthropic-beta", "Content-Type", "Content-Length"}) {
            ok(!cc.containsKey(forbidden));
            ok(!anth.containsKey(forbidden));
        }
        ok("application/json".equals(cc.get("Accept")));
        ok("text/event-stream".equals(anth.get("Accept")));

        // 4. session 按账号稳定派生，逐请求 id 每次变化
        String sid = ZCodeIdentity.sessionId(scope);
        ok(sid.equals(ZCodeIdentity.sessionId(scope)));
        ok(!sid.equals(ZCodeIdentity.sessionId("device-a|account-c")));
        ok(!sid.contains(scope));
        ok(!sid.contains("account-b"));
        ok(UUID.fromString(sid).toString().equals(sid));
        Map<String, String> again = ZCodeIdentity.headers(scope, false, false);
        ok(sid.equals(again.get("x-session-id")));
        ok(!cc.get("x-request-id").equals(again.get("x-request-id")));
        ok(!cc.get("x-zcode-trace-id").equals(again.get("x-zcode-trace-id")));
        ok(!cc.get("x-query-id").equals(again.get("x-query-id")));
        ok(UUID.fromString(cc.get("x-request-id")).toString().equals(cc.get("x-request-id")));

        // 5. 冲突身份头整组剥离，鉴权与协议头保留；大小写不敏感；不改入参
        Map<String, String> raw = new HashMap<String, String>();
        raw.put("User-Agent", "claude-cli/2.0.0 (external, cli)");
        raw.put("X-Stainless-Lang", "js");
        raw.put("x-stainless-arch", "arm64");
        raw.put("x-codex-turn-id", "t-1");
        raw.put("x-app", "cursor");
        raw.put("x-claude-code-session-id", "s-1");
        raw.put("X-Title", "not-zcode");
        raw.put("Authorization", "Bearer keep-me");
        raw.put("x-api-key", "keep-me-too");
        raw.put("anthropic-version", "2023-06-01");
        raw.put("anthropic-beta", "keep");
        raw.put("Content-Type", "application/json");
        raw.put("Accept", "application/json");
        Map<String, String> clean = ZCodeIdentity.stripConflicts(raw);
        ok(clean.size() == 6);
        for (String key : new String[]{"Authorization", "x-api-key", "anthropic-version",
                "anthropic-beta", "Content-Type", "Accept"}) ok(clean.containsKey(key));
        for (String key : new String[]{"User-Agent", "X-Stainless-Lang", "x-stainless-arch",
                "x-codex-turn-id", "x-app", "x-claude-code-session-id", "X-Title"}) ok(!clean.containsKey(key));
        ok(raw.size() == 13);                       // 入参未被修改
        ok(ZCodeIdentity.stripConflicts(null).isEmpty());
        ok(ZCodeIdentity.stripConflicts(new HashMap<String, String>()).isEmpty());
        ok(ZCodeIdentity.conflicts("x-stainless-os"));
        ok(ZCodeIdentity.conflicts("x-zcode-agent"));
        ok(!ZCodeIdentity.conflicts("authorization"));
        ok(!ZCodeIdentity.conflicts("anthropic-version"));

        // 6. 403「非官方客户端」的面板提示判定
        ok(ZCodeIdentity.isUnofficialClient(403, "非官方客户端禁止访问"));
        ok(ZCodeIdentity.isUnofficialClient(403, "unofficial client"));
        ok(ZCodeIdentity.isUnofficialClient(405, "请使用官方客户端"));
        ok(!ZCodeIdentity.isUnofficialClient(200, "非官方客户端"));
        ok(!ZCodeIdentity.isUnofficialClient(403, "额度不足"));
        ok(!ZCodeIdentity.isUnofficialClient(500, "非官方客户端"));
        ok(!ZCodeIdentity.isUnofficialClient(403, null));
        ok(ZCodeIdentity.hint().contains(ZCodeIdentity.APP_VERSION));

        System.out.println("ZCodeIdentityOfflineTest OK");
    }
}
