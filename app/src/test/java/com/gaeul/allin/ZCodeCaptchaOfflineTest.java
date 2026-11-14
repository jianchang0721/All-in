package com.gaeul.allin;

import com.gaeul.allin.json.JSONObject;

/** ZCode 领取的人机验证通道 + 1113 额度分类的离线回归。 */
public final class ZCodeCaptchaOfflineTest {

    private static void ok(boolean b) { if (!b) throw new AssertionError(); }

    // giftClientConfigs() 返回的是 envelope 的 data，里面才是 configs
    private static final String CONFIGS = "{\"configs\":{"
            + "\"captcha\":{\"enabled\":true,\"prefix\":\"no8xfe\",\"region\":\"cn\","
            + "\"sceneId\":\"11xygtvd\",\"skip_model_request\":true}}}";
    private static final String BODY_1113 = "{\"error\":{\"code\":\"1113\","
            + "\"message\":\"Insufficient balance or no resource package. Please recharge.\"}}";

    public static void main(String[] args) throws Exception {
        // 1. 真实下发的 client/configs 片段解析
        ZCodeCaptcha.Config c = ZCodeCaptcha.config(new JSONObject(CONFIGS));
        ok(c.enabled);
        ok(c.complete);
        ok("no8xfe".equals(c.prefix));
        ok("11xygtvd".equals(c.sceneId));
        ok("cn".equals(c.region));
        JSONObject desc = ZCodeCaptcha.descriptor(c);
        ok(desc.optBoolean("ok"));
        ok(ZCodeCaptcha.SDK_URL.equals(desc.optString("sdkUrl")));
        ok("no8xfe".equals(desc.optString("prefix")));
        ok("11xygtvd".equals(desc.optString("sceneId")));
        ok(ZCodeCaptcha.HEADER.equals(desc.optString("header")));
        ok(!desc.has("jwt") && !desc.has("token") && !desc.has("access"));

        // 2. 缺失 / 注入防护：非法值一律丢弃，且不把未知配置当成「不用校验」
        ZCodeCaptcha.Config empty = ZCodeCaptcha.config(new JSONObject("{\"code\":0}"));
        ok(!empty.enabled && !empty.complete);
        ZCodeCaptcha.Config off = ZCodeCaptcha.config(new JSONObject(
                "{\"configs\":{\"captcha\":{\"enabled\":false,\"prefix\":\"no8xfe\",\"sceneId\":\"11xygtvd\",\"region\":\"cn\"}}}"));
        ok(!off.enabled && off.complete);
        ZCodeCaptcha.Config bad = ZCodeCaptcha.config(new JSONObject(
                "{\"configs\":{\"captcha\":{\"enabled\":true,\"prefix\":\"\\\"/><script>\",\"sceneId\":\"11xygtvd\",\"region\":\"cn\"}}}"));
        ok(bad.enabled && !bad.complete);
        ok("".equals(ZCodeCaptcha.safe("\"/><script>")));
        ok("".equals(ZCodeCaptcha.safe("a;alert(1)")));
        ok("abc-123_XY".equals(ZCodeCaptcha.safe("abc-123_XY")));
        ok(!ZCodeCaptcha.descriptor(bad).optBoolean("ok"));

        // 3. token store：账号隔离、一次性、TTL、非法输入
        ZCodeCaptcha.clear();
        final long[] now = {1000L};
        ZCodeCaptcha.setTestClock(new ZCodeCaptcha.Clock() { public long now() { return now[0]; } });
        try {
            ok(!ZCodeCaptcha.ready("jwt-a", "dev-1"));
            ok(!ZCodeCaptcha.store("jwt-a", "dev-1", ""));
            ok(!ZCodeCaptcha.store("jwt-a", "dev-1", "bad\ncontrol"));
            ok(!ZCodeCaptcha.store("jwt-a", "dev-1", null));
            StringBuilder tooLong = new StringBuilder();
            for (int i = 0; i < 9000; i++) tooLong.append('x');
            ok(!ZCodeCaptcha.store("jwt-a", "dev-1", tooLong.toString()));

            ok(ZCodeCaptcha.store("jwt-a", "dev-1", "verify-param-a"));
            ok(!ZCodeCaptcha.ready("jwt-b", "dev-1"));              // 不同账号拿不到
            ok(!ZCodeCaptcha.ready("jwt-a", "dev-2"));              // 不同设备拿不到
            ok(ZCodeCaptcha.ready("jwt-a", "dev-1"));
            ok("verify-param-a".equals(ZCodeCaptcha.consume("jwt-a", "dev-1")));
            ok(!ZCodeCaptcha.ready("jwt-a", "dev-1"));              // 一次性消费
            ok("".equals(ZCodeCaptcha.consume("jwt-a", "dev-1")));

            ok(ZCodeCaptcha.store("jwt-a", "dev-1", "verify-param-b"));
            now[0] += 5L * 60_000L;                                // 恰好过期
            ok(!ZCodeCaptcha.ready("jwt-a", "dev-1"));
            ok("".equals(ZCodeCaptcha.consume("jwt-a", "dev-1")));
        } finally {
            ZCodeCaptcha.setTestClock(null);
            ZCodeCaptcha.clear();
        }

        // 4. 1113 不再被当成限流：402 -> QUOTA / BALANCE
        ok(ZhipuEnvelope.codeStatus(1113) == 402);
        ok(ZhipuEnvelope.codeStatus(1302) == 429);                 // 真限流保持 429
        ok(FailureLayers.fromResponse(402, BODY_1113) == FailureLayers.Kind.QUOTA);
        ok(FailureLayers.layer(FailureLayers.Kind.QUOTA) == FailureLayers.Layer.BALANCE);
        UpstreamFailure f = UpstreamFailure.classify("zcode", 402, BODY_1113, true, false);
        ok(f.kind == UpstreamFailure.Kind.QUOTA);
        ok(f.fallback);

        System.out.println("ZCodeCaptchaOfflineTest OK");
    }
}
