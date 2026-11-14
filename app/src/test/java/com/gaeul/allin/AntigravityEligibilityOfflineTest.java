package com.gaeul.allin;

import com.gaeul.allin.json.JSONObject;

/** Code Assist「账号所在地区未开放」的离线回归：纯 Java，不联网、不依赖 Android 运行时。 */
public final class AntigravityEligibilityOfflineTest {

    private static void ok(boolean b) { if (!b) throw new AssertionError(); }

    private static final String REAL = "Code Assist 403: { \"error\": { \"code\": 403, "
            + "\"message\": \"Your current account is not eligible for Gemini Code Assist for individuals "
            + "because it is not currently available in your location.\", "
            + "\"status\": \"PERMISSION_DENIED\", "
            + "\"details\": [ { \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\" } ] } }";

    public static void main(String[] args) throws Exception {
        // 1. 真实错误体命中；措辞特异，不能误伤普通 403
        ok(AntigravityEligibility.isIndividualNotEligible(REAL));
        ok(AntigravityEligibility.isIndividualNotEligible(403, REAL));
        ok(AntigravityEligibility.isIndividualNotEligible(502, REAL)); // 网关包装后仍认得出
        ok(AntigravityEligibility.isIndividualNotEligible(0, REAL));
        ok(AntigravityEligibility.isIndividualNotEligible(REAL.toLowerCase(java.util.Locale.ROOT)));
        ok(AntigravityEligibility.isIndividualNotEligible(
                "not eligible for Gemini Code Assist for individuals"));
        ok(AntigravityEligibility.isIndividualNotEligible(
                "gemini code assist: not currently available in your location"));
        ok(!AntigravityEligibility.isIndividualNotEligible(null));
        ok(!AntigravityEligibility.isIndividualNotEligible(""));
        ok(!AntigravityEligibility.isIndividualNotEligible("Code Assist 403: permission denied"));
        ok(!AntigravityEligibility.isIndividualNotEligible("model_not_found"));
        ok(!AntigravityEligibility.isIndividualNotEligible(200, REAL)); // 成功回包里出现这句不算失败

        // 2. prod->daily 回落：明确 4xx 不重发，链路问题与 5xx 才回落
        ok(!AntigravityEligibility.shouldRetryOnAltBase(403));
        ok(!AntigravityEligibility.shouldRetryOnAltBase(401));
        ok(!AntigravityEligibility.shouldRetryOnAltBase(429));
        ok(AntigravityEligibility.shouldRetryOnAltBase(0));
        ok(AntigravityEligibility.shouldRetryOnAltBase(500));
        ok(AntigravityEligibility.shouldRetryOnAltBase(502));
        ok(AntigravityEligibility.shouldRetryOnAltBase(503));

        // 3. 展示层：不再落到 OTHER / 实际推理，而是 LOGIN 层的明确类别
        FailureLayers.Kind k = FailureLayers.fromResponse(502, REAL);
        ok(k == FailureLayers.Kind.NOT_ELIGIBLE);
        ok(FailureLayers.fromResponse(403, REAL) == FailureLayers.Kind.NOT_ELIGIBLE);
        ok(FailureLayers.fromResponse(403, "{\"error\":{\"code\":403,\"message\":\"forbidden\"}}")
                == FailureLayers.Kind.RESTRICTED);
        ok(FailureLayers.layer(k) == FailureLayers.Layer.LOGIN);
        ok(FailureLayers.label(k).contains("地区"));
        ok(FailureLayers.advice(k).contains("重新登录"));
        ok(FailureLayers.advice(k).contains("其它供应商"));
        ok("not_eligible".equals(FailureLayers.name(k)));
        ok(FailureLayers.fromName("not_eligible") == k);
        ok(FailureLayers.fromUpstream(UpstreamFailure.Kind.NOT_ELIGIBLE) == k);
        ok(AntigravityEligibility.label().contains("Gemini Code Assist"));
        ok(AntigravityEligibility.reason().contains("地区"));

        JSONObject shown = new JSONObject();
        FailureLayers.describe(shown, k);
        ok("not_eligible".equals(shown.optString("errorKind")));
        ok("login".equals(shown.optString("failureLayer")));
        ok(shown.optString("failureLabel").contains("地区"));
        ok(shown.optString("advice").contains("其它供应商"));

        // 4. 路由层：不是 AUTH，不换账号、不重放
        UpstreamFailure f = UpstreamFailure.classify("antigravity", 403, REAL, true, false);
        ok(f.kind == UpstreamFailure.Kind.NOT_ELIGIBLE);
        ok(!f.fallback);
        ok(!f.sameCredentialReplay);
        ok(!PatiencePolicyAllows(f));           // 不该被当成可耐心等待的限流/过载
        UpstreamFailure generic = UpstreamFailure.classify("antigravity", 403,
                "{\"error\":{\"code\":403,\"message\":\"forbidden\"}}", true, false);
        ok(generic.kind == UpstreamFailure.Kind.AUTH && generic.fallback); // 既有契约不变

        System.out.println("AntigravityEligibilityOfflineTest OK");
    }

    /** PatiencePolicy 只放行 RATE / OVERLOAD；NOT_ELIGIBLE 不该进等待队列。 */
    private static boolean PatiencePolicyAllows(UpstreamFailure f) {
        return f.kind == UpstreamFailure.Kind.RATE || f.kind == UpstreamFailure.Kind.OVERLOAD;
    }
}
