package com.gaeul.allin;

import java.util.Locale;

/**
 * Gemini Code Assist for individuals 的「账号所在地区未开放」判定与展示文案。
 *
 * <p>上游 {@code cloudcode-pa.googleapis.com/v1internal:loadCodeAssist} 对不在服务地区的
 * Google 账号返回 403 / {@code PERMISSION_DENIED}，正文是固定的一句：
 * {@code Your current account is not eligible for Gemini Code Assist for individuals
 * because it is not currently available in your location.}。
 *
 * <p>这不是凭据失效，也不是推理故障：重新登录、刷新 token、换模型、换端点、换同地区账号
 * 都不会改变资格。此前网关把它压成 502 + {@code FailureLayers.Kind.OTHER}
 * （「未归类的上游错误 / 实际推理」），用户会去换本来没坏的 Key；而
 * {@code UpstreamFailure.classify} 对任意 403 判成 {@code AUTH} 且 {@code fallback=true}，
 * 会白跑一次换账号重试。本类提供一个不依赖 Android、不联网的纯判定，让三处口径统一。
 *
 * <p>措辞足够特异，因此判定只看正文，不强求状态码必须是 403：网关在
 * {@code forwardAntigravity} 里可能把它包装成 502，展示层仍需认得出来。
 */
public final class AntigravityEligibility {

    private AntigravityEligibility() {}

    private static final String MARKER_ELIGIBLE =
            "not eligible for gemini code assist for individuals";
    private static final String MARKER_LOCATION = "not currently available in your location";

    /** 正文是否是「账号所在地区未开放个人版」这一条固定拒绝。 */
    public static boolean isIndividualNotEligible(String body) {
        if (body == null || body.isEmpty()) return false;
        String s = body.toLowerCase(Locale.ROOT);
        if (s.contains(MARKER_ELIGIBLE)) return true;
        return s.contains("gemini code assist") && s.contains(MARKER_LOCATION);
    }

    /**
     * 带状态码的判定，供展示层与路由层共用。状态码只用来排除明显的成功回包，
     * 不作为硬门槛：包装后的 502、异常路径里的 0 都要继续认出这条文案。
     */
    public static boolean isIndividualNotEligible(int status, String body) {
        if (status >= 200 && status < 300) return false;
        return isIndividualNotEligible(body);
    }

    /**
     * {@code loadCodeAssist} 的 prod→daily 回落是否该做。
     *
     * <p>原来任何异常都换域名重发一次。明确的 4xx 是服务端对账号/请求的判定，换域名
     * （同一个 Code Assist 后端）不会改变结果，只会多打一次被拒的请求；只有链路问题
     * （{@code codeAssistStatus} 为 0）和 5xx 才值得回落到另一个 base。
     *
     * @param codeAssistStatus {@link AntigravityAuth#codeAssistStatus(Throwable)} 的结果
     */
    public static boolean shouldRetryOnAltBase(int codeAssistStatus) {
        return !(codeAssistStatus >= 400 && codeAssistStatus < 500);
    }

    /** 面板短名。 */
    public static String label() {
        return "账号所在地区未开放 Gemini Code Assist 个人版";
    }

    /** 上游原因的一句话转述，不含凭据、不含上游正文。 */
    public static String reason() {
        return "Google 判定该账号所在地区目前未开放 Gemini Code Assist for individuals。";
    }

    /** 一句话可执行的建议；明确说清哪些操作没用，避免用户反复重登、换 Key。 */
    public static String advice() {
        return "该 Google 账号所在地区目前未开放 Gemini Code Assist 个人版。"
                + "重新登录、刷新 token、换模型、换端点或换同地区账号都不会改变资格；"
                + "请在服务已开放的地区使用该账号，或改用其它供应商。";
    }
}
