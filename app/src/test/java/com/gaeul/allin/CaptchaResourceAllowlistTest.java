package com.gaeul.allin;

/**
 * 面板 WebView 的资源白名单回归。
 *
 * <p>面板的 {@code shouldInterceptRequest} 默认把所有非 assets 请求换成**空响应**；
 * 阿里云验证码 SDK 因此「加载成功但内容为空」，onload 触发而 {@code initAliyunCaptcha}
 * 不存在 —— 用户看到的就是「完成安全验证」按钮点了没有任何反应。
 * 这里锁住放行范围，同时确认没有把任意域名放进来。
 */
public final class CaptchaResourceAllowlistTest {

    private static void ok(boolean b) { if (!b) throw new AssertionError(); }

    public static void main(String[] args) {
        // 必须放行：SDK、动态设备指纹脚本、样式、校验接口
        ok(MainActivity.isCaptchaResource("https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"));
        ok(MainActivity.isCaptchaResource("https://o.alicdn.com/captcha-frontend/dynamicJS/3.29.0/pe.096.af431a090d6756cf.js"));
        ok(MainActivity.isCaptchaResource("https://o.alicdn.com/captcha-frontend/main.css"));
        ok(MainActivity.isCaptchaResource("https://cloudauth-device.aliyuncs.com/v1/device"));
        ok(MainActivity.isCaptchaResource("https://cn-shanghai.device.saf.aliyuncs.com/v1/verify"));
        ok(MainActivity.isCaptchaResource("https://captcha-open.aliyuncs.com/api/v1"));
        ok(MainActivity.isCaptchaResource("https://no8xfe.aliyuncaptcha.com/resource.js"));

        // 必须拒绝：非 https、路径不符、后缀伪装、userinfo 伪装、其它阿里云服务
        ok(!MainActivity.isCaptchaResource(null));
        ok(!MainActivity.isCaptchaResource(""));
        ok(!MainActivity.isCaptchaResource("http://o.alicdn.com/captcha-frontend/x.js"));
        ok(!MainActivity.isCaptchaResource("https://o.alicdn.com/other/x.js"));
        ok(!MainActivity.isCaptchaResource("https://alicdn.com.evil.com/captcha-frontend/x.js"));
        ok(!MainActivity.isCaptchaResource("https://evil-aliyuncs.com/x"));
        ok(!MainActivity.isCaptchaResource("https://aliyuncs.com.evil.com/x"));
        ok(!MainActivity.isCaptchaResource("https://example.com/captcha-frontend/x.js"));
        ok(!MainActivity.isCaptchaResource("https://o.alicdn.com@evil.com/captcha-frontend/x.js"));
        ok(!MainActivity.isCaptchaResource("file:///android_asset/dashboard.html"));
        ok(!MainActivity.isCaptchaResource("https://storage.aliyuncs.com/x"));
        ok(!MainActivity.isCaptchaResource("https://oss.aliyuncs.com/captcha-frontend/x.js"));

        System.out.println("CaptchaResourceAllowlistTest OK");
    }
}
