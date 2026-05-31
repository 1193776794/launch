package com.xff.launch.util;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * WebView 侧指纹采集——和 native 侧相互独立的一条取证链。
 *
 * <p>WebView 必须在主线程操作，引擎采集在后台线程；这里用 Handler 投递到主线程
 * 跑 WebView，再用 CountDownLatch 把结果同步回后台采集线程。
 */
public final class WebProbe {

    private WebProbe() {}

    /** WebView 默认 User-Agent（含机型/安卓版本/Chrome 版本/Build）。 */
    public static String userAgent(Context ctx) {
        final String[] out = {""};
        final CountDownLatch latch = new CountDownLatch(1);
        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                out[0] = WebSettings.getDefaultUserAgent(ctx.getApplicationContext());
            } catch (Throwable ignored) {
            } finally {
                latch.countDown();
            }
        });
        await(latch, 2000);
        return out[0] == null ? "" : out[0];
    }

    /**
     * 通过离屏 WebView 执行 JS，采集 navigator / screen / WebGL 等机型相关特征，返回 JSON。
     * 失败返回空串。
     */
    public static String jsFingerprint(Context ctx) {
        final String[] out = {""};
        final WebView[] holder = {null};
        final CountDownLatch latch = new CountDownLatch(1);
        final Handler main = new Handler(Looper.getMainLooper());

        main.post(() -> {
            try {
                WebView wv = new WebView(ctx.getApplicationContext());
                holder[0] = wv;
                WebSettings s = wv.getSettings();
                s.setJavaScriptEnabled(true);
                wv.addJavascriptInterface(new JsBridge(out, latch), "AndroidFp");
                wv.loadDataWithBaseURL("https://localhost/", PAGE, "text/html", "utf-8", null);
            } catch (Throwable t) {
                latch.countDown();
            }
        });

        await(latch, 3000);
        // 主线程销毁 WebView，避免泄漏
        main.post(() -> {
            try {
                if (holder[0] != null) holder[0].destroy();
            } catch (Throwable ignored) {}
        });

        String r = out[0];
        return (r == null || r.startsWith("ERR:")) ? "" : r;
    }

    private static void await(CountDownLatch latch, long ms) {
        try {
            latch.await(ms, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    /** JS → Java 回调桥。 */
    private static class JsBridge {
        private final String[] out;
        private final CountDownLatch latch;

        JsBridge(String[] out, CountDownLatch latch) {
            this.out = out;
            this.latch = latch;
        }

        @JavascriptInterface
        public void onResult(String r) {
            out[0] = r;
            latch.countDown();
        }
    }

    /** 采集脚本：拿 navigator / screen / WebGL UNMASKED 渲染器，回传 JSON。 */
    private static final String PAGE =
            "<html><body><script>" +
            "try{" +
            "var c=document.createElement('canvas');" +
            "var gl=c.getContext('webgl')||c.getContext('experimental-webgl');" +
            "var d=gl&&gl.getExtension('WEBGL_debug_renderer_info');" +
            "var gv=d?gl.getParameter(d.UNMASKED_VENDOR_WEBGL):'';" +
            "var gr=d?gl.getParameter(d.UNMASKED_RENDERER_WEBGL):'';" +
            "var o={" +
            "p:navigator.platform," +
            "hc:navigator.hardwareConcurrency," +
            "dm:navigator.deviceMemory," +
            "lang:(navigator.languages||[]).join(',')," +
            "sw:screen.width,sh:screen.height," +
            "dpr:window.devicePixelRatio," +
            "cd:screen.colorDepth," +
            "tp:navigator.maxTouchPoints," +
            "glv:gv,glr:gr" +
            "};" +
            "AndroidFp.onResult(JSON.stringify(o));" +
            "}catch(e){AndroidFp.onResult('ERR:'+e);}" +
            "</script></body></html>";
}
