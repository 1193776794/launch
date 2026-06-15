package com.xff.launch.util;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Looper;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoNr;
import android.telephony.CellInfoWcdma;
import android.telephony.TelephonyManager;

import androidx.core.content.ContextCompat;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * 网络位置指纹采集源（对照京东 JDGuard field 7 的 Wi-Fi/LBS/基站维度）。
 *
 * <p>提供经纬度 / 定位来源 / 精度 / 海拔 / 时间戳 / 基站 / Wi-Fi 接入信息，
 * 供指纹板块（{@code FingerprintDefinitions}）以多路探针形式声明。所有方法异常隔离、
 * 无权限或失败返回空串。位置类信息随环境变化、不进 composite（声明层用 weight(0)）。
 *
 * <p>风控对照（JD 分析）：
 * <ul>
 *   <li>经纬度须与 Wi-Fi BSSID 反查位置吻合（声称北京但 BSSID 在上海 → 暴露）。</li>
 *   <li>来源 frm 永远 "gps" 罕见、永远 "cache" 且 t 不变 → 静止/hook。</li>
 *   <li>精度 acc：GPS 室外 5-20m，网络 30-3000m；acc=0 且 GPS 源 → 异常组合。</li>
 *   <li>时间戳 t=0 → 从未定位；远小于当前 → 缓存过期仍上报。</li>
 *   <li>海拔 alt：模拟器多数恒 0。</li>
 * </ul>
 */
public final class LocationProbe {

    private LocationProbe() {}

    private static boolean hasLocationPerm(Context ctx) {
        return ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
    }

    // 一次采集内 5 个 geo_* 探针共享同一次定位结果，避免重复触发主动定位。
    private static volatile Location sCache;
    private static volatile long sCacheAt;
    private static final long CACHE_TTL_MS = 15_000L;
    private static final long ACTIVE_TIMEOUT_MS = 3000L;

    /**
     * 取定位：先用三源末次定位（快）；若全为 null（位置服务开但尚无缓存 fix），
     * 则主动请求一次性定位（带超时），结果缓存 15s 供多个 geo_* 探针复用。
     * 无权限返回 null。应在后台线程调用（会阻塞至多 {@link #ACTIVE_TIMEOUT_MS}）。
     */
    public static Location bestLocation(Context ctx) {
        if (!hasLocationPerm(ctx)) return null;
        long now = System.currentTimeMillis();
        Location cached = sCache;
        if (cached != null && (now - sCacheAt) < CACHE_TTL_MS) return cached;

        Location best = lastKnown(ctx);
        if (best == null) best = requestFresh(ctx);  // 末次为空 → 主动要一发
        if (best != null) {
            sCache = best;
            sCacheAt = now;
        }
        return best;
    }

    /** 三源末次定位中时间最新的一个。 */
    private static Location lastKnown(Context ctx) {
        try {
            LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) return null;
            String[] providers = {
                    LocationManager.GPS_PROVIDER,
                    LocationManager.NETWORK_PROVIDER,
                    LocationManager.PASSIVE_PROVIDER
            };
            Location best = null;
            for (String p : providers) {
                try {
                    if (!lm.isProviderEnabled(p)) continue;
                    Location l = lm.getLastKnownLocation(p);
                    if (l != null && (best == null || l.getTime() > best.getTime())) best = l;
                } catch (Exception ignored) {}
            }
            return best;
        } catch (Exception e) {
            return null;
        }
    }

    /** 主动请求一次性定位（network 优先，超时 3s）。后台线程调用，回调投递到主 Looper。 */
    @SuppressWarnings("deprecation")
    private static Location requestFresh(Context ctx) {
        try {
            LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) return null;
            String provider = lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
                    ? LocationManager.NETWORK_PROVIDER
                    : (lm.isProviderEnabled(LocationManager.GPS_PROVIDER) ? LocationManager.GPS_PROVIDER : null);
            if (provider == null) return null;

            final Location[] holder = {null};
            final CountDownLatch latch = new CountDownLatch(1);
            final LocationListener listener = new LocationListener() {
                @Override public void onLocationChanged(android.location.Location location) {
                    holder[0] = location;
                    latch.countDown();
                }
                @Override public void onProviderDisabled(String p) {}
                @Override public void onProviderEnabled(String p) {}
                @Override public void onStatusChanged(String p, int s, android.os.Bundle e) {}
            };
            lm.requestSingleUpdate(provider, listener, Looper.getMainLooper());
            try {
                latch.await(ACTIVE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            try { lm.removeUpdates(listener); } catch (Exception ignored) {}
            // 主动失败兜底：再看一眼末次（可能此刻被别的 app 刷新了）
            return holder[0] != null ? holder[0] : lastKnown(ctx);
        } catch (Exception e) {
            return null;
        }
    }

    // ==================== 定位维度 ====================

    public static String coordinate(Context ctx) {
        Location l = bestLocation(ctx);
        return l == null ? "" : String.format(Locale.ROOT, "%.6f,%.6f", l.getLatitude(), l.getLongitude());
    }

    public static String source(Context ctx) {
        Location l = bestLocation(ctx);
        return (l == null || l.getProvider() == null) ? "" : l.getProvider();
    }

    public static String accuracy(Context ctx) {
        Location l = bestLocation(ctx);
        if (l == null) return "";
        return l.hasAccuracy() ? String.format(Locale.ROOT, "%.1f m", l.getAccuracy()) : "无";
    }

    public static String altitude(Context ctx) {
        Location l = bestLocation(ctx);
        if (l == null) return "";
        return l.hasAltitude() ? String.format(Locale.ROOT, "%.1f m", l.getAltitude()) : "无";
    }

    public static String time(Context ctx) {
        Location l = bestLocation(ctx);
        return l == null ? "" : String.valueOf(l.getTime());
    }

    // ==================== Wi-Fi 接入（位置指纹）====================

    public static String wifiBssid(Context ctx) {
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return "";
            WifiInfo wi = wm.getConnectionInfo();
            String b = wi != null ? wi.getBSSID() : null;
            return b == null ? "" : b.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    public static String wifiSsid(Context ctx) {
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return "";
            WifiInfo wi = wm.getConnectionInfo();
            String s = wi != null ? wi.getSSID() : null;
            return s == null ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    /** 周边热点：去重 SSID 数量 + 前若干个名（物理位置指纹/农场机识别）。 */
    @SuppressWarnings("deprecation")
    public static String wifiScan(Context ctx) {
        try {
            WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return "";
            List<ScanResult> scans = wm.getScanResults();
            if (scans == null || scans.isEmpty()) return "";
            Set<String> ssids = new LinkedHashSet<>();
            for (ScanResult r : scans) {
                if (r.SSID != null && !r.SSID.isEmpty()) ssids.add(r.SSID);
            }
            if (ssids.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            int shown = 0;
            for (String s : ssids) {
                if (shown++ >= 8) { sb.append("…"); break; }
                if (sb.length() > 0) sb.append(";");
                sb.append(s);
            }
            return ssids.size() + " 个: " + sb;
        } catch (Exception e) {
            return "";
        }
    }

    // ==================== 基站 ====================

    /** 已注册主基站标识：制式 + mcc/mnc + lac/tac + cid/ci/nci (+pci)。 */
    public static String cellInfo(Context ctx) {
        if (!hasLocationPerm(ctx)) return "";
        try {
            TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) return "";
            List<CellInfo> cells = tm.getAllCellInfo();
            if (cells == null || cells.isEmpty()) return "";
            // 优先取已注册（serving）小区
            for (CellInfo c : cells) {
                if (c.isRegistered()) {
                    String s = describeCell(c);
                    if (!s.isEmpty()) return s;
                }
            }
            for (CellInfo c : cells) {
                String s = describeCell(c);
                if (!s.isEmpty()) return s;
            }
            return "";
        } catch (SecurityException se) {
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    private static String describeCell(CellInfo c) {
        try {
            if (c instanceof CellInfoLte) {
                CellIdentityLte id = ((CellInfoLte) c).getCellIdentity();
                return "LTE mcc=" + nz(id.getMccString()) + " mnc=" + nz(id.getMncString())
                        + " tac=" + id.getTac() + " ci=" + id.getCi() + " pci=" + id.getPci();
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && c instanceof CellInfoNr) {
                CellIdentityNr id = (CellIdentityNr) ((CellInfoNr) c).getCellIdentity();
                return "NR mcc=" + nz(id.getMccString()) + " mnc=" + nz(id.getMncString())
                        + " tac=" + id.getTac() + " nci=" + id.getNci() + " pci=" + id.getPci();
            } else if (c instanceof CellInfoWcdma) {
                CellIdentityWcdma id = ((CellInfoWcdma) c).getCellIdentity();
                return "WCDMA mcc=" + nz(id.getMccString()) + " mnc=" + nz(id.getMncString())
                        + " lac=" + id.getLac() + " cid=" + id.getCid();
            } else if (c instanceof CellInfoGsm) {
                CellIdentityGsm id = ((CellInfoGsm) c).getCellIdentity();
                return "GSM mcc=" + nz(id.getMccString()) + " mnc=" + nz(id.getMncString())
                        + " lac=" + id.getLac() + " cid=" + id.getCid();
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
