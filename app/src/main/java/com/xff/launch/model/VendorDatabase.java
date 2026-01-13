package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Database of vendor profiles for device legitimacy verification
 * Contains ROM features, services, and preinstalled apps for major phone brands
 */
public class VendorDatabase {
    private static VendorDatabase instance;
    private final List<VendorProfile> vendors;

    private VendorDatabase() {
        vendors = new ArrayList<>();
        initVendors();
    }

    public static VendorDatabase getInstance() {
        if (instance == null) {
            instance = new VendorDatabase();
        }
        return instance;
    }

    private void initVendors() {
        // ==================== Xiaomi / Redmi / POCO ====================
        vendors.add(new VendorProfile("xiaomi", "小米")
                .setBrands("xiaomi", "redmi", "poco", "mi")
                .setManufacturers("xiaomi")
                .setRomName("MIUI/HyperOS")
                .setRomVersionProperties(
                        "ro.miui.ui.version.name",
                        "ro.miui.ui.version.code",
                        "ro.mi.os.version.name",
                        "ro.mi.os.version.code"
                )
                .setRequiredPackages(
                        "com.xiaomi.xmsf",              // Xiaomi Service Framework
                        "com.miui.securitycenter",      // Security Center
                        "com.miui.home"                 // MIUI Launcher
                )
                .setOptionalPackages(
                        "com.xiaomi.xmsfkeeper",        // Service Framework Keeper
                        "com.miui.systemui.plugin",     // SystemUI Plugin
                        "com.xiaomi.market",            // Mi Store
                        "com.miui.gallery",             // Gallery
                        "com.miui.notes",               // Notes
                        "com.miui.weather2",            // Weather
                        "com.miui.mishare.connectivity", // Mi Share
                        "com.xiaomi.account",           // Xiaomi Account
                        "com.xiaomi.mipicks",           // GetApps
                        "com.miui.cloudservice",        // Mi Cloud
                        "com.xiaomi.joyose",            // Game Turbo
                        "com.miui.screenrecorder",      // Screen Recorder
                        "com.miui.player",              // Music Player
                        "com.miui.videoplayer",         // Video Player
                        "com.miui.compass",             // Compass
                        "com.miui.calculator",          // Calculator
                        "com.miui.cleaner"              // Cleaner
                )
                .setSystemProperties(
                        "ro.product.mod_device",
                        "ro.miui.cust_variant"
                )
                .setFingerprintPatterns("xiaomi", "redmi", "poco")
                .setHasGms(true));

        // ==================== Huawei ====================
        vendors.add(new VendorProfile("huawei", "华为")
                .setBrands("huawei")
                .setManufacturers("huawei")
                .setRomName("EMUI/HarmonyOS")
                .setRomVersionProperties(
                        "ro.build.version.emui",
                        "hw_sc.build.platform.version"
                )
                .setRequiredPackages(
                        "com.huawei.android.launcher",  // Launcher
                        "com.huawei.systemmanager"      // System Manager
                )
                .setOptionalPackages(
                        "com.huawei.hms.core",          // HMS Core
                        "com.huawei.appmarket",         // AppGallery
                        "com.huawei.hwid",              // Huawei ID
                        "com.huawei.android.hwpay",     // Huawei Pay
                        "com.huawei.health",            // Huawei Health
                        "com.huawei.wallet",            // Huawei Wallet
                        "com.huawei.music",             // Music
                        "com.huawei.himovie",           // Video
                        "com.huawei.browser",           // Browser
                        "com.huawei.search",            // HiSearch
                        "com.huawei.android.totemweather", // Weather
                        "com.huawei.android.tips",      // Tips
                        "com.huawei.photos",            // Gallery
                        "com.huawei.notepad",           // Notepad
                        "com.huawei.android.hwouc",     // System Update
                        "com.huawei.hicloud",           // Cloud
                        "com.huawei.gameassistant",     // Game Center
                        "com.huawei.intelligent"        // AI Life
                )
                .setSystemProperties(
                        "ro.build.hw_emui_api_level",
                        "ro.huawei.build.display.id"
                )
                .setFingerprintPatterns("huawei")
                .setHasGms(false));

        // ==================== Honor ====================
        vendors.add(new VendorProfile("honor", "荣耀")
                .setBrands("honor")
                .setManufacturers("honor", "huawei")
                .setRomName("MagicOS/MagicUI")
                .setRomVersionProperties(
                        "ro.build.version.magic",
                        "ro.honor.build.display.id"
                )
                .setRequiredPackages(
                        "com.hihonor.android.launcher"  // Honor Launcher
                )
                .setOptionalPackages(
                        "com.hihonor.id",               // Honor ID
                        "com.hihonor.appmarket",        // App Market
                        "com.hihonor.systemmanager",    // System Manager
                        "com.hihonor.cloudservice",     // Cloud Service
                        "com.hihonor.gamecenter",       // Game Center
                        "com.huawei.hms.core"           // HMS Core (some models)
                )
                .setSystemProperties(
                        "ro.honor.build.version"
                )
                .setFingerprintPatterns("honor")
                .setHasGms(true));

        // ==================== OPPO ====================
        vendors.add(new VendorProfile("oppo", "OPPO")
                .setBrands("oppo")
                .setManufacturers("oppo")
                .setRomName("ColorOS")
                .setRomVersionProperties(
                        "ro.build.version.opporom",
                        "ro.oppo.version"
                )
                .setRequiredPackages(
                        "com.coloros.launcher",         // ColorOS Launcher
                        "com.coloros.safecenter"        // Security Center
                )
                .setOptionalPackages(
                        "com.heytap.msp",               // Push Service
                        "com.heytap.usercenter",        // User Center
                        "com.heytap.market",            // App Market
                        "com.coloros.filemanager",      // File Manager
                        "com.coloros.gallery3d",        // Gallery
                        "com.coloros.weather",          // Weather
                        "com.coloros.calculator",       // Calculator
                        "com.coloros.compass2",         // Compass
                        "com.coloros.soundrecorder",    // Sound Recorder
                        "com.coloros.screenrecorder",   // Screen Recorder
                        "com.coloros.gamespace",        // Game Space
                        "com.coloros.floatassistant",   // Floating Assistant
                        "com.coloros.oshare",           // OPPO Share
                        "com.coloros.wallet",           // Wallet
                        "com.oppo.music",               // Music
                        "com.oppo.camera"               // Camera
                )
                .setSystemProperties(
                        "ro.oppo.market.name",
                        "ro.build.display.ota"
                )
                .setFingerprintPatterns("oppo")
                .setHasGms(true));

        // ==================== OnePlus ====================
        vendors.add(new VendorProfile("oneplus", "一加")
                .setBrands("oneplus")
                .setManufacturers("oneplus", "oppo")
                .setRomName("OxygenOS/ColorOS")
                .setRomVersionProperties(
                        "ro.build.version.ota",
                        "ro.rom.version",
                        "ro.build.version.opporom"
                )
                .setRequiredPackages(
                        "com.oneplus.launcher",         // OnePlus Launcher
                        "com.oplus.launcher"            // OPLUS Launcher
                )
                .setOptionalPackages(
                        "com.oneplus.security",         // Security
                        "com.oneplus.filemanager",      // File Manager
                        "com.oneplus.gallery",          // Gallery
                        "com.oneplus.note",             // Notes
                        "com.oneplus.weather",          // Weather
                        "com.oneplus.camera",           // Camera
                        "com.oneplus.gamespace",        // Game Space
                        "com.heytap.msp",               // Push Service
                        "com.oplus.games"               // Games
                )
                .setSystemProperties(
                        "ro.build.ota.versionname"
                )
                .setFingerprintPatterns("oneplus")
                .setHasGms(true));

        // ==================== Realme ====================
        vendors.add(new VendorProfile("realme", "realme")
                .setBrands("realme")
                .setManufacturers("realme", "oppo")
                .setRomName("realme UI")
                .setRomVersionProperties(
                        "ro.build.version.realmeui",
                        "ro.build.version.opporom"
                )
                .setRequiredPackages(
                        "com.realme.launcher"           // Realme Launcher
                )
                .setOptionalPackages(
                        "com.heytap.msp",               // Push Service
                        "com.realme.filemanager",       // File Manager
                        "com.coloros.gamespace",        // Game Space
                        "com.realme.themecenter"        // Theme Center
                )
                .setSystemProperties(
                        "ro.product.realme.model"
                )
                .setFingerprintPatterns("realme")
                .setHasGms(true));

        // ==================== vivo / iQOO ====================
        vendors.add(new VendorProfile("vivo", "vivo")
                .setBrands("vivo", "iqoo")
                .setManufacturers("vivo", "bbk")
                .setRomName("OriginOS/FuntouchOS")
                .setRomVersionProperties(
                        "ro.vivo.os.version",
                        "ro.vivo.os.build.display.id",
                        "ro.build.version.funtouch"
                )
                .setRequiredPackages(
                        "com.bbk.launcher2",            // vivo Launcher
                        "com.vivo.permissionmanager"    // Permission Manager
                )
                .setOptionalPackages(
                        "com.vivo.pushservice",         // Push Service
                        "com.vivo.appstore",            // App Store
                        "com.vivo.wallet",              // Wallet
                        "com.vivo.easyshare",           // Easy Share
                        "com.vivo.gallery",             // Gallery
                        "com.vivo.weather",             // Weather
                        "com.vivo.browser",             // Browser
                        "com.vivo.music",               // Music
                        "com.vivo.compass",             // Compass
                        "com.vivo.calculator",          // Calculator
                        "com.vivo.soundrecorder",       // Sound Recorder
                        "com.vivo.gamecube",            // Game Center
                        "com.vivo.assistant",           // Assistant
                        "com.bbk.account",              // BBK Account
                        "com.iqoo.gamecube"             // iQOO Game Center
                )
                .setSystemProperties(
                        "ro.vivo.product.model",
                        "ro.vivo.market.name"
                )
                .setFingerprintPatterns("vivo", "iqoo", "bbk")
                .setHasGms(true));

        // ==================== Samsung ====================
        vendors.add(new VendorProfile("samsung", "三星")
                .setBrands("samsung")
                .setManufacturers("samsung")
                .setRomName("One UI")
                .setRomVersionProperties(
                        "ro.build.version.oneui",
                        "ro.build.PDA"
                )
                .setRequiredPackages(
                        "com.sec.android.app.launcher",  // Samsung Launcher
                        "com.samsung.android.lool"       // Device Care
                )
                .setOptionalPackages(
                        "com.samsung.android.samsungpass",   // Samsung Pass
                        "com.samsung.android.spay",          // Samsung Pay
                        "com.samsung.android.bixby.agent",   // Bixby
                        "com.samsung.android.visionintelligence", // Bixby Vision
                        "com.samsung.android.game.gamehome", // Game Launcher
                        "com.samsung.android.game.gametools", // Game Tools
                        "com.samsung.android.scloud",        // Samsung Cloud
                        "com.samsung.android.app.notes",     // Samsung Notes
                        "com.samsung.android.calendar",      // Calendar
                        "com.samsung.android.email.provider", // Email
                        "com.samsung.android.messaging",     // Messages
                        "com.samsung.android.dialer",        // Phone
                        "com.sec.android.gallery3d",         // Gallery
                        "com.samsung.android.app.camera",    // Camera
                        "com.samsung.android.sm.devicesecurity", // Device Security
                        "com.samsung.android.themestore",    // Theme Store
                        "com.samsung.android.app.spage",     // Samsung Free
                        "com.samsung.android.app.dressroom", // AR Zone
                        "com.samsung.android.mobileservice", // Samsung Experience Service
                        "com.sec.android.app.myfiles"        // My Files
                )
                .setSystemProperties(
                        "ro.build.display.id",
                        "ro.boot.em.model"
                )
                .setFingerprintPatterns("samsung")
                .setHasGms(true));

        // ==================== Meizu ====================
        vendors.add(new VendorProfile("meizu", "魅族")
                .setBrands("meizu")
                .setManufacturers("meizu")
                .setRomName("Flyme")
                .setRomVersionProperties(
                        "ro.build.display.id",
                        "ro.flyme.published"
                )
                .setRequiredPackages(
                        "com.meizu.flyme.launcher"      // Flyme Launcher
                )
                .setOptionalPackages(
                        "com.meizu.account",            // Meizu Account
                        "com.meizu.mstore",             // App Store
                        "com.meizu.flyme.update",       // System Update
                        "com.meizu.media.music",        // Music
                        "com.meizu.media.video",        // Video
                        "com.meizu.media.gallery",      // Gallery
                        "com.meizu.flyme.input",        // Input Method
                        "com.meizu.safe",               // Security
                        "com.meizu.notepaper"           // Notes
                )
                .setSystemProperties(
                        "ro.meizu.product.model"
                )
                .setFingerprintPatterns("meizu")
                .setHasGms(true));

        // ==================== Lenovo / Motorola ====================
        vendors.add(new VendorProfile("lenovo", "联想/摩托罗拉")
                .setBrands("lenovo", "motorola", "moto")
                .setManufacturers("lenovo", "motorola")
                .setRomName("Stock Android/ZUI")
                .setRomVersionProperties(
                        "ro.build.version.zui",
                        "ro.mot.build.customerid"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "com.motorola.motocare",        // Moto Care
                        "com.motorola.actions",         // Moto Actions
                        "com.motorola.launcher3",       // Launcher
                        "com.lenovo.lsf.user",          // Lenovo Service
                        "com.motorola.gamemode"         // Game Mode
                )
                .setSystemProperties(
                        "ro.lenovo.series"
                )
                .setFingerprintPatterns("lenovo", "motorola", "moto")
                .setHasGms(true));

        // ==================== ZTE / Nubia ====================
        vendors.add(new VendorProfile("zte", "中兴/努比亚")
                .setBrands("zte", "nubia")
                .setManufacturers("zte", "nubia")
                .setRomName("MyOS/Nubia UI")
                .setRomVersionProperties(
                        "ro.build.MiFavor_version",
                        "ro.build.nubia.rom.name"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "cn.nubia.neopower",            // Neo Power
                        "cn.nubia.gamespace",           // Game Space
                        "com.zte.heartyservice"         // ZTE Service
                )
                .setSystemProperties(
                        "ro.product.zte.config.version"
                )
                .setFingerprintPatterns("zte", "nubia")
                .setHasGms(true));

        // ==================== Sony ====================
        vendors.add(new VendorProfile("sony", "索尼")
                .setBrands("sony")
                .setManufacturers("sony")
                .setRomName("Stock Android")
                .setRomVersionProperties(
                        "ro.semc.version.sw"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "com.sonymobile.home",          // Launcher
                        "com.sonymobile.photo.editor",  // Photo Editor
                        "com.sonymobile.album"          // Album
                )
                .setSystemProperties(
                        "ro.semc.product.model"
                )
                .setFingerprintPatterns("sony")
                .setHasGms(true));

        // ==================== Google Pixel ====================
        vendors.add(new VendorProfile("google", "Google")
                .setBrands("google")
                .setManufacturers("google")
                .setRomName("Pixel UI")
                .setRomVersionProperties(
                        "ro.product.device"
                )
                .setRequiredPackages(
                        "com.google.android.apps.nexuslauncher" // Pixel Launcher
                )
                .setOptionalPackages(
                        "com.google.android.apps.photos",       // Photos
                        "com.google.android.apps.recorder",     // Recorder
                        "com.google.android.apps.tips",         // Tips
                        "com.google.android.apps.wellbeing",    // Digital Wellbeing
                        "com.google.android.GoogleCamera"       // Camera
                )
                .setSystemProperties()
                .setFingerprintPatterns("google", "pixel")
                .setHasGms(true));

        // ==================== ASUS ====================
        vendors.add(new VendorProfile("asus", "华硕")
                .setBrands("asus")
                .setManufacturers("asus")
                .setRomName("ZenUI/ROG UI")
                .setRomVersionProperties(
                        "ro.build.asus.sku"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "com.asus.launcher3",           // Launcher
                        "com.asus.gamewidget",          // Game Genie
                        "com.asus.aura.service"         // Aura RGB
                )
                .setSystemProperties(
                        "ro.asus.ui.version"
                )
                .setFingerprintPatterns("asus")
                .setHasGms(true));

        // ==================== LG ====================
        vendors.add(new VendorProfile("lg", "LG")
                .setBrands("lge", "lg")
                .setManufacturers("lge", "lg")
                .setRomName("LG UX")
                .setRomVersionProperties(
                        "ro.lge.swversion"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "com.lge.launcher3",            // Launcher
                        "com.lge.qmemoplus"             // QuickMemo+
                )
                .setSystemProperties()
                .setFingerprintPatterns("lge", "lg")
                .setHasGms(true));

        // ==================== HTC ====================
        vendors.add(new VendorProfile("htc", "HTC")
                .setBrands("htc")
                .setManufacturers("htc")
                .setRomName("HTC Sense")
                .setRomVersionProperties(
                        "ro.build.sense.version"
                )
                .setRequiredPackages()
                .setOptionalPackages(
                        "com.htc.launcher"              // Launcher
                )
                .setSystemProperties()
                .setFingerprintPatterns("htc")
                .setHasGms(true));
    }

    /**
     * Get all vendor profiles
     */
    public List<VendorProfile> getAllVendors() {
        return vendors;
    }

    /**
     * Find vendor profile by brand
     */
    public VendorProfile findByBrand(String brand) {
        if (brand == null) return null;
        for (VendorProfile vendor : vendors) {
            if (vendor.matchesBrand(brand)) {
                return vendor;
            }
        }
        return null;
    }

    /**
     * Find vendor profile by manufacturer
     */
    public VendorProfile findByManufacturer(String manufacturer) {
        if (manufacturer == null) return null;
        for (VendorProfile vendor : vendors) {
            if (vendor.matchesManufacturer(manufacturer)) {
                return vendor;
            }
        }
        return null;
    }

    /**
     * Find vendor profile by brand or manufacturer
     */
    public VendorProfile findVendor(String brand, String manufacturer) {
        VendorProfile profile = findByBrand(brand);
        if (profile == null) {
            profile = findByManufacturer(manufacturer);
        }
        return profile;
    }
}
