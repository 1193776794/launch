package com.xff.launch.model;

/**
 * Vendor service model for device legitimacy verification
 */
public class VendorService {
    private String name;
    private String packageName;
    private String vendor;
    private boolean installed;
    private boolean expected;

    public VendorService(String name, String packageName, String vendor) {
        this.name = name;
        this.packageName = packageName;
        this.vendor = vendor;
        this.installed = false;
        this.expected = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getVendor() {
        return vendor;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    public boolean isInstalled() {
        return installed;
    }

    public void setInstalled(boolean installed) {
        this.installed = installed;
    }

    public boolean isExpected() {
        return expected;
    }

    public void setExpected(boolean expected) {
        this.expected = expected;
    }

    /**
     * Check if the service status matches expectations
     */
    public boolean isStatusValid() {
        // If expected and installed, or not expected and not installed, it's valid
        // If expected but not installed, it's still valid (could be user uninstalled)
        // If not expected but installed, it could indicate device modification
        return expected || !installed;
    }

    /**
     * Get status description
     */
    public String getStatusDescription() {
        if (installed && expected) {
            return "已安装";
        } else if (installed && !expected) {
            return "异常-不应存在";
        } else if (!installed && expected) {
            return "未安装";
        } else {
            return "未安装 (正常)";
        }
    }
}
