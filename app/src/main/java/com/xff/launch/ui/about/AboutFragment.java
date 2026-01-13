package com.xff.launch.ui.about;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.google.android.material.button.MaterialButton;
import com.xff.launch.R;

/**
 * About page fragment with author info and app features
 */
public class AboutFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_about, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        TextView tvVersion = view.findViewById(R.id.tv_version);
        TextView tvEmail = view.findViewById(R.id.tv_email);
        MaterialButton btnUpdate = view.findViewById(R.id.btn_update);
        MaterialButton btnFeedback = view.findViewById(R.id.btn_feedback);

        // Set dynamic version number
        setVersionInfo(tvVersion);

        // WeChat ID click - copy to clipboard
        tvEmail.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) requireContext()
                    .getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("WeChat", getString(R.string.author_wechat));
            clipboard.setPrimaryClip(clip);
            Toast.makeText(requireContext(), R.string.copied, Toast.LENGTH_SHORT).show();
        });

        // Check update button
        btnUpdate.setOnClickListener(v -> {
            Toast.makeText(requireContext(), "当前已是最新版本", Toast.LENGTH_SHORT).show();
        });

        // Feedback button - copy WeChat ID
        btnFeedback.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) requireContext()
                    .getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("WeChat", "xx1193776794");
            clipboard.setPrimaryClip(clip);
            Toast.makeText(requireContext(), "微信号已复制，请在微信中添加好友", Toast.LENGTH_SHORT).show();
        });
    }

    /**
     * Set version info dynamically from PackageInfo
     */
    private void setVersionInfo(TextView tvVersion) {
        try {
            String packageName = requireContext().getPackageName();
            android.content.pm.PackageInfo packageInfo = requireContext()
                    .getPackageManager()
                    .getPackageInfo(packageName, 0);

            // Get version name (e.g. "1.0.0")
            String versionName = packageInfo.versionName;

            // Format and set version text
            String versionText = getString(R.string.version_format, versionName);
            tvVersion.setText(versionText);

        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            // Fallback to default string if package info not found
            tvVersion.setText(R.string.app_version);
        }
    }
}
