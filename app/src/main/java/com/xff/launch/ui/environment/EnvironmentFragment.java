package com.xff.launch.ui.environment;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.chip.Chip;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import com.xff.launch.R;
import com.xff.launch.adapter.DetectionGroupAdapter;
import com.xff.launch.detector.DebugDetector;
import com.xff.launch.detector.EmulatorDetector;
import com.xff.launch.detector.HookDetector;
import com.xff.launch.detector.NetworkDetector;
import com.xff.launch.detector.ReadlinkDetector;
import com.xff.launch.detector.RootDetector;
import com.xff.launch.detector.SideChannelDetector;
import com.xff.launch.detector.ZygoteDetector;
import com.xff.launch.detector.TamperDetector;
import com.xff.launch.detector.BootloaderDetector;
import com.xff.launch.detector.DeviceAuthenticityDetector;
import com.xff.launch.detector.MultiInstanceDetector;
import com.xff.launch.model.DetectionCategory;
import com.xff.launch.model.DetectionGroup;
import com.xff.launch.model.DetectionResult;
import com.xff.launch.model.DetectionStatus;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Environment detection fragment
 */
public class EnvironmentFragment extends Fragment {

    private SwipeRefreshLayout swipeRefresh;
    private TextView tvSafeCount;
    private TextView tvRiskCount;
    private TextView tvWarningCount;
    private TextView tvUnknownCount;
    private TextView tvScore;
    private Chip tvStatusLabel;
    private TextView tvLastCheckTime;
    private LinearProgressIndicator progressScore;
    private RecyclerView recyclerDetection;

    private DetectionGroupAdapter adapter;
    private ExecutorService executor;
    private DetectionResult currentResult;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_environment, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        initViews(view);
        setupRecyclerView();
        startDetection();
    }

    private void initViews(View view) {
        swipeRefresh = view.findViewById(R.id.swipe_refresh);
        tvSafeCount = view.findViewById(R.id.tv_safe_count);
        tvRiskCount = view.findViewById(R.id.tv_risk_count);
        tvWarningCount = view.findViewById(R.id.tv_warning_count);
        tvUnknownCount = view.findViewById(R.id.tv_unknown_count);
        tvScore = view.findViewById(R.id.tv_score);
        tvStatusLabel = view.findViewById(R.id.tv_status_label);
        tvLastCheckTime = view.findViewById(R.id.tv_last_check_time);
        progressScore = view.findViewById(R.id.progress_score);
        recyclerDetection = view.findViewById(R.id.recycler_detection);

        swipeRefresh.setColorSchemeResources(R.color.primary);
        swipeRefresh.setOnRefreshListener(this::startDetection);
    }

    private void setupRecyclerView() {
        adapter = new DetectionGroupAdapter();
        adapter.setOnItemClickListener(this::showDetectionDetail);
        recyclerDetection.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerDetection.setAdapter(adapter);
    }

    /**
     * Show detection detail dialog
     */
    private void showDetectionDetail(com.xff.launch.model.DetectionItem item) {
        com.xff.launch.ui.DetectionDetailDialog dialog =
                com.xff.launch.ui.DetectionDetailDialog.newInstance(item);
        dialog.show(getParentFragmentManager(), "detection_detail");
    }

    public void startDetection() {
        if (executor == null) {
            executor = Executors.newSingleThreadExecutor();
        }

        // Cache context and strings on main thread before going to background
        if (!isAdded()) return;
        final Context ctx = requireContext().getApplicationContext();
        final String strRoot = getString(R.string.category_root);
        final String strHook = getString(R.string.category_hook);
        final String strEmulator = getString(R.string.category_emulator);
        final String strDebug = getString(R.string.category_debug);
        final String strSideChannel = getString(R.string.category_side_channel);
        final String strReadlink = getString(R.string.category_readlink);
        final String strZygote = getString(R.string.category_zygote);
        final String strTamper = getString(R.string.category_tamper);
        final String strBootloader = getString(R.string.category_bootloader);
        final String strNetwork = getString(R.string.category_network);
        final String strAuthenticity = getString(R.string.category_authenticity);
        final String strMultiInstance = getString(R.string.category_multi_instance);

        swipeRefresh.setRefreshing(true);

        executor.execute(() -> {
            DetectionResult result = performDetection(ctx,
                    strRoot, strHook, strEmulator, strDebug, strSideChannel,
                    strReadlink, strZygote, strTamper, strBootloader, strNetwork,
                    strAuthenticity, strMultiInstance);

            if (getActivity() != null && isAdded()) {
                getActivity().runOnUiThread(() -> {
                    if (!isAdded()) return;
                    currentResult = result;
                    updateUI(result);
                    swipeRefresh.setRefreshing(false);
                });
            }
        });
    }

    private DetectionResult performDetection(Context ctx,
            String strRoot, String strHook, String strEmulator, String strDebug,
            String strSideChannel, String strReadlink, String strZygote,
            String strTamper, String strBootloader, String strNetwork,
            String strAuthenticity, String strMultiInstance) {
        DetectionResult result = new DetectionResult();
        List<DetectionGroup> groups = new ArrayList<>();

        // Root Detection Group
        DetectionGroup rootGroup = new DetectionGroup(
                strRoot,
                DetectionCategory.ROOT,
                R.drawable.ic_root
        );
        RootDetector rootDetector = new RootDetector(ctx);
        rootGroup.setItems(rootDetector.getAllDetections());
        groups.add(rootGroup);

        // Hook Detection Group
        DetectionGroup hookGroup = new DetectionGroup(
                strHook,
                DetectionCategory.HOOK,
                R.drawable.ic_hook
        );
        HookDetector hookDetector = new HookDetector(ctx);
        hookGroup.setItems(hookDetector.getAllDetections());
        groups.add(hookGroup);

        // Emulator Detection Group
        DetectionGroup emulatorGroup = new DetectionGroup(
                strEmulator,
                DetectionCategory.EMULATOR,
                R.drawable.ic_emulator
        );
        EmulatorDetector emulatorDetector = new EmulatorDetector(ctx);
        emulatorGroup.setItems(emulatorDetector.getAllDetections());
        groups.add(emulatorGroup);

        // Debug Detection Group
        DetectionGroup debugGroup = new DetectionGroup(
                strDebug,
                DetectionCategory.DEBUG,
                R.drawable.ic_debug
        );
        DebugDetector debugDetector = new DebugDetector(ctx);
        debugGroup.setItems(debugDetector.getAllDetections());
        groups.add(debugGroup);

        // Network Detection Group (VPN / proxy / local proxy ports / routes)
        DetectionGroup networkGroup = new DetectionGroup(
                strNetwork,
                DetectionCategory.NETWORK,
                R.drawable.ic_network
        );
        NetworkDetector networkDetector = new NetworkDetector(ctx);
        networkGroup.setItems(networkDetector.getAllDetections());
        groups.add(networkGroup);

        // Runtime Integrity Detection Group
        DetectionGroup sideChannelGroup = new DetectionGroup(
                strSideChannel,
                DetectionCategory.SIDE_CHANNEL,
                R.drawable.ic_side_channel
        );
        SideChannelDetector sideChannelDetector = new SideChannelDetector(ctx);
        sideChannelGroup.setItems(sideChannelDetector.getAllDetections());
        groups.add(sideChannelGroup);

        // Readlink Detection Group
        DetectionGroup readlinkGroup = new DetectionGroup(
                strReadlink,
                DetectionCategory.READLINK,
                R.drawable.ic_readlink
        );
        ReadlinkDetector readlinkDetector = new ReadlinkDetector(ctx);
        readlinkGroup.setItems(readlinkDetector.getAllDetections());
        groups.add(readlinkGroup);

        // Zygote Injection Detection Group
        DetectionGroup zygoteGroup = new DetectionGroup(
                strZygote,
                DetectionCategory.ZYGOTE,
                R.drawable.ic_zygote
        );
        ZygoteDetector zygoteDetector = new ZygoteDetector(ctx);
        zygoteGroup.setItems(zygoteDetector.getAllDetections());
        groups.add(zygoteGroup);

        // Tamper/Device Modification Detection Group
        DetectionGroup tamperGroup = new DetectionGroup(
                strTamper,
                DetectionCategory.TAMPER,
                R.drawable.ic_tamper
        );
        TamperDetector tamperDetector = new TamperDetector(ctx);
        tamperGroup.setItems(tamperDetector.getAllDetections());
        groups.add(tamperGroup);

        // Bootloader Unlock Detection Group
        DetectionGroup bootloaderGroup = new DetectionGroup(
                strBootloader,
                DetectionCategory.BOOTLOADER,
                R.drawable.ic_bootloader
        );
        BootloaderDetector bootloaderDetector = new BootloaderDetector(ctx);
        bootloaderGroup.setItems(bootloaderDetector.getAllDetections());
        groups.add(bootloaderGroup);

        // Device Authenticity / Risk Signals (锁屏/电池/无障碍/TEE — JD field 2/5/15/14)
        DetectionGroup authenticityGroup = new DetectionGroup(
                strAuthenticity,
                DetectionCategory.AUTHENTICITY,
                R.drawable.ic_phone
        );
        DeviceAuthenticityDetector authenticityDetector = new DeviceAuthenticityDetector(ctx);
        authenticityGroup.setItems(authenticityDetector.getAllDetections());
        groups.add(authenticityGroup);

        // Multi-instance / Sandbox Hijack (多开容器/fd路径劫持 — JD field 1)
        DetectionGroup multiInstanceGroup = new DetectionGroup(
                strMultiInstance,
                DetectionCategory.MULTI_INSTANCE,
                R.drawable.ic_readlink
        );
        MultiInstanceDetector multiInstanceDetector = new MultiInstanceDetector(ctx);
        multiInstanceGroup.setItems(multiInstanceDetector.getAllDetections());
        groups.add(multiInstanceGroup);

        result.setGroups(groups);
        result.calculateScore();

        return result;
    }

    private void updateUI(DetectionResult result) {
        // Update counts
        tvSafeCount.setText(String.valueOf(result.getSafeCount()));
        tvRiskCount.setText(String.valueOf(result.getRiskCount()));
        tvWarningCount.setText(String.valueOf(result.getWarningCount()));
        tvUnknownCount.setText(String.valueOf(result.getUnknownCount()));

        // Update score
        int score = result.getOverallScore();
        tvScore.setText(getString(R.string.score_format, score));
        progressScore.setProgress(score);

        // Update status label (M3 Chip)
        DetectionStatus status = result.getOverallStatus();
        switch (status) {
            case SAFE:
                tvStatusLabel.setText(getString(R.string.status_safe));
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe_on_container));
                tvStatusLabel.setChipBackgroundColorResource(R.color.status_safe_container);
                progressScore.setIndicatorColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
                break;
            case RISK:
                tvStatusLabel.setText("高风险");
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk_on_container));
                tvStatusLabel.setChipBackgroundColorResource(R.color.status_risk_container);
                progressScore.setIndicatorColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
                break;
            case WARNING:
                tvStatusLabel.setText("中等风险");
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_warning_on_container));
                tvStatusLabel.setChipBackgroundColorResource(R.color.status_warning_container);
                progressScore.setIndicatorColor(ContextCompat.getColor(requireContext(), R.color.status_warning));
                break;
            default:
                tvStatusLabel.setText(getString(R.string.status_unknown));
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_unknown_on_container));
                tvStatusLabel.setChipBackgroundColorResource(R.color.status_unknown_container);
                break;
        }

        // Update last check time
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        tvLastCheckTime.setText(getString(R.string.last_check_time, sdf.format(new Date())));

        // Update detection groups
        adapter.setGroups(result.getGroups());
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }
}
