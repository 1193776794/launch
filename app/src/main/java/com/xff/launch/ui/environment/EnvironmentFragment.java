package com.xff.launch.ui.environment;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.xff.launch.R;
import com.xff.launch.adapter.DetectionGroupAdapter;
import com.xff.launch.detector.DebugDetector;
import com.xff.launch.detector.EmulatorDetector;
import com.xff.launch.detector.HookDetector;
import com.xff.launch.detector.ReadlinkDetector;
import com.xff.launch.detector.RootDetector;
import com.xff.launch.detector.SideChannelDetector;
import com.xff.launch.detector.ZygoteDetector;
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
    private TextView tvStatusLabel;
    private TextView tvLastCheckTime;
    private ProgressBar progressScore;
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

        swipeRefresh.setRefreshing(true);

        executor.execute(() -> {
            DetectionResult result = performDetection();

            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    currentResult = result;
                    updateUI(result);
                    swipeRefresh.setRefreshing(false);
                });
            }
        });
    }

    private DetectionResult performDetection() {
        DetectionResult result = new DetectionResult();
        List<DetectionGroup> groups = new ArrayList<>();

        // Root Detection Group
        DetectionGroup rootGroup = new DetectionGroup(
                getString(R.string.category_root),
                DetectionCategory.ROOT,
                R.drawable.ic_root
        );
        RootDetector rootDetector = new RootDetector(requireContext());
        rootGroup.setItems(rootDetector.getAllDetections());
        groups.add(rootGroup);

        // Hook Detection Group
        DetectionGroup hookGroup = new DetectionGroup(
                getString(R.string.category_hook),
                DetectionCategory.HOOK,
                R.drawable.ic_hook
        );
        HookDetector hookDetector = new HookDetector(requireContext());
        hookGroup.setItems(hookDetector.getAllDetections());
        groups.add(hookGroup);

        // Emulator Detection Group
        DetectionGroup emulatorGroup = new DetectionGroup(
                getString(R.string.category_emulator),
                DetectionCategory.EMULATOR,
                R.drawable.ic_emulator
        );
        EmulatorDetector emulatorDetector = new EmulatorDetector(requireContext());
        emulatorGroup.setItems(emulatorDetector.getAllDetections());
        groups.add(emulatorGroup);

        // Debug Detection Group
        DetectionGroup debugGroup = new DetectionGroup(
                getString(R.string.category_debug),
                DetectionCategory.DEBUG,
                R.drawable.ic_debug
        );
        DebugDetector debugDetector = new DebugDetector(requireContext());
        debugGroup.setItems(debugDetector.getAllDetections());
        groups.add(debugGroup);

        // Side-Channel Attack Detection Group
        DetectionGroup sideChannelGroup = new DetectionGroup(
                getString(R.string.category_side_channel),
                DetectionCategory.SIDE_CHANNEL,
                R.drawable.ic_side_channel
        );
        SideChannelDetector sideChannelDetector = new SideChannelDetector(requireContext());
        sideChannelGroup.setItems(sideChannelDetector.getAllDetections());
        groups.add(sideChannelGroup);

        // Readlink Detection Group (Symlink/Proc/Namespace)
        DetectionGroup readlinkGroup = new DetectionGroup(
                getString(R.string.category_readlink),
                DetectionCategory.READLINK,
                R.drawable.ic_readlink
        );
        ReadlinkDetector readlinkDetector = new ReadlinkDetector(requireContext());
        readlinkGroup.setItems(readlinkDetector.getAllDetections());
        groups.add(readlinkGroup);

        // Zygote Injection Detection Group (Zygisk/Riru/LSPosed)
        DetectionGroup zygoteGroup = new DetectionGroup(
                getString(R.string.category_zygote),
                DetectionCategory.ZYGOTE,
                R.drawable.ic_zygote
        );
        ZygoteDetector zygoteDetector = new ZygoteDetector(requireContext());
        zygoteGroup.setItems(zygoteDetector.getAllDetections());
        groups.add(zygoteGroup);

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

        // Update status label
        DetectionStatus status = result.getOverallStatus();
        switch (status) {
            case SAFE:
                tvStatusLabel.setText(getString(R.string.status_safe));
                tvStatusLabel.setBackgroundResource(R.drawable.card_background);
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
                progressScore.setProgressTintList(ContextCompat.getColorStateList(requireContext(), R.color.status_safe));
                break;
            case RISK:
                tvStatusLabel.setText("高风险");
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
                progressScore.setProgressTintList(ContextCompat.getColorStateList(requireContext(), R.color.status_risk));
                break;
            case WARNING:
                tvStatusLabel.setText("中等风险");
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_warning));
                progressScore.setProgressTintList(ContextCompat.getColorStateList(requireContext(), R.color.status_warning));
                break;
            default:
                tvStatusLabel.setText(getString(R.string.status_unknown));
                tvStatusLabel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_unknown));
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
