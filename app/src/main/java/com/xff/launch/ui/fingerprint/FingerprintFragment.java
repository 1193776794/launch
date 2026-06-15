package com.xff.launch.ui.fingerprint;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.card.MaterialCardView;
import com.xff.launch.R;
import com.xff.launch.detector.NativeDetector;
import com.xff.launch.model.CollectProbe;
import com.xff.launch.model.FingerprintItem;
import com.xff.launch.model.FingerprintResult;
import com.xff.launch.model.ProbeMethod;
import com.xff.launch.model.ProbeStatus;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 指纹信息页。
 *
 * <p>本类只做两件事：调引擎采集 → 绑定 UI。所有取证逻辑都在
 * {@link FingerprintDefinitions} 声明，引擎在 {@link FingerprintEngine} 执行。
 */
public class FingerprintFragment extends Fragment {

    private SwipeRefreshLayout swipeRefresh;
    private TextView tvDeviceFingerprint;
    private TextView tvConsistencySummary;
    private View ivStatusIcon;
    private RecyclerView recyclerIdentifiers;

    private View btnCopyFingerprint;

    private ExecutorService executor;
    private FingerprintResult currentResult;
    private NativeDetector nativeDetector;
    private final FingerprintEngine engine = new FingerprintEngine();

    // 经纬度/基站/Wi-Fi 位置指纹需定位权限，授予/拒绝后都重采一次刷新结果
    private ActivityResultLauncher<String[]> locationPermLauncher;
    private boolean locationRequested = false;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        locationPermLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestMultiplePermissions(),
                granted -> { if (isAdded()) collectFingerprints(); });
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_fingerprint, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        nativeDetector = NativeDetector.getInstance();
        initViews(view);
        setupCopyButtons();
        collectFingerprints();
        maybeRequestLocationPermission();
    }

    /** 首次进入若无定位权限则申请一次（用于经纬度/基站/Wi-Fi BSSID 位置指纹）。 */
    private void maybeRequestLocationPermission() {
        if (locationRequested || locationPermLauncher == null || !isAdded()) return;
        boolean granted = ContextCompat.checkSelfPermission(requireContext(),
                Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        if (!granted) {
            locationRequested = true;
            locationPermLauncher.launch(new String[]{
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION
            });
        }
    }

    private void initViews(View view) {
        swipeRefresh = view.findViewById(R.id.swipe_refresh);
        tvDeviceFingerprint = view.findViewById(R.id.tv_device_fingerprint);
        tvConsistencySummary = view.findViewById(R.id.tv_consistency_summary);
        ivStatusIcon = view.findViewById(R.id.iv_status_icon);

        recyclerIdentifiers = view.findViewById(R.id.recycler_identifiers);

        btnCopyFingerprint = view.findViewById(R.id.btn_copy_fingerprint);

        swipeRefresh.setColorSchemeResources(R.color.primary);
        swipeRefresh.setOnRefreshListener(this::collectFingerprints);

        recyclerIdentifiers.setLayoutManager(new LinearLayoutManager(requireContext()));
    }

    private void setupCopyButtons() {
        btnCopyFingerprint.setOnClickListener(v -> copyToClipboard("Device Fingerprint", tvDeviceFingerprint.getText().toString()));
    }

    public void collectFingerprints() {
        if (executor == null) {
            executor = Executors.newSingleThreadExecutor();
        }
        swipeRefresh.setRefreshing(true);

        executor.execute(() -> {
            FingerprintResult result = engine.collect(
                    FingerprintDefinitions.build(requireContext().getApplicationContext(), nativeDetector));

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

    private void updateUI(FingerprintResult result) {
        // 设备指纹 hash
        String compositeFp = result.getCompositeFingerprint();
        tvDeviceFingerprint.setText(compositeFp != null
                ? compositeFp.substring(0, Math.min(32, compositeFp.length())) : "");

        // 一致性汇总（取消信任分，改为计数 + 颜色）
        int total = result.getItems().size();
        int consistent = result.getConsistentCount();
        boolean clean = !result.hasInconsistency();
        int color = ContextCompat.getColor(requireContext(), clean ? R.color.status_safe : R.color.status_risk);
        tvConsistencySummary.setText(String.format("指纹一致性 %d/%d 项一致", consistent, total));
        tvConsistencySummary.setTextColor(color);
        ivStatusIcon.setBackgroundTintList(ColorStateList.valueOf(color));

        recyclerIdentifiers.setAdapter(new FingerprintItemAdapter(requireContext(), result.getItems()));
    }

    private void copyToClipboard(String label, String text) {
        ClipboardManager clipboard = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText(label, text));
        Toast.makeText(requireContext(), R.string.copied, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    // ==================== 可展开适配器 ====================

    private static class FingerprintItemAdapter extends RecyclerView.Adapter<FingerprintItemAdapter.ViewHolder> {
        private final Context context;
        private final List<FingerprintItem> items;
        private final Set<Integer> expanded = new HashSet<>();

        FingerprintItemAdapter(Context context, List<FingerprintItem> items) {
            this.context = context;
            this.items = items != null ? items : new ArrayList<>();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_fingerprint, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            FingerprintItem item = items.get(position);
            boolean consistent = item.isConsistent();
            boolean isExpanded = expanded.contains(position);

            holder.tvName.setText(item.getDisplayName());
            holder.tvValue.setText(item.getHitValue());

            // 颜色标识：一致/不一致
            int strokeColor = ContextCompat.getColor(context, consistent ? R.color.status_safe : R.color.status_risk);
            holder.card.setStrokeColor(strokeColor);
            holder.accentBar.setBackgroundResource(consistent ? R.drawable.card_accent_safe : R.drawable.card_accent_risk);
            holder.tvConsistency.setText(consistent ? "一致" : "不一致");
            holder.tvConsistency.setBackgroundColor(ContextCompat.getColor(context,
                    consistent ? R.color.status_safe_container : R.color.status_risk_container));
            holder.tvConsistency.setTextColor(ContextCompat.getColor(context,
                    consistent ? R.color.status_safe_on_container : R.color.status_risk_on_container));

            // 展开/折叠
            holder.ivExpand.setImageResource(isExpanded ? R.drawable.ic_collapse : R.drawable.ic_expand);
            holder.probeContainer.setVisibility(isExpanded ? View.VISIBLE : View.GONE);
            holder.tvSummary.setVisibility(isExpanded ? View.VISIBLE : View.GONE);
            if (isExpanded) {
                bindProbes(holder, item);
            } else {
                holder.probeContainer.removeAllViews();
            }

            holder.header.setOnClickListener(v -> {
                int pos = holder.getBindingAdapterPosition();
                if (pos == RecyclerView.NO_POSITION) return;
                if (expanded.contains(pos)) expanded.remove(pos);
                else expanded.add(pos);
                notifyItemChanged(pos);
            });
            holder.header.setOnLongClickListener(v -> {
                ClipboardManager cb = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                cb.setPrimaryClip(ClipData.newPlainText(item.getDisplayName(), item.getHitValue()));
                Toast.makeText(context, R.string.copied, Toast.LENGTH_SHORT).show();
                return true;
            });
        }

        private void bindProbes(ViewHolder holder, FingerprintItem item) {
            holder.probeContainer.removeAllViews();
            LayoutInflater inflater = LayoutInflater.from(context);
            for (CollectProbe p : item.getProbes()) {
                View row = inflater.inflate(R.layout.item_probe, holder.probeContainer, false);
                ProbeMethod m = p.getMethod();
                ((TextView) row.findViewById(R.id.tv_icon)).setText(m.getIcon());
                ((TextView) row.findViewById(R.id.tv_method)).setText(m.getDisplayName());

                String api = p.getApi();
                if (p.getSource() != null && !p.getSource().isEmpty()) {
                    api = api + " · " + p.getSource();
                }
                ((TextView) row.findViewById(R.id.tv_api)).setText(api);
                ((TextView) row.findViewById(R.id.tv_result)).setText(p.getDisplayValue());

                View dot = row.findViewById(R.id.iv_status);
                dot.setBackgroundTintList(ColorStateList.valueOf(probeColor(p)));
                holder.probeContainer.addView(row);
            }

            // 底部汇总
            int ok = item.getOkCount();
            int outliers = item.getOutlierCount();
            String summary;
            if (item.isConsistent()) {
                summary = String.format("%d 路采集 · %d 路一致 · 命中 %s",
                        item.getProbes().size(), ok, shorten(item.getHitValue()));
            } else {
                summary = String.format("⚠ %d 路采集 · %d 路异常 · 命中 %s",
                        item.getProbes().size(), outliers, shorten(item.getHitValue()));
            }
            holder.tvSummary.setText(summary);
        }

        private int probeColor(CollectProbe p) {
            if (p.getStatus() == ProbeStatus.OK) {
                return ContextCompat.getColor(context, p.isOutlier() ? R.color.status_risk : R.color.status_safe);
            } else if (p.getStatus() == ProbeStatus.ERROR) {
                return ContextCompat.getColor(context, R.color.status_warning);
            }
            return ContextCompat.getColor(context, R.color.md_theme_light_outline);
        }

        private String shorten(String s) {
            if (s == null) return "";
            return s.length() <= 16 ? s : s.substring(0, 16) + "..";
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            final MaterialCardView card;
            final View accentBar;
            final View header;
            final TextView tvName, tvValue, tvConsistency, tvSummary;
            final ImageView ivExpand;
            final ViewGroup probeContainer;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                card = (MaterialCardView) itemView;
                accentBar = itemView.findViewById(R.id.accent_bar);
                header = itemView.findViewById(R.id.header);
                tvName = itemView.findViewById(R.id.tv_name);
                tvValue = itemView.findViewById(R.id.tv_value);
                tvConsistency = itemView.findViewById(R.id.tv_consistency);
                tvSummary = itemView.findViewById(R.id.tv_summary);
                ivExpand = itemView.findViewById(R.id.iv_expand);
                probeContainer = itemView.findViewById(R.id.probe_container);
            }
        }
    }
}
