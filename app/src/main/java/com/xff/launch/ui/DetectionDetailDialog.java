package com.xff.launch.ui;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.xff.launch.R;
import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;

import java.util.List;
import java.util.Map;

/**
 * Dialog to show detailed detection information
 */
public class DetectionDetailDialog extends DialogFragment {

    private static final String ARG_NAME = "name";
    private static final String ARG_DESCRIPTION = "description";
    private static final String ARG_DETAIL = "detail";
    private static final String ARG_STATUS = "status";

    private DetectionItem detectionItem;

    public static DetectionDetailDialog newInstance(DetectionItem item) {
        DetectionDetailDialog dialog = new DetectionDetailDialog();
        Bundle args = new Bundle();
        args.putString(ARG_NAME, item.getName());
        args.putString(ARG_DESCRIPTION, item.getDescription());
        args.putString(ARG_DETAIL, item.getDetail());
        args.putString(ARG_STATUS, item.getStatus().name());
        dialog.setArguments(args);
        // Store the full item for accessing details
        dialog.detectionItem = item;
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_detection_detail, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (detectionItem == null || getArguments() == null) {
            dismiss();
            return;
        }

        // 设置标题
        TextView titleText = view.findViewById(R.id.dialog_title);
        titleText.setText(detectionItem.getName());

        // 设置描述
        TextView descText = view.findViewById(R.id.dialog_description);
        descText.setText(detectionItem.getDescription());

        // 设置状态
        TextView statusText = view.findViewById(R.id.dialog_status);
        View statusIndicator = view.findViewById(R.id.status_indicator);

        switch (detectionItem.getStatus()) {
            case SAFE:
                statusText.setText("✅ 安全");
                statusText.setTextColor(Color.parseColor("#4CAF50"));
                statusIndicator.setBackgroundColor(Color.parseColor("#4CAF50"));
                break;
            case RISK:
                statusText.setText("🔴 风险");
                statusText.setTextColor(Color.parseColor("#F44336"));
                statusIndicator.setBackgroundColor(Color.parseColor("#F44336"));
                break;
            case WARNING:
                statusText.setText("⚠️ 警告");
                statusText.setTextColor(Color.parseColor("#FF9800"));
                statusIndicator.setBackgroundColor(Color.parseColor("#FF9800"));
                break;
            case UNKNOWN:
                statusText.setText("❓ 未知");
                statusText.setTextColor(Color.parseColor("#9E9E9E"));
                statusIndicator.setBackgroundColor(Color.parseColor("#9E9E9E"));
                break;
        }

        // 设置检测层级信息
        LinearLayout layerContainer = view.findViewById(R.id.layer_container);
        if (layerContainer != null) {
            layerContainer.removeAllViews();

            Map<DetectionLayer, Boolean> layerResults = detectionItem.getLayerResults();
            if (layerResults != null && !layerResults.isEmpty()) {
                for (Map.Entry<DetectionLayer, Boolean> entry : layerResults.entrySet()) {
                    View layerView = createLayerView(entry.getKey(), entry.getValue());
                    if (layerView != null) {
                        layerContainer.addView(layerView);
                    }
                }
            }
        }

        // 设置详细信息列表
        LinearLayout detailsContainer = view.findViewById(R.id.details_container);
        if (detailsContainer != null) {
            detailsContainer.removeAllViews();

            List<DetectionItem.DetectionDetail> details = detectionItem.getDetectionDetails();
            if (details != null && !details.isEmpty()) {
            // 按分类分组
            Map<String, List<DetectionItem.DetectionDetail>> groupedDetails = new java.util.LinkedHashMap<>();
            for (DetectionItem.DetectionDetail detail : details) {
                String category = detail.getCategory();
                if (!groupedDetails.containsKey(category)) {
                    groupedDetails.put(category, new java.util.ArrayList<>());
                }
                groupedDetails.get(category).add(detail);
            }

                // 显示分组后的详细信息
                for (Map.Entry<String, List<DetectionItem.DetectionDetail>> entry : groupedDetails.entrySet()) {
                    View categoryView = createCategoryView(entry.getKey(), entry.getValue());
                    if (categoryView != null) {
                        detailsContainer.addView(categoryView);
                    }
                }
            } else {
                // 没有详细信息时显示简要说明
                TextView noDetailsText = new TextView(requireContext());
                noDetailsText.setText(detectionItem.getDetail());
                noDetailsText.setTextSize(14);
                noDetailsText.setTextColor(Color.parseColor("#666666"));
                noDetailsText.setPadding(16, 16, 16, 16);
                detailsContainer.addView(noDetailsText);
            }
        }

        // 关闭按钮
        view.findViewById(R.id.btn_close).setOnClickListener(v -> dismiss());
    }

    private View createLayerView(DetectionLayer layer, boolean detected) {
        Context context = requireContext();
        LinearLayout layerView = new LinearLayout(context);
        layerView.setOrientation(LinearLayout.HORIZONTAL);
        layerView.setPadding(16, 8, 16, 8);

        // 层级名称
        TextView layerName = new TextView(context);
        String layerText = "";
        switch (layer) {
            case JAVA:
                layerText = "☕ Java层";
                break;
            case NATIVE:
                layerText = "🔧 Native层";
                break;
            case SYSCALL:
                layerText = "⚙️ Syscall层";
                break;
        }
        layerName.setText(layerText);
        layerName.setTextSize(14);
        layerName.setTextColor(Color.parseColor("#333333"));
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
            0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        layerName.setLayoutParams(nameParams);

        // 检测结果
        TextView resultText = new TextView(context);
        if (detected) {
            resultText.setText("✓ 检测到");
            resultText.setTextColor(Color.parseColor("#F44336"));
        } else {
            resultText.setText("✗ 未检测到");
            resultText.setTextColor(Color.parseColor("#4CAF50"));
        }
        resultText.setTextSize(14);

        layerView.addView(layerName);
        layerView.addView(resultText);

        return layerView;
    }

    private View createCategoryView(String category, List<DetectionItem.DetectionDetail> details) {
        Context context = requireContext();
        LinearLayout categoryView = new LinearLayout(context);
        categoryView.setOrientation(LinearLayout.VERTICAL);
        categoryView.setPadding(0, 16, 0, 0);

        // 分类标题
        TextView categoryTitle = new TextView(context);
        categoryTitle.setText(category);
        categoryTitle.setTextSize(16);
        categoryTitle.setTextColor(Color.parseColor("#333333"));
        categoryTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        categoryTitle.setPadding(16, 8, 16, 8);
        categoryView.addView(categoryTitle);

        // 分类下的详细项目
        for (DetectionItem.DetectionDetail detail : details) {
            View detailView = createDetailItemView(detail);
            categoryView.addView(detailView);
        }

        return categoryView;
    }

    private View createDetailItemView(DetectionItem.DetectionDetail detail) {
        Context context = requireContext();
        LinearLayout itemView = new LinearLayout(context);
        itemView.setOrientation(LinearLayout.VERTICAL);
        itemView.setPadding(32, 8, 16, 8);

        int backgroundColor = Color.parseColor("#F8F8F8");
        int titleColor = Color.parseColor("#333333");
        int valueColor = Color.parseColor("#666666");
        if (isRiskDetail(detail)) {
            backgroundColor = Color.parseColor("#FFEBEE");
            titleColor = Color.parseColor("#D32F2F");
            valueColor = Color.parseColor("#B71C1C");
        } else if (isWarningDetail(detail)) {
            backgroundColor = Color.parseColor("#FFF8E1");
            titleColor = Color.parseColor("#E65100");
            valueColor = Color.parseColor("#795548");
        } else if (isSafeDetail(detail)) {
            backgroundColor = Color.parseColor("#F1F8E9");
            titleColor = Color.parseColor("#2E7D32");
            valueColor = Color.parseColor("#33691E");
        }
        itemView.setBackgroundColor(backgroundColor);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, 4, 0, 4);
        itemView.setLayoutParams(params);

        // 项目名称行
        LinearLayout headerRow = new LinearLayout(context);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);

        TextView iconText = new TextView(context);
        iconText.setText(detail.getIcon() + " ");
        iconText.setTextSize(14);
        iconText.setTextColor(titleColor);

        TextView itemName = new TextView(context);
        itemName.setText(detail.getItem());
        itemName.setTextSize(14);
        itemName.setTextColor(titleColor);
        itemName.setTypeface(null, android.graphics.Typeface.BOLD);

        headerRow.addView(iconText);
        headerRow.addView(itemName);

        // 值
        TextView valueText = new TextView(context);
        valueText.setText(detail.getValue());
        valueText.setTextSize(13);
        valueText.setTextColor(valueColor);
        valueText.setPadding(0, 4, 0, 0);
        valueText.setLineSpacing(4, 1.0f);

        // 层级标签
        TextView layerTag = new TextView(context);
        String layerText = "";
        switch (detail.getLayer()) {
            case JAVA:
                layerText = "Java";
                layerTag.setTextColor(Color.parseColor("#2196F3"));
                break;
            case NATIVE:
                layerText = "Native";
                layerTag.setTextColor(Color.parseColor("#FF9800"));
                break;
            case SYSCALL:
                layerText = "Syscall";
                layerTag.setTextColor(Color.parseColor("#9C27B0"));
                break;
        }
        layerTag.setText("• " + layerText);
        layerTag.setTextSize(11);
        layerTag.setPadding(0, 4, 0, 0);

        itemView.addView(headerRow);
        itemView.addView(valueText);
        itemView.addView(layerTag);

        return itemView;
    }

    private boolean isRiskDetail(DetectionItem.DetectionDetail detail) {
        String icon = detail.getIcon();
        return equalsIcon(icon, "RISK")
                || equalsIcon(icon, "VPN")
                || equalsIcon(icon, "ROOT")
                || equalsIcon(icon, "HOOK")
                || equalsIcon(icon, "EMULATOR");
    }

    private boolean isWarningDetail(DetectionItem.DetectionDetail detail) {
        String icon = detail.getIcon();
        return equalsIcon(icon, "WARN")
                || equalsIcon(icon, "WARNING")
                || equalsIcon(icon, "PROXY");
    }

    private boolean isSafeDetail(DetectionItem.DetectionDetail detail) {
        String icon = detail.getIcon();
        return equalsIcon(icon, "SAFE")
                || equalsIcon(icon, "OK")
                || equalsIcon(icon, "SKIP");
    }

    private boolean equalsIcon(String icon, String expected) {
        return icon != null && expected.equalsIgnoreCase(icon.trim());
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        Dialog dialog = super.onCreateDialog(savedInstanceState);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        return dialog;
    }

    @Override
    public void onStart() {
        super.onStart();
        Dialog dialog = getDialog();
        if (dialog != null) {
            Window window = dialog.getWindow();
            if (window != null) {
                window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT);
                window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
            }
        }
    }
}
