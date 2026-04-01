package com.xff.launch.adapter;

import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.xff.launch.R;
import com.xff.launch.model.DetectionGroup;
import com.xff.launch.model.DetectionStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Adapter for detection group cards with expandable items - M3 style
 */
public class DetectionGroupAdapter extends RecyclerView.Adapter<DetectionGroupAdapter.GroupViewHolder> {

    private List<DetectionGroup> groups = new ArrayList<>();
    private DetectionItemAdapter.OnItemClickListener itemClickListener;

    public void setOnItemClickListener(DetectionItemAdapter.OnItemClickListener listener) {
        this.itemClickListener = listener;
    }

    public void setGroups(List<DetectionGroup> groups) {
        this.groups = groups;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public GroupViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_detection_group, parent, false);
        return new GroupViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull GroupViewHolder holder, int position) {
        holder.bind(groups.get(position), itemClickListener);
    }

    @Override
    public int getItemCount() {
        return groups.size();
    }

    static class GroupViewHolder extends RecyclerView.ViewHolder {
        private final ImageView ivCategoryIcon;
        private final TextView tvCategoryName;
        private final TextView tvStatusSummary;
        private final View ivStatusIcon;
        private final ImageView ivExpand;
        private final View divider;
        private final LinearLayout layoutItems;
        private final RecyclerView recyclerItems;
        private final View layoutHeader;

        GroupViewHolder(@NonNull View itemView) {
            super(itemView);
            ivCategoryIcon = itemView.findViewById(R.id.iv_category_icon);
            tvCategoryName = itemView.findViewById(R.id.tv_category_name);
            tvStatusSummary = itemView.findViewById(R.id.tv_status_summary);
            ivStatusIcon = itemView.findViewById(R.id.iv_status_icon);
            ivExpand = itemView.findViewById(R.id.iv_expand);
            divider = itemView.findViewById(R.id.divider);
            layoutItems = itemView.findViewById(R.id.layout_items);
            recyclerItems = itemView.findViewById(R.id.recycler_items);
            layoutHeader = itemView.findViewById(R.id.layout_header);
        }

        void bind(DetectionGroup group, DetectionItemAdapter.OnItemClickListener itemClickListener) {
            tvCategoryName.setText(group.getName());
            ivCategoryIcon.setImageResource(group.getIconResId());

            // Status summary (risk/total)
            int riskCount = group.getRiskCount();
            int totalCount = group.getItems() != null ? group.getItems().size() : 0;
            tvStatusSummary.setText(riskCount + "/" + totalCount);

            // Status dot color
            DetectionStatus status = group.getOverallStatus();
            int dotColor;
            switch (status) {
                case SAFE:
                    dotColor = ContextCompat.getColor(itemView.getContext(), R.color.status_safe);
                    break;
                case RISK:
                    dotColor = ContextCompat.getColor(itemView.getContext(), R.color.status_risk);
                    break;
                case WARNING:
                    dotColor = ContextCompat.getColor(itemView.getContext(), R.color.status_warning);
                    break;
                default:
                    dotColor = ContextCompat.getColor(itemView.getContext(), R.color.status_unknown);
                    break;
            }
            ivStatusIcon.setBackgroundTintList(ColorStateList.valueOf(dotColor));

            // Set expand state
            updateExpandState(group.isExpanded());

            // Set up items recycler
            DetectionItemAdapter itemAdapter = new DetectionItemAdapter();
            itemAdapter.setOnItemClickListener(itemClickListener);
            recyclerItems.setLayoutManager(new LinearLayoutManager(itemView.getContext()));
            recyclerItems.setAdapter(itemAdapter);
            itemAdapter.setItems(group.getItems());

            // Handle click to expand/collapse with arrow rotation
            layoutHeader.setOnClickListener(v -> {
                group.toggleExpanded();
                updateExpandState(group.isExpanded());

                // Animate arrow rotation
                float targetRotation = group.isExpanded() ? 180f : 0f;
                ivExpand.animate().rotation(targetRotation).setDuration(300).start();
            });
        }

        private void updateExpandState(boolean expanded) {
            if (expanded) {
                divider.setVisibility(View.VISIBLE);
                layoutItems.setVisibility(View.VISIBLE);
                ivExpand.setRotation(180f);
            } else {
                divider.setVisibility(View.GONE);
                layoutItems.setVisibility(View.GONE);
                ivExpand.setRotation(0f);
            }
        }
    }
}
