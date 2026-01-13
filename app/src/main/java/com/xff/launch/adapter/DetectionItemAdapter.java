package com.xff.launch.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.xff.launch.R;
import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Adapter for individual detection items
 */
public class DetectionItemAdapter extends RecyclerView.Adapter<DetectionItemAdapter.ItemViewHolder> {

    private List<DetectionItem> items = new ArrayList<>();
    private OnItemClickListener clickListener;

    public interface OnItemClickListener {
        void onItemClick(DetectionItem item);
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        this.clickListener = listener;
    }

    public void setItems(List<DetectionItem> items) {
        this.items = items;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ItemViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_detection, parent, false);
        return new ItemViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ItemViewHolder holder, int position) {
        holder.bind(items.get(position), clickListener);
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ItemViewHolder extends RecyclerView.ViewHolder {
        private final ImageView ivStatus;
        private final TextView tvName;
        private final TextView tvDetail;

        ItemViewHolder(@NonNull View itemView) {
            super(itemView);
            ivStatus = itemView.findViewById(R.id.iv_status);
            tvName = itemView.findViewById(R.id.tv_name);
            tvDetail = itemView.findViewById(R.id.tv_detail);
        }

        void bind(DetectionItem item, OnItemClickListener listener) {
            tvName.setText(item.getName());
            tvDetail.setText(item.getDetail());

            // Set status icon
            DetectionStatus status = item.getStatus();
            switch (status) {
                case SAFE:
                    ivStatus.setImageResource(R.drawable.ic_status_safe);
                    break;
                case RISK:
                    ivStatus.setImageResource(R.drawable.ic_status_risk);
                    break;
                case WARNING:
                    ivStatus.setImageResource(R.drawable.ic_status_warning);
                    break;
                default:
                    ivStatus.setImageResource(R.drawable.ic_status_unknown);
                    break;
            }

            // 设置点击事件 - 只有检测到风险或有详细信息时可点击
            if (status == DetectionStatus.RISK || status == DetectionStatus.WARNING || item.hasDetails()) {
                itemView.setOnClickListener(v -> {
                    if (listener != null) {
                        listener.onItemClick(item);
                    }
                });
                // 添加点击反馈 - 通过 TypedValue 获取 attribute 的实际 drawable
                android.util.TypedValue outValue = new android.util.TypedValue();
                itemView.getContext().getTheme().resolveAttribute(
                    android.R.attr.selectableItemBackground, outValue, true);
                itemView.setBackgroundResource(outValue.resourceId);
                itemView.setClickable(true);
            } else {
                itemView.setOnClickListener(null);
                itemView.setClickable(false);
                itemView.setBackgroundResource(0);
            }
        }
    }
}
