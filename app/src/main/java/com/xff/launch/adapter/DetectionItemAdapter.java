package com.xff.launch.adapter;

import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.xff.launch.R;
import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Adapter for individual detection items - M3 style with status dots
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
        private final View ivStatus;
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

            // Set status dot color
            DetectionStatus status = item.getStatus();
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
            ivStatus.setBackgroundTintList(ColorStateList.valueOf(dotColor));

            // Click events
            if (status == DetectionStatus.RISK || status == DetectionStatus.WARNING || item.hasDetails()) {
                itemView.setOnClickListener(v -> {
                    if (listener != null) {
                        listener.onItemClick(item);
                    }
                });
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
