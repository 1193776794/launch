package com.xff.launch;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * Splash screen activity with anime-style image
 */
public class SplashActivity extends AppCompatActivity {

    private static final long SPLASH_DELAY = 2000; // 2 seconds

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);

        // Hide system UI for immersive experience
        hideSystemUI();

        // Start animations
        startAnimations();

        // Navigate to main activity after delay
        new Handler(Looper.getMainLooper()).postDelayed(this::navigateToMain, SPLASH_DELAY);
    }

    private void hideSystemUI() {
        View decorView = getWindow().getDecorView();
        decorView.setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                        | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                        | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_FULLSCREEN);
    }

    private void startAnimations() {
        ImageView ivSplash = findViewById(R.id.iv_splash_image);
        TextView tvAppName = findViewById(R.id.tv_app_name);
        TextView tvSlogan = findViewById(R.id.tv_slogan);

        // Fade in animation for image
        AlphaAnimation fadeIn = new AlphaAnimation(0f, 1f);
        fadeIn.setDuration(800);
        fadeIn.setFillAfter(true);

        // Delayed fade in for text
        AlphaAnimation textFadeIn = new AlphaAnimation(0f, 1f);
        textFadeIn.setDuration(600);
        textFadeIn.setStartOffset(400);
        textFadeIn.setFillAfter(true);

        ivSplash.startAnimation(fadeIn);
        tvAppName.startAnimation(textFadeIn);
        tvSlogan.startAnimation(textFadeIn);
    }

    private void navigateToMain() {
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);

        // Fade transition
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);

        finish();
    }

    @Override
    public void onBackPressed() {
        // Disable back button during splash
    }
}
