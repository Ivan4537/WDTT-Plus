package com.wdtt.plus.vk

import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/** Pause the remaining network budget, not a new attempt; manual waiting is bounded. */
internal class VkCaptchaTimeout(private val expired: () -> Unit) {
    private val handler = Handler(Looper.getMainLooper())
    private val budget = VkCaptchaDeadline()
    private val task = Runnable { budget.cancel(); expired() }
    fun arm(milliseconds: Long) { budget.arm(milliseconds, SystemClock.elapsedRealtime()); schedule() }
    fun armIfIdle(milliseconds: Long) {
        budget.armIfIdle(milliseconds, SystemClock.elapsedRealtime())
        schedule()
    }
    fun pause(value: Boolean) { budget.pause(value, SystemClock.elapsedRealtime()); schedule() }
    private fun schedule() {
        handler.removeCallbacks(task)
        budget.delay(SystemClock.elapsedRealtime())?.let { handler.postDelayed(task, it) }
    }
    fun cancel() { budget.cancel(); handler.removeCallbacks(task) }
}

/** Pure clock model, exercised without Android or a live WebView. */
internal class VkCaptchaDeadline {
    private var due = 0L
    private var remaining: Long? = null
    private var paused = false
    private var pauseStarted = 0L
    fun arm(milliseconds: Long, now: Long) {
        remaining = milliseconds
        if (!paused) due = now + milliseconds
    }
    fun armIfIdle(milliseconds: Long, now: Long) {
        if (remaining == null) arm(milliseconds, now)
    }
    fun pause(value: Boolean, now: Long) {
        if (paused == value) return
        if (value) {
            remaining = remaining?.let { (due - now).coerceAtLeast(1) }
            pauseStarted = now
        } else remaining?.let { due = now + it }
        paused = value
    }
    fun delay(now: Long): Long? {
        remaining ?: return null
        return if (paused) (180_000 - (now - pauseStarted)).coerceAtLeast(1) else (due - now).coerceAtLeast(1)
    }
    fun cancel() { remaining = null }
}
