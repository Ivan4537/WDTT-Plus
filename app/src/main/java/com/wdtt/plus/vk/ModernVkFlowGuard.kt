package com.wdtt.plus.vk

/** Monotonic safety state shared by page callbacks and the fallback watchdog. */
internal class ModernVkFlowGuard {
    var mutationPossible = false
        private set
    var terminal = false
        private set
    private var closed = false
    private var bridgeStarted = false
    private var containerHandoffClaimed = false
    var containerHandoffPending = false
        private set

    val canFallback: Boolean get() = !mutationPossible && !closed
    val allowPageStatus: Boolean get() = !bridgeStarted && acceptsPageCallbacks
    val acceptsPageCallbacks: Boolean get() = !containerHandoffPending && !terminal && !closed

    /** Reserve the mobile-to-container transition before returning to WebView. */
    fun beginContainerHandoff(): Boolean {
        if (!allowPageStatus || containerHandoffClaimed) return false
        containerHandoffClaimed = true
        containerHandoffPending = true
        return true
    }

    fun completeContainerHandoff(): Boolean {
        if (!containerHandoffPending) return false
        containerHandoffPending = false
        return !closed && !terminal && !mutationPossible
    }

    fun accept(stage: String): Boolean {
        if (!acceptsPageCallbacks) return false
        if (mutationPossible && (stage.startsWith("AUTH_") || stage.startsWith("CLAIM_") ||
            stage in setOf("INIT_WAIT", "SESSION_WAIT", "PROFILE_WAIT", "AUTO_READY"))) return false
        bridgeStarted = true
        if (stage.startsWith("PERMIT_WAIT_") || stage.startsWith("CALL_PERMIT_") || stage.startsWith("CALL_SENT_") || stage == "CLAIM_BLOCKED") {
            mutationPossible = true
        }
        terminal = stage == "PREP_FAILED" || stage == "FLOW_FAILED" || stage == "CLAIM_BLOCKED" ||
            listOf("CALL_TIMEOUT_", "CALL_FAILED_", "CALL_INVALID_", "CALL_EMPTY_").any(stage::startsWith)
        return true
    }

    fun close() { closed = true }
}
