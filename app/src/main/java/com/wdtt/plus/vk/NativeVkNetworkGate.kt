package com.wdtt.plus.vk

/** Callback snapshots only: onAvailable is not proof that capabilities are readable. */
internal class NativeVkNetworkGate<N>(private val requireBlockedStatus: Boolean) {
    private var current: N? = null
    private var physical = false
    private var links = false
    private var unblocked = !requireBlockedStatus

    fun available(value: N) {
        current = value; physical = false; links = false; unblocked = !requireBlockedStatus
    }
    fun capabilities(value: N, notVpn: Boolean, internet: Boolean) {
        if (current == value) physical = notVpn && internet
    }
    fun linkProperties(value: N) { if (current == value) links = true }
    fun blocked(value: N, blocked: Boolean) { if (current == value) unblocked = !blocked }
    fun lost(value: N) { if (current == value) { current = null; physical = false; links = false } }
    fun ready(value: N) = current == value && physical && links && unblocked
}
