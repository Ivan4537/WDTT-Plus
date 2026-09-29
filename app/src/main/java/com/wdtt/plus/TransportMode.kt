package com.wdtt.plus

internal const val TRANSPORT_AUTO = "auto"

// All profile generations use one adaptive transport. Native negotiation keeps
// compatibility with servers that only support ordinary WireGuard forwarding.
@Suppress("UNUSED_PARAMETER")
internal fun normalizeTransportExperiment(value: String?): String = TRANSPORT_AUTO

@Suppress("UNUSED_PARAMETER")
internal fun effectiveTransportExperiment(value: String?, tunnelMode: String): String = TRANSPORT_AUTO
