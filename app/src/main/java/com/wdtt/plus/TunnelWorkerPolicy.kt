package com.wdtt.plus

internal const val TUNNEL_WORKERS_PER_GROUP = 9
internal const val APP_MAX_WORKERS = 108

internal fun normalizeTunnelWorkerCount(requested: Int, profileMaxWorkers: Int = 0): Int {
    val configuredMaximum = (profileMaxWorkers / TUNNEL_WORKERS_PER_GROUP) * TUNNEL_WORKERS_PER_GROUP
    val maximum = configuredMaximum.takeIf { it >= TUNNEL_WORKERS_PER_GROUP }
        ?.coerceAtMost(APP_MAX_WORKERS)
        ?: APP_MAX_WORKERS
    val rounded = ((requested.coerceAtLeast(TUNNEL_WORKERS_PER_GROUP) + TUNNEL_WORKERS_PER_GROUP / 2) /
        TUNNEL_WORKERS_PER_GROUP) * TUNNEL_WORKERS_PER_GROUP
    return rounded.coerceIn(TUNNEL_WORKERS_PER_GROUP, maximum)
}

internal fun reconcileTunnelWorkerCountForProfileLimit(
    selectedWorkers: Int,
    previousProfileMaxWorkers: Int?,
    currentProfileMaxWorkers: Int,
    remoteManaged: Boolean,
): Int {
    val normalizedCurrent = normalizeTunnelWorkerCount(
        selectedWorkers,
        currentProfileMaxWorkers,
    )
    if (!remoteManaged || currentProfileMaxWorkers !in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS) {
        return normalizedCurrent
    }
    if (currentProfileMaxWorkers % TUNNEL_WORKERS_PER_GROUP != 0) return normalizedCurrent

    val previousLimit = previousProfileMaxWorkers?.takeIf {
        it in TUNNEL_WORKERS_PER_GROUP..APP_MAX_WORKERS &&
            it % TUNNEL_WORKERS_PER_GROUP == 0
    }
    if (previousLimit == null) return currentProfileMaxWorkers

    val selectedAtPreviousCeiling = normalizeTunnelWorkerCount(
        selectedWorkers,
        previousLimit,
    ) == previousLimit
    return if (currentProfileMaxWorkers > previousLimit && selectedAtPreviousCeiling) {
        currentProfileMaxWorkers
    } else {
        normalizedCurrent
    }
}
