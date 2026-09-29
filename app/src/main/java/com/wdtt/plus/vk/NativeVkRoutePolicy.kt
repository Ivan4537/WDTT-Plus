package com.wdtt.plus.vk

internal object NativeVkRoutePolicy {
    fun mayFallback(usingDefault: Boolean, attemptCount: Int) = !usingDefault && attemptCount == 0
    fun needsLogin(savedRoute: String, selectedRoute: String) =
        if (savedRoute.isEmpty()) selectedRoute.endsWith(":default") else savedRoute != selectedRoute
}
