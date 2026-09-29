package com.wdtt.plus

import android.content.Context
import java.net.HttpURLConnection
import java.net.URL

/**
 * Opens a neutral HTTPS request through Android's default network for this UID.
 *
 * Deliberately do not bind service traffic to a physical `NOT_VPN` network:
 * Android's default may be an external VPN that is required to reach the
 * service. Temporary direct routing for an external continuation is handled
 * separately and only for the exact backend-provided destinations.
 */
internal fun openDefaultHttpConnection(
    @Suppress("UNUSED_PARAMETER") context: Context?,
    url: String,
): HttpURLConnection = URL(url).openConnection() as HttpURLConnection
