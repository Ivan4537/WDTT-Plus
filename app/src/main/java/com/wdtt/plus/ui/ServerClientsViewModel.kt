package com.wdtt.plus.ui

import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.lifecycle.ViewModel
import com.wdtt.plus.ServerAdminState
import java.util.concurrent.ConcurrentHashMap

data class ServerClientsProcessSnapshot(
    val state: ServerAdminState?,
    val lastRefreshAt: Long,
    val lastRefreshAttemptAt: Long,
    val lastRefreshError: String,
    val attempted: Boolean
)

object ServerClientsProcessCache {
    private val values = ConcurrentHashMap<String, ServerClientsProcessSnapshot>()

    fun get(targetKey: String): ServerClientsProcessSnapshot? = values[targetKey]

    fun put(targetKey: String, snapshot: ServerClientsProcessSnapshot) {
        values[targetKey] = snapshot
    }
}

class ServerClientsViewModel : ViewModel() {
    val serverState = mutableStateOf<ServerAdminState?>(null)
    val clientSearch = mutableStateOf("")
    val selectedClientIndex = mutableIntStateOf(0)
    val lastRefreshAt = mutableLongStateOf(0L)
    val lastRefreshAttemptAt = mutableLongStateOf(0L)
    val lastRefreshError = mutableStateOf("")
    val automaticRefreshAttempted = mutableStateOf(false)
    var targetKey: String = ""
}
