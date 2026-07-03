package com.wdtt.plus.ui

import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.lifecycle.ViewModel
import com.wdtt.plus.ServerAdminState

class ServerClientsViewModel : ViewModel() {
    val serverState = mutableStateOf<ServerAdminState?>(null)
    val clientSearch = mutableStateOf("")
    val selectedClientIndex = mutableIntStateOf(0)
    var targetKey: String = ""
}
