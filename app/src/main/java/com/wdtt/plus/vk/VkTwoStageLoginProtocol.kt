package com.wdtt.plus.vk

/**
 * Validates the modern VK ID callback before advancing to the Mini App OAuth
 * context whose token is compatible with VK Calls. No credential from the
 * first stage is retained or exchanged.
 */
internal object VkTwoStageLoginProtocol {
    fun continueWithMiniApp(
        rawCallback: String,
        vkIdAttempt: VkApiProtocol.AuthAttempt,
    ): VkOAuthProtocol.AuthAttempt {
        VkApiProtocol.callback(rawCallback, vkIdAttempt.state)
        return VkOAuthProtocol.newAttempt()
    }
}
