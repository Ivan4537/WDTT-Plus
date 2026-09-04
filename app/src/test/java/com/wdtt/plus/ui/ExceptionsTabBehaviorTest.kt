package com.wdtt.plus.ui

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExceptionsTabBehaviorTest {
    @Test
    fun `header stays collapsed while app list can still scroll to its first item`() {
        assertEquals(
            -240f,
            collapsingHeaderOffsetAfterScroll(
                currentOffsetPx = -240f,
                headerHeightPx = 240f,
                deltaPx = 80f,
                allowExpand = false,
            ),
        )
    }

    @Test
    fun `header expands after app list reaches its first item`() {
        assertEquals(
            -160f,
            collapsingHeaderOffsetAfterScroll(
                currentOffsetPx = -240f,
                headerHeightPx = 240f,
                deltaPx = 80f,
                allowExpand = true,
            ),
        )
    }

    @Test
    fun `header gesture clamps expansion and collapse to measured height`() {
        assertEquals(
            0f,
            collapsingHeaderOffsetAfterScroll(-40f, 240f, 100f, allowExpand = true),
        )
        assertEquals(
            -240f,
            collapsingHeaderOffsetAfterScroll(-200f, 240f, -100f, allowExpand = true),
        )
    }

    @Test
    fun `quick exclusions recognize current whitelist app packages`() {
        val packages = listOf(
            "ru.oneme.app",
            "ru.gosuslugi.goskey",
            "com.octopod.russianpost.client.android",
            "ru.nspk.mirpay",
            "ru.nspk.sbpay",
            "com.vkontakte.android",
            "com.vk.calls",
            "logo.com.mbanking",
            "ru.rzd.pass",
            "ru.tutu.tutu_emp",
            "ru.vkusvill",
            "com.icemobile.lenta.prod",
            "ru.reksoft.okey",
            "ru.myauchan.droid",
            "www.metro.com",
            "ru.tander.magnit",
            "ru.pyaterochka.app.browser",
            "ru.perekrestok.app",
            "club.chizhik",
            "com.logistic.sdek",
            "ru.dodopizza.app",
            "ru.burgerking",
            "com.apegroup.mcdonaldsrussia",
            "com.carshering",
            "youdrive.today",
            "ru.ivi.client",
            "ru.more.play",
            "ru.zen.android",
            "gpm.tnt_premier",
            "ru.mts.mtstv",
            "ru.radioplayer",
        )

        packages.forEach { packageName ->
            assertTrue(
                "Expected $packageName to be a quick exclusion",
                matchesQuickExclusionApp(name = "Неизвестное название", packageName = packageName),
            )
        }
    }

    @Test
    fun `quick exclusions match store label aliases without selecting unrelated apps`() {
        assertTrue(matchesQuickExclusionApp("МАКС: общение, звонки, сервисы", "store.variant"))
        assertTrue(matchesQuickExclusionApp("Вкусно — и точка", "store.variant"))
        assertTrue(matchesQuickExclusionApp("Сателлит Online", "store.variant"))
        assertFalse(matchesQuickExclusionApp("Калькулятор", "com.example.calculator"))
    }

    @Test
    fun `known user apps stay visible when firmware marks them as system apps`() {
        assertFalse(isVpnRoutingSystemApp("com.vkontakte.android", ApplicationInfo.FLAG_SYSTEM))
        assertFalse(isVpnRoutingSystemApp("com.vk.calls", ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))
        assertTrue(isVpnRoutingSystemApp("com.android.settings", ApplicationInfo.FLAG_SYSTEM))
    }

    @Test
    fun `selected system apps stay visible when the switch is off`() {
        val visible = visibleAppsWithSystemSelected(
            listOf(
                AppItem(
                    name = "VK",
                    packageName = "com.vkontakte.android",
                    icon = null,
                    isSystem = false,
                ),
                AppItem(
                    name = "Android Settings",
                    packageName = "com.android.settings",
                    icon = null,
                    isSystem = true,
                ),
            ),
            selectedPackages = setOf("com.android.settings"),
        )

        assertEquals(
            listOf("com.vkontakte.android", "com.android.settings"),
            visible.map(AppItem::packageName),
        )
    }

    @Test
    fun `selected apps are sorted first and each group stays alphabetical`() {
        val sorted = sortAppsForRoutingList(
            listOf(
                AppItem(name = "Яндекс", packageName = "ru.yandex.searchplugin", icon = null, isSystem = false),
                AppItem(name = "Банк", packageName = "ru.bank", icon = null, isSystem = false),
                AppItem(name = "Авито", packageName = "com.avito.android", icon = null, isSystem = false),
                AppItem(name = "Настройки", packageName = "com.android.settings", icon = null, isSystem = true),
            ),
            selectedPackages = setOf("ru.yandex.searchplugin", "com.android.settings"),
        )

        assertEquals(
            listOf(
                "com.android.settings",
                "ru.yandex.searchplugin",
                "com.avito.android",
                "ru.bank",
            ),
            sorted.map(AppItem::packageName),
        )
    }
}
