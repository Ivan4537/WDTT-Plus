package com.wdtt.plus

import org.junit.Assert.assertEquals
import org.junit.Test

class MainNavigationIndicatorTest {
    @Test
    fun indicatorFollowsActiveDragBetweenTabs() {
        assertEquals(
            1.4f,
            navigationIndicatorTarget(
                selectedIndex = 1,
                dragTargetIndex = 2,
                dragProgress = 0.4f,
                itemCount = 5,
            ),
            0.0001f,
        )
    }

    @Test
    fun indicatorReturnsToSelectedTabWhenDragReentersCenter() {
        assertEquals(
            2f,
            navigationIndicatorTarget(
                selectedIndex = 2,
                dragTargetIndex = -1,
                dragProgress = 0f,
                itemCount = 5,
            ),
            0f,
        )
    }

    @Test
    fun invalidDragTargetCannotLeaveIndicatorBetweenTabs() {
        assertEquals(
            3f,
            navigationIndicatorTarget(
                selectedIndex = 3,
                dragTargetIndex = 5,
                dragProgress = 0.8f,
                itemCount = 5,
            ),
            0f,
        )
    }

    @Test
    fun releaseBeforeHalfwayKeepsNearestCurrentTab() {
        assertEquals(
            1,
            navigationDestinationIndex(
                selectedIndex = 1,
                dragTargetIndex = 2,
                dragProgress = 0.49f,
                itemCount = 5,
            ),
        )
    }

    @Test
    fun releaseAfterHalfwayOpensNearestTargetTab() {
        assertEquals(
            2,
            navigationDestinationIndex(
                selectedIndex = 1,
                dragTargetIndex = 2,
                dragProgress = 0.51f,
                itemCount = 5,
            ),
        )
    }
}
