package com.btsec.testtool.data.fuzzing

import android.content.Context
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertNotNull
import io.mockk.mockk

class BleFuzzEngineTest {

    @Test
    fun `test ble fuzz engine creation`() {
        val payloadGenerator = FuzzPayloadGenerator()
        val context = mockk<Context>(relaxed = true)
        val engine = BleFuzzEngine(payloadGenerator, context)
        assertNotNull(engine)
    }
}
