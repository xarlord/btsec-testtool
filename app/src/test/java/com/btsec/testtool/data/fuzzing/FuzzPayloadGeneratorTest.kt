package com.btsec.testtool.data.fuzzing

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertNotNull

class FuzzPayloadGeneratorTest {

    @Test
    fun `test fuzz payload generator creation`() {
        val generator = FuzzPayloadGenerator()
        assertNotNull(generator)
    }
}
