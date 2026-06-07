/*
 * Bluetooth Security Testing Tool
 * Copyright (c) 2026 Security Research Team
 *
 * Licensed under MIT with additional restrictions:
 * - This application may ONLY be used for authorized security testing
 * - See LICENSE for full terms
 */
package com.btsec.testtool.data.bluetooth

import timber.log.Timber
import java.lang.reflect.Method
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Safely wraps reflection calls needed for Android BLE hidden APIs.
 *
 * Android's Bluetooth stack has several hidden methods (e.g. `removeBond()`,
 * `BluetoothGatt.refresh()`) that are only accessible via reflection.
 * This utility validates every call against a strict whitelist, performs
 * thorough null-safety checks, and logs warnings so that any misuse is
 * visible in crash reports and logcat.
 */
@Singleton
class ReflectionHelper @Inject constructor() {

    /**
     * Method names that are allowed to be invoked via reflection.
     * Adding a new entry requires a security review — see Issue #127.
     */
    private val allowedMethods = setOf(
        "removeBond",
        "refresh"
    )

    /**
     * Invoke a hidden method on [target] by [methodName] with the given [args].
     *
     * @param target      The object whose method will be invoked.
     * @param clazz       The declaring class to look up the method on.
     * @param methodName  The name of the hidden method (must be in [allowedMethods]).
     * @param paramTypes  Parameter types of the method.
     * @param args        Arguments to pass to the method.
     * @return Result.success(value) on success, Result.failure on any error or validation failure.
     */
    fun invokeHiddenMethod(
        target: Any,
        clazz: Class<*>,
        methodName: String,
        paramTypes: Array<Class<*>> = emptyArray(),
        args: Array<Any?> = emptyArray()
    ): Result<Any?> {
        // Validate method name against whitelist
        if (methodName !in allowedMethods) {
            Timber.w("Reflection blocked: method '%s' is not in the allowed whitelist", methodName)
            return Result.failure(SecurityException("Reflection call to '$methodName' is not permitted"))
        }

        Timber.w("Reflection usage: invoking '%s' on %s", methodName, clazz.simpleName)

        return try {
            val method: Method? = clazz.getDeclaredMethod(methodName, *paramTypes)

            if (method == null) {
                Timber.e("Reflection failed: getDeclaredMethod('%s') returned null on %s", methodName, clazz.simpleName)
                return Result.failure(NoSuchMethodException("Method '$methodName' not found on ${clazz.simpleName}"))
            }

            method.isAccessible = true

            val result = method.invoke(target, *args)
            Result.success(result)
        } catch (e: NoSuchMethodException) {
            Timber.e(e, "Reflection error: method '%s' not found on %s", methodName, clazz.simpleName)
            Result.failure(e)
        } catch (e: SecurityException) {
            Timber.e(e, "Reflection error: security exception invoking '%s' on %s", methodName, clazz.simpleName)
            Result.failure(e)
        } catch (e: IllegalAccessException) {
            Timber.e(e, "Reflection error: illegal access invoking '%s' on %s", methodName, clazz.simpleName)
            Result.failure(e)
        } catch (e: IllegalArgumentException) {
            Timber.e(e, "Reflection error: illegal argument invoking '%s' on %s", methodName, clazz.simpleName)
            Result.failure(e)
        } catch (e: Exception) {
            Timber.e(e, "Reflection error: unexpected exception invoking '%s' on %s", methodName, clazz.simpleName)
            Result.failure(e)
        }
    }
}
