package org.matrix.vector.impl.core

import android.app.ActivityThread
import android.os.Build
import android.os.IBinder
import dalvik.system.DexFile
import org.matrix.vector.util.Utils
import org.matrix.vector.ipc.IFrameworkService
import org.matrix.vector.impl.di.VectorBootstrap
import org.matrix.vector.impl.hookers.*
import org.matrix.vector.impl.hooks.VectorHookBuilder

/**
 * Modern framework initialization and bootstrap sequence. Deploys interceptors into the ART runtime
 * and handles early process deoptimization.
 */
object VectorStartup {

    /**
     * Auxiliary framework interceptors, dropped one bit at a time by `debug.vector.stealth` so a
     * bisect can tell which of them a target's anti-tamper checks react to. Zero, the default,
     * keeps every framework hook exactly as before.
     *
     * 0x01 crash-dump interceptor (Thread.dispatchUncaughtException)
     * 0x02 in-memory-dex trust interceptor (DexFile.openInMemoryDexFile*)
     * 0x04 LoadedApk constructor interceptors
     * 0x08 LoadedApk.createAppFactory
     * 0x10 LoadedApk.createOrUpdateClassLoaderLocked
     * 0x20 ActivityThread.attach
     *
     * Dropping 0x04..0x20 also drops the module lifecycle itself, so those are diagnostic only:
     * they answer "would even an unloaded framework be seen", not "can a module still run".
     */
    private const val STEALTH_NO_CRASH_DUMP = 0x01
    private const val STEALTH_NO_DEX_TRUST = 0x02
    private const val STEALTH_NO_LOADED_APK_CTOR = 0x04
    private const val STEALTH_NO_CREATE_APP_FACTORY = 0x08
    private const val STEALTH_NO_CREATE_CL = 0x10
    private const val STEALTH_NO_ATTACH = 0x20

    private fun stealthMask(): Int =
        try {
            android.os.SystemProperties.getInt("debug.vector.stealth", 0)
        } catch (t: Throwable) {
            0
        }

    @JvmStatic
    fun init(
        isSystem: Boolean,
        processName: String?,
        appDir: String?,
        service: IFrameworkService?,
    ) {
        VectorServiceClient.init(service, processName ?: "android")
        VectorDeopter.deoptBootMethods()
    }

    /**
     * Registers a pre-built [LoadedApk] whose constructor ran before the hooks were installed -- the
     * LSPatch rootless target being the one case. Once tracked, [LoadedApkCreateAppFactoryHooker] and
     * [LoadedApkCreateCLHooker] dispatch its `onPackageLoaded`/`onPackageReady` (and legacy
     * `handleLoadPackage`) exactly once when its class loader is realized, with `onPackageLoaded`
     * running *before* the app's `AppComponentFactory` static initializer.
     */
    @JvmStatic
    fun trackLoadedApk(loadedApk: Any) {
        LoadedApkTracker.activeApks.add(loadedApk)
    }

    @JvmStatic
    fun bootstrap(isSystem: Boolean, systemServerStarted: Boolean) {
        val stealth = stealthMask()
        if (stealth != 0) {
            Utils.logW("stealth=0x" + Integer.toHexString(stealth) + ": auxiliary interceptors disabled")
        }

        // Crash Dump Interceptor
        if ((stealth and STEALTH_NO_CRASH_DUMP) == 0) {
            Thread::class
                .java
                .declaredMethods
                .firstOrNull { it.name == "dispatchUncaughtException" }
                ?.let { VectorHookBuilder(it).intercept(CrashDumpHooker) }
        }

        // Process-specific Interceptors
        if (isSystem) {
            val zygoteInitClass = Class.forName("com.android.internal.os.ZygoteInit")
            zygoteInitClass.declaredMethods
                .filter { it.name == "handleSystemServerProcess" }
                .forEach { VectorHookBuilder(it).intercept(HandleSystemServerProcessHooker) }
        } else if ((stealth and STEALTH_NO_DEX_TRUST) == 0) {
            DexFile::class
                .java
                .declaredMethods
                .filter {
                    it.name == "openDexFile" ||
                        it.name == "openInMemoryDexFile" ||
                        it.name == "openInMemoryDexFiles"
                }
                .forEach { VectorHookBuilder(it).intercept(DexTrustHooker) }
        }

        // Application Load Interceptors
        val loadedApkClass = Class.forName("android.app.LoadedApk")
        if ((stealth and STEALTH_NO_LOADED_APK_CTOR) == 0) {
            loadedApkClass.declaredConstructors.forEach {
                // Hook all constructors of LoadedApk to catch early instantiations securely
                VectorHookBuilder(it).intercept(LoadedApkCtorHooker)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            (stealth and STEALTH_NO_CREATE_APP_FACTORY) == 0
        ) {
            loadedApkClass.declaredMethods
                .filter { it.name == "createAppFactory" }
                .forEach { VectorHookBuilder(it).intercept(LoadedApkCreateAppFactoryHooker) }
        }

        if ((stealth and STEALTH_NO_CREATE_CL) == 0) {
            loadedApkClass.declaredMethods
                .filter { it.name == "createOrUpdateClassLoaderLocked" }
                .forEach { VectorHookBuilder(it).intercept(LoadedApkCreateCLHooker) }
        }

        // ActivityThread Attachment Interceptor
        if ((stealth and STEALTH_NO_ATTACH) == 0) {
            val activityThreadClass = Class.forName("android.app.ActivityThread")
            activityThreadClass.declaredMethods
                .filter { it.name == "attach" }
                .forEach { VectorHookBuilder(it).intercept(AppAttachHooker) }
        }

        // Late System Server Injection
        if (systemServerStarted) {
            val activityService: IBinder? = android.os.ServiceManager.getService("activity")
            if (activityService != null) {
                val classLoader = activityService.javaClass.classLoader
                if (classLoader != null) {
                    // Manually trigger the routines that the hooks normally would
                    HandleSystemServerProcessHooker.initSystemServer(classLoader, isLate = true)

                    // ActivityThread.attach ran before we were injected, so AppAttachHooker will
                    // never fire here and nothing else instantiates modules. Without this,
                    // dispatchSystemServerLoaded below would notify an empty module set.
                    val activityThread = ActivityThread.currentActivityThread()
                    if (activityThread != null) {
                        VectorBootstrap.withLegacy { it.loadModules(activityThread) }
                    } else {
                        Utils.logW(
                            "Late system server injection: no current ActivityThread, modules cannot be loaded"
                        )
                    }

                    // Say plainly what this is. onSystemServerStarting is documented as "system
                    // server is ready to start critical services", which is no longer true here -
                    // the services are already running. Modules that key off it should treat a
                    // late dispatch as best effort.
                    Utils.logW(
                        "Late system server injection: dispatching onSystemServerStarting after " +
                            "system server has already started; critical services are live"
                    )
                    StartBootstrapServicesHooker.dispatchSystemServerLoaded(classLoader)
                }
            }
        }
    }
}
