/*
 * Based on WireGuard Android GoBackend (Copyright 2017-2025 WireGuard LLC).
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wdtt.plus;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import com.wireguard.android.backend.Backend;
import com.wireguard.android.backend.BackendException;
import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.android.util.SharedLibraryLoader;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * WireGuard Go backend with non-intrusive automatic restore semantics.
 *
 * <p>It is derived from the exact GoBackend bundled by tunnel 1.0.20260102.
 * The only intentional behavioural differences are that an UP never invokes
 * {@link android.net.VpnService#prepare(Context)} and that {@link VpnService}
 * reports {@link VpnService#onRevoke()} to the owner. Android's establish()
 * atomically returns {@code null} when this app is no longer prepared, so an
 * automatic resume cannot take the VPN slot from another application.</p>
 */
public final class SafeGoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WDTT/SafeGoBackend";
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();

    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;
    @Nullable private Runnable revocationListener;

    public SafeGoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        this.context = context.getApplicationContext();
    }

    public void setRevocationListener(@Nullable final Runnable listener) {
        revocationListener = listener;
    }

    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel == null) return Collections.emptySet();
        final Set<String> tunnels = new ArraySet<>();
        tunnels.add(currentTunnel.getName());
        return tunnels;
    }

    @Override
    public Tunnel.State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? Tunnel.State.UP : Tunnel.State.DOWN;
    }

    @Override
    public Statistics getStatistics(final Tunnel tunnel) throws Exception {
        final Statistics stats = StatisticsBridge.create();
        if (tunnel != currentTunnel || currentTunnelHandle == -1) return stats;
        final String config = NativeBridge.getConfig(currentTunnelHandle);
        if (config == null) return stats;

        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMs = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null) StatisticsBridge.add(stats, key, rx, tx, latestHandshakeMs);
                key = null;
                rx = 0;
                tx = 0;
                latestHandshakeMs = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    // Keep parsing: a malformed peer must not hide other peers.
                }
            } else if (key != null && line.startsWith("rx_bytes=")) {
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (key != null && line.startsWith("tx_bytes=")) {
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (key != null && line.startsWith("last_handshake_time_sec=")) {
                try {
                    latestHandshakeMs += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMs = 0;
                }
            } else if (key != null && line.startsWith("last_handshake_time_nsec=")) {
                try {
                    latestHandshakeMs += Long.parseLong(line.substring(25)) / 1_000_000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMs = 0;
                }
            }
        }
        if (key != null) StatisticsBridge.add(stats, key, rx, tx, latestHandshakeMs);
        return stats;
    }

    @Override
    public String getVersion() throws Exception {
        return NativeBridge.version();
    }

    @Override
    public boolean isAlwaysOn() throws ExecutionException, InterruptedException, TimeoutException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false;
        return vpnService.get(0, TimeUnit.NANOSECONDS).isAlwaysOn();
    }

    @Override
    public boolean isLockdownEnabled() throws ExecutionException, InterruptedException, TimeoutException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false;
        return vpnService.get(0, TimeUnit.NANOSECONDS).isLockdownEnabled();
    }

    @Override
    public synchronized Tunnel.State setState(
            final Tunnel tunnel,
            Tunnel.State state,
            @Nullable final Config config
    ) throws Exception {
        final Tunnel.State originalState = getState(tunnel);
        if (state == Tunnel.State.TOGGLE) {
            state = originalState == Tunnel.State.UP ? Tunnel.State.DOWN : Tunnel.State.UP;
        }
        if (state == originalState && tunnel == currentTunnel && config == currentConfig) {
            return originalState;
        }

        if (state == Tunnel.State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            if (currentTunnel != null) setStateInternal(currentTunnel, null, Tunnel.State.DOWN);
            try {
                setStateInternal(tunnel, config, Tunnel.State.UP);
            } catch (final Exception error) {
                if (originalTunnel != null) {
                    try {
                        setStateInternal(originalTunnel, originalConfig, Tunnel.State.UP);
                    } catch (final Exception restoreError) {
                        error.addSuppressed(restoreError);
                    }
                }
                throw error;
            }
        } else if (state == Tunnel.State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, Tunnel.State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(
            final Tunnel tunnel,
            @Nullable final Config config,
            final Tunnel.State state
    ) throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);
        if (state == Tunnel.State.UP) {
            if (config == null) throw new BackendException(BackendException.Reason.TUNNEL_MISSING_CONFIG);

            final VpnService service = requireVpnService();
            service.setOwner(this);
            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }

            resolveEndpoints(config);
            final String goConfig = config.toWgUserspaceString();
            final android.net.VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());
            for (final String app : config.getInterface().getExcludedApplications()) {
                builder.addDisallowedApplication(app);
            }
            for (final String app : config.getInterface().getIncludedApplications()) {
                builder.addAllowedApplication(app);
            }
            for (final InetNetwork address : config.getInterface().getAddresses()) {
                builder.addAddress(address.getAddress(), address.getMask());
            }
            for (final InetAddress dnsServer : config.getInterface().getDnsServers()) {
                builder.addDnsServer(dnsServer.getHostAddress());
            }
            for (final String domain : config.getInterface().getDnsSearchDomains()) {
                builder.addSearchDomain(domain);
            }
            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork allowedIp : peer.getAllowedIps()) {
                    if (allowedIp.getMask() == 0) sawDefaultRoute = true;
                    builder.addRoute(allowedIp.getAddress(), allowedIp.getMask());
                }
            }
            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }
            builder.setMtu(config.getInterface().getMtu().orElse(1280));
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false);
            service.setUnderlyingNetworks(null);
            builder.setBlocking(true);

            try (ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null) {
                    service.stopSelf();
                    throw new VpnSlotUnavailableException();
                }
                currentTunnelHandle = NativeBridge.turnOn(tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0) {
                throw new BackendException(
                        BackendException.Reason.GO_ACTIVATION_ERROR_CODE,
                        currentTunnelHandle
                );
            }
            currentTunnel = tunnel;
            currentConfig = config;
            service.protect(NativeBridge.getSocketV4(currentTunnelHandle));
            service.protect(NativeBridge.getSocketV6(currentTunnelHandle));
        } else {
            if (currentTunnelHandle == -1) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            final int handleToClose = currentTunnelHandle;
            currentTunnel = null;
            currentTunnelHandle = -1;
            currentConfig = null;
            NativeBridge.turnOff(handleToClose);
            try {
                vpnService.get(0, TimeUnit.NANOSECONDS).stopSelf();
            } catch (final TimeoutException ignored) {
                // Service may already be stopping after an external revoke.
            }
        }
        tunnel.onStateChange(state);
    }

    private VpnService requireVpnService() throws BackendException {
        if (!vpnService.isDone()) {
            Log.d(TAG, "Requesting to start VpnService");
            context.startService(new Intent(context, VpnService.class));
        }
        try {
            return vpnService.get(2, TimeUnit.SECONDS);
        } catch (final TimeoutException error) {
            final BackendException result = new BackendException(
                    BackendException.Reason.UNABLE_TO_START_VPN
            );
            result.initCause(error);
            throw result;
        } catch (final InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new BackendException(BackendException.Reason.UNABLE_TO_START_VPN);
        } catch (final ExecutionException error) {
            final BackendException result = new BackendException(
                    BackendException.Reason.UNABLE_TO_START_VPN
            );
            result.initCause(error);
            throw result;
        }
    }

    private static void resolveEndpoints(final Config config) throws Exception {
        dnsRetry:
        for (int attempt = 0; attempt < DNS_RESOLUTION_RETRIES; ++attempt) {
            for (final Peer peer : config.getPeers()) {
                final InetEndpoint endpoint = peer.getEndpoint().orElse(null);
                if (endpoint == null || endpoint.getResolved().orElse(null) != null) continue;
                if (attempt == DNS_RESOLUTION_RETRIES - 1) {
                    throw new BackendException(
                            BackendException.Reason.DNS_RESOLUTION_FAILURE,
                            endpoint.getHost()
                    );
                }
                Log.w(TAG, "DNS host \"" + endpoint.getHost() + "\" failed to resolve; trying again");
                Thread.sleep(1000);
                continue dnsRetry;
            }
            return;
        }
    }

    private synchronized void handleServiceDestroyed() {
        final Tunnel tunnel = currentTunnel;
        if (tunnel == null) return;
        final int handleToClose = currentTunnelHandle;
        currentTunnel = null;
        currentTunnelHandle = -1;
        currentConfig = null;
        if (handleToClose != -1) {
            try {
                NativeBridge.turnOff(handleToClose);
            } catch (final Exception error) {
                Log.w(TAG, "Unable to stop wg-go after VpnService destruction", error);
            }
        }
        tunnel.onStateChange(Tunnel.State.DOWN);
    }

    private void notifySystemRevoked() {
        final Runnable listener = revocationListener;
        if (listener != null && currentTunnel != null) listener.run();
    }

    private static synchronized void resetVpnServiceFuture() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            vpnService = vpnService.newIncompleteFuture();
        } else {
            vpnService = new CompletableFuture<>();
        }
    }

    /** Raised when Android atomically refuses an automatic establish attempt. */
    public static final class VpnSlotUnavailableException extends Exception {
        public VpnSlotUnavailableException() {
            super("Android VPN slot is not available to WDTT Plus");
        }
    }

    /** Android service paired with this backend. */
    public static class VpnService extends android.net.VpnService {
        @Nullable private SafeGoBackend owner;

        public android.net.VpnService.Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            super.onCreate();
        }

        @Override
        public void onRevoke() {
            final SafeGoBackend currentOwner = owner;
            if (currentOwner != null) currentOwner.notifySystemRevoked();
            super.onRevoke();
        }

        @Override
        public void onDestroy() {
            final SafeGoBackend currentOwner = owner;
            if (currentOwner != null) currentOwner.handleServiceDestroyed();
            resetVpnServiceFuture();
            super.onDestroy();
        }

        public void setOwner(final SafeGoBackend owner) {
            this.owner = owner;
        }
    }

    /**
     * The dependency's JNI exports are named for GoBackend. Keeping this small
     * bridge lets this class reuse the exact audited native library instead of
     * shipping a second wg-go binary.
     */
    private static final class NativeBridge {
        private static final Method GET_CONFIG = method("wgGetConfig", int.class);
        private static final Method GET_SOCKET_V4 = method("wgGetSocketV4", int.class);
        private static final Method GET_SOCKET_V6 = method("wgGetSocketV6", int.class);
        private static final Method TURN_OFF = method("wgTurnOff", int.class);
        private static final Method TURN_ON = method("wgTurnOn", String.class, int.class, String.class);
        private static final Method VERSION = method("wgVersion");

        private static Method method(final String name, final Class<?>... parameters) {
            try {
                final Method method = GoBackend.class.getDeclaredMethod(name, parameters);
                method.setAccessible(true);
                return method;
            } catch (final ReflectiveOperationException error) {
                throw new IllegalStateException("WireGuard native bridge is incompatible", error);
            }
        }

        @Nullable static String getConfig(final int handle) throws Exception {
            return (String) invoke(GET_CONFIG, handle);
        }

        static int getSocketV4(final int handle) throws Exception {
            return (Integer) invoke(GET_SOCKET_V4, handle);
        }

        static int getSocketV6(final int handle) throws Exception {
            return (Integer) invoke(GET_SOCKET_V6, handle);
        }

        static void turnOff(final int handle) throws Exception {
            invoke(TURN_OFF, handle);
        }

        static int turnOn(final String name, final int fd, final String settings) throws Exception {
            return (Integer) invoke(TURN_ON, name, fd, settings);
        }

        static String version() throws Exception {
            return (String) invoke(VERSION);
        }

        private static Object invoke(final Method method, final Object... arguments) throws Exception {
            try {
                return method.invoke(null, arguments);
            } catch (final IllegalAccessException error) {
                throw new IllegalStateException("WireGuard native bridge is inaccessible", error);
            } catch (final InvocationTargetException error) {
                final Throwable cause = error.getCause();
                if (cause instanceof Exception) throw (Exception) cause;
                if (cause instanceof Error) throw (Error) cause;
                throw new IllegalStateException("WireGuard native bridge failed", cause);
            }
        }
    }

    /** Statistics has package-private construction in the pinned tunnel library. */
    private static final class StatisticsBridge {
        private static final Constructor<Statistics> CONSTRUCTOR = constructor();
        private static final Method ADD = addMethod();

        private static Constructor<Statistics> constructor() {
            try {
                final Constructor<Statistics> constructor = Statistics.class.getDeclaredConstructor();
                constructor.setAccessible(true);
                return constructor;
            } catch (final ReflectiveOperationException error) {
                throw new IllegalStateException("WireGuard statistics bridge is incompatible", error);
            }
        }

        private static Method addMethod() {
            try {
                final Method method = Statistics.class.getDeclaredMethod(
                        "add", Key.class, long.class, long.class, long.class
                );
                method.setAccessible(true);
                return method;
            } catch (final ReflectiveOperationException error) {
                throw new IllegalStateException("WireGuard statistics bridge is incompatible", error);
            }
        }

        static Statistics create() throws Exception {
            try {
                return CONSTRUCTOR.newInstance();
            } catch (final InstantiationException | IllegalAccessException error) {
                throw new IllegalStateException("WireGuard statistics bridge is inaccessible", error);
            } catch (final InvocationTargetException error) {
                throw new IllegalStateException("WireGuard statistics bridge failed", error.getCause());
            }
        }

        static void add(
                final Statistics statistics,
                final Key key,
                final long rx,
                final long tx,
                final long handshake
        ) throws Exception {
            try {
                ADD.invoke(statistics, key, rx, tx, handshake);
            } catch (final IllegalAccessException error) {
                throw new IllegalStateException("WireGuard statistics bridge is inaccessible", error);
            } catch (final InvocationTargetException error) {
                final Throwable cause = error.getCause();
                if (cause instanceof Exception) throw (Exception) cause;
                if (cause instanceof Error) throw (Error) cause;
                throw new IllegalStateException("WireGuard statistics bridge failed", cause);
            }
        }
    }
}
