package app.rahyab.vpn

/**
 * JNI bridge to the Rust core (librahyab.so, built by cargo-ndk in CI).
 *
 * Two independent pieces:
 *  - startEngine: Khorshid supervisor + local SOCKS hub (returns hub port)
 *  - startTunnel: tun2proxy wired to the VpnService tun fd, pointed at the hub
 */
object RustCore {
    init {
        System.loadLibrary("rahyab")
    }

    /** Starts the Khorshid engine + local hub. Returns hub port, or negative error. */
    external fun startEngine(configJson: String): Int

    external fun stopEngine()

    /** Live status: {"phase","environment","active","hub_addr","attempts","last_error"} */
    external fun statusJson(): String

    /** Hands the tun fd to tun2proxy → local hub. Returns 0 on success. */
    external fun startTunnel(fd: Int, mtu: Int, hubPort: Int): Int

    external fun stopTunnel()
}
