import CFNetwork
import Darwin
import Foundation
import LocalAuthentication
import PSGCompanion
import UIKit

/// Reads the few things iOS lets an app see about the phone (FR-IOS-02).
/// Everything else in `DevicePosture` comes from the owner's answers.
enum DevicePostureReader {
    static func read(into posture: inout DevicePosture) {
        posture.osVersion = UIDevice.current.systemVersion
        posture.passcodeSet = passcodeSet()
        posture.httpProxySet = httpProxySet()
        posture.jailbreakSigns = jailbreakSigns()
        posture.debuggerAttached = debuggerAttached()
    }

    /// `deviceOwnerAuthentication` can be evaluated only when a passcode is
    /// set; the error code tells "no passcode" apart from other reasons.
    static func passcodeSet() -> Bool? {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return true }
        if let e = error, e.code == LAError.passcodeNotSet.rawValue { return false }
        return nil
    }

    /// The system proxy settings, which a configuration profile or the Wi-Fi
    /// settings can set.
    static func httpProxySet() -> Bool? {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return nil }
        let http = (settings["HTTPEnable"] as? Int ?? 0) == 1 && !((settings["HTTPProxy"] as? String) ?? "").isEmpty
        let pac = (settings["ProxyAutoConfigEnable"] as? Int ?? 0) == 1
        return http || pac
    }

    /// Traces a jailbreak leaves that a sandboxed app can see. None of these
    /// is proof alone, which is why the owner is asked whether they did it.
    static func jailbreakSigns() -> [String] {
        #if targetEnvironment(simulator)
        return []
        #else
        var signs = [String]()
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app", "/Applications/Filza.app",
                     "/var/jb", "/private/var/jb", "/private/var/lib/apt", "/usr/sbin/sshd", "/bin/bash", "/etc/apt",
                     "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/libsubstitute.dylib", "/usr/lib/TweakInject"]
        for p in paths where FileManager.default.fileExists(atPath: p) { signs.append(p) }
        for scheme in ["cydia", "sileo", "zbra", "filza", "undecimus"] {
            if let url = URL(string: "\(scheme)://"), UIApplication.shared.canOpenURL(url) { signs.append("\(scheme):// app") }
        }
        // A normal app cannot write outside its sandbox.
        let probe = "/private/psg-sandbox-probe.txt"
        if (try? "x".write(toFile: probe, atomically: false, encoding: .utf8)) != nil {
            signs.append("sandbox is open")
            try? FileManager.default.removeItem(atPath: probe)
        }
        return signs
        #endif
    }

    /// NFR-SEC-03: report a debugger attached to the app.
    static func debuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0 else { return false }
        #if DEBUG
        return false // Xcode attaches one on every debug run.
        #else
        return (info.kp_proc.p_flag & P_TRACED) != 0
        #endif
    }
}
