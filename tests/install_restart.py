"""Exercise installer transactions with a local release and service-manager fakes."""

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"
FAKE = r'''#!/bin/sh
set -eu
case "${0##*/}" in
    id) echo 501 ;;
    uname) case "$1" in -s) echo "$TEST_OS";; -m) echo arm64;; esac ;;
    sudo)
        if [ "$1" = test ]; then
            [ "$2" = "$TEST_BINARY" ] && [ "$3" = -ef ] && [ "$4" = "/proc/$(cat "$TEST_STATE")/exe" ]
        else
            exec "$@"
        fi
        ;;
    launchctl)
        case "$*" in
            'print gui/501/io.oixc.proxy')
                printf '\tprogram = %s\n\tpid = %s\n' "$TEST_BINARY" "$(cat "$TEST_STATE")"
                ;;
            'kill SIGTERM gui/501/io.oixc.proxy')
                printf '%s\n' "$*" >> "$TEST_EVENTS"
                echo 0 > "$TEST_STATE"
                ;;
            'kickstart -p gui/501/io.oixc.proxy')
                printf '%s\n' "$*" >> "$TEST_EVENTS"
                echo "$(($(wc -l < "$TEST_EVENTS") + 940000))" > "$TEST_STATE"
                ;;
            *) exit 20 ;;
        esac
        ;;
    systemctl)
        case "$*" in
            'show --property=MainPID --value oixc-proxy.service') cat "$TEST_STATE" ;;
            'show --property=KillSignal --value oixc-proxy.service') echo 15 ;;
            'restart --no-block oixc-proxy.service')
                printf '%s\n' "$*" >> "$TEST_EVENTS"
                echo "$(($(wc -l < "$TEST_EVENTS") + 940000))" > "$TEST_STATE"
                ;;
            *) exit 20 ;;
        esac
        ;;
    lsof)
        [ "$3" = -p ] && [ "$4" = "$(cat "$TEST_STATE")" ]
        printf 'n127.0.0.1:6178\nn127.0.0.1:6177\n'
        ;;
    date) cat "$TEST_CLOCK" ;;
    sleep) echo "$(($(cat "$TEST_CLOCK") + 5))" > "$TEST_CLOCK" ;;
    curl)
        case "$1" in
            -q)
                for arg do url=$arg; done
                case "$url" in
                    'http://127.0.0.1:6177/healthz') printf 204 ;;
                    'http://127.0.0.1:6177/surge-proxies.conf?all=1')
                        case "$TEST_FAIL:$("$TEST_BINARY" version)" in
                            yes:*0.11.0*) printf 503 ;;
                            *) printf 200 ;;
                        esac
                        ;;
                    *) exit 21 ;;
                esac
                ;;
            -fsSL) cp "$TEST_MIRROR/${2##*/}" "$4" ;;
            *) exit 21 ;;
        esac
        ;;
    *) exit 22 ;;
esac
'''


class InstallerRestart(unittest.TestCase):
    def run_install(self, platform, fail=False, restart=True, wrong_port=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commands = root / "commands"
            commands.mkdir()
            fake = commands / "fake"
            fake.write_text(FAKE)
            fake.chmod(0o755)
            for name in ("id", "uname", "sudo", "launchctl", "systemctl", "lsof", "date", "sleep", "curl"):
                (commands / name).symlink_to(fake)
            asset_dir = root / "release"
            asset_dir.mkdir()
            install_dir = root / "prefix with spaces"
            install_dir.mkdir()
            destination = install_dir / "oixc-proxy"
            old = '#!/bin/sh\necho "oixc-proxy 0.10.0 (commit old)"\n'
            new = '#!/bin/sh\necho "oixc-proxy 0.11.0 (commit new)"\n'
            destination.write_text(old)
            destination.chmod(0o755)
            candidate = root / "candidate"
            candidate.write_text(new)
            target = "apple-darwin" if platform == "Darwin" else "unknown-linux-musl"
            archive = asset_dir / f"oixc-proxy-aarch64-{target}.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                package.add(candidate, arcname="oixc-proxy")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            (asset_dir / "SHA256SUMS").write_text(f"{checksum}  {archive.name}\n")
            state = root / "pid"
            state.write_text("940000\n")
            events = root / "events"
            events.touch()
            clock = root / "clock"
            clock.write_text("100\n")
            args = ["sh", str(INSTALLER), "--version", "v0.11.0", "--install-dir", str(install_dir)]
            if restart:
                port = 6176 if wrong_port else 6177
                args += ["--restart", "--nodelist-url", f"http://127.0.0.1:{port}"]
                if platform == "Linux":
                    args += ["--service-target", "system/oixc-proxy.service"]
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=15,
                env={
                    **os.environ, "PATH": f"{commands}:{os.environ['PATH']}",
                    "OIXC_RELEASE_BASE_URL": "http://example.test/release",
                    "TEST_OS": platform, "TEST_MIRROR": str(asset_dir),
                    "TEST_STATE": str(state), "TEST_EVENTS": str(events),
                    "TEST_CLOCK": str(clock), "TEST_BINARY": str(destination),
                    "TEST_FAIL": "yes" if fail else "no",
                },
            )
            detail = result.stdout + result.stderr
            self.assertEqual(result.returncode, int(fail or wrong_port), detail)
            self.assertEqual(destination.read_text(), old if fail or wrong_port else new, detail)
            self.assertFalse((install_dir / ".oixc-proxy-install.lock").exists(), detail)
            if restart and not wrong_port:
                self.assertEqual((install_dir / "oixc-proxy.previous").read_text(), old)
                cycle = ["kill SIGTERM gui/501/io.oixc.proxy", "kickstart -p gui/501/io.oixc.proxy"] if platform == "Darwin" else ["restart --no-block oixc-proxy.service"]
                self.assertEqual(events.read_text().splitlines(), cycle * (2 if fail else 1), detail)
                self.assertIn("restored and verified" if fail else "Updated", detail)
            else:
                self.assertEqual(events.read_text(), "", detail)
                self.assertFalse((install_dir / "oixc-proxy.previous").exists(), detail)

    def test_launchd_and_systemd_upgrade_and_recover(self):
        for platform in ("Darwin", "Linux"):
            for fail in (False, True):
                with self.subTest(platform=platform, fail=fail):
                    self.run_install(platform, fail=fail)

    def test_binary_only_and_wrong_listener(self):
        self.run_install("Linux", restart=False)
        self.run_install("Darwin", wrong_port=True)


if __name__ == "__main__":
    unittest.main()
