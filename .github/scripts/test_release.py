"""Exercise release workflow shell steps without publishing anything."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "release.yml"


def step(name):
    section = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    body = section.split("        run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:])
    if not lines:
        raise ValueError(f"empty workflow step: {name}")
    return "\n".join(lines)


class ReleaseTests(unittest.TestCase):
    def run_step(self, name, prefix="", **env):
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                ["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                 prefix + "\n" + step(name)],
                cwd=directory,
                env={**os.environ, "RUNNER_TEMP": directory,
                     "PACKAGE_NAME": "package", "TARGET_BINARY": "fortitool",
                     **env},
                capture_output=True, text=True, timeout=10,
            )

    def test_static_inspection(self):
        for mode, success in [("static", True), ("headers_fail", False),
                              ("dynamic_fail", False), ("interp", False),
                              ("needed", False)]:
            with self.subTest(mode=mode):
                result = self.run_step(
                    "Check extracted Linux binary is static",
                    prefix='''readelf() {
                      case "$MODE:$1" in
                        headers_fail:-lW|dynamic_fail:-dW) return 2 ;;
                        interp:-lW) printf '  INTERP 0x000000\n' ;;
                        needed:-dW) printf '  0x000001 (NEEDED) libc.so\n' ;;
                        *) printf 'No dynamic entries\n' ;;
                      esac
                    }''',
                    MODE=mode,
                )
                self.assertEqual(result.returncode == 0, success, result.stderr)

    def test_release_classification(self):
        for version, prerelease in [("v1.2.3", False), ("v1.2.3-rc.1", True),
                                    ("v1.2.3+build.5", False),
                                    ("v1.2.3+build-test", False)]:
            with self.subTest(version=version):
                result = self.run_step(
                    "Publish release",
                    prefix='gh() { printf "%s\\n" "$@"; }',
                    RELEASE_VERSION=version,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                args = result.stdout.splitlines()
                self.assertEqual(args[:3], ["release", "create", version])
                self.assertIn("--verify-tag", args)
                self.assertEqual("--prerelease" in args, prerelease)
                if prerelease:
                    self.assertIn("--latest=false", args)


if __name__ == "__main__":
    unittest.main()
