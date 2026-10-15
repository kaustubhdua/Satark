import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkflowActionPinningTests(unittest.TestCase):
    def test_every_external_action_uses_an_immutable_commit_sha(self):
        workflows = sorted((*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml")))
        self.assertTrue(workflows, f"no workflow files found under {WORKFLOW_DIR}")

        found = 0
        for workflow in workflows:
            source = workflow.read_text(encoding="utf-8")
            for action in USES_PATTERN.findall(source):
                if action.startswith(("./", "docker://")):
                    continue
                found += 1
                self.assertIn("@", action, f"{workflow.relative_to(REPO_ROOT)} uses mutable ref {action!r}")
                _, ref = action.rsplit("@", 1)
                self.assertRegex(
                    ref,
                    IMMUTABLE_SHA,
                    f"{workflow.relative_to(REPO_ROOT)} action {action!r} must pin a full 40-character commit SHA",
                )

        self.assertGreater(found, 0, "no external GitHub Actions references were checked")


if __name__ == "__main__":
    unittest.main()
