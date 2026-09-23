import unittest
from rag import RagPipeline
from claude import ClaudeClient

class TestAiAdvisorService(unittest.TestCase):
    def test_rag_pipeline_construction(self):
        pipeline = RagPipeline()
        prompts = pipeline.build_structured_prompt("How do we patch PAN-OS command injection?", "ten_test_startup")

        self.assertIn("system", prompts)
        self.assertIn("context", prompts)
        self.assertIn("query", prompts)
        self.assertIn("CVE-2024-3400", prompts["context"])
        self.assertIn("INC-0891", prompts["context"])

    def test_claude_haiku_summary(self):
        client = ClaudeClient()
        alert = {
            "alert_id": "alt_1234",
            "rule_name": "Suspicious PowerShell Encoded Execution",
            "asset_id": "ws-dev-01",
            "severity": "high",
        }
        res = client.generate_haiku_summary(alert)
        self.assertIn("summary", res)
        self.assertIn("slack_payload", res)
        self.assertTrue(len(res["summary"]) > 10)

    def test_claude_sonnet_structured_advisory(self):
        client = ClaudeClient()
        prompts = {
            "system": "You are ShieldDesk Advisor",
            "context": "Relevant CVE-2024-3400",
            "query": "What are the immediate containment steps for this breach?",
        }
        advisory = client.generate_sonnet_advisory(prompts)

        self.assertIn("severity", advisory)
        self.assertIn("summary", advisory)
        self.assertIn("root_cause", advisory)
        self.assertIn("fix_steps", advisory)
        self.assertIn("estimated_fix_time", advisory)
        self.assertIn("risk_if_ignored", advisory)

        # Validate structured fix_steps array
        steps = advisory["fix_steps"]
        self.assertGreaterEqual(len(steps), 1)
        self.assertIn("command", steps[0])
        self.assertIn("explanation", steps[0])

    def test_blast_radius_simulation(self):
        client = ClaudeClient()
        sim = client.simulate_blast_radius("CVE-2024-3400", "gw-vpn-01")
        self.assertEqual(sim["target_cve"], "CVE-2024-3400")
        self.assertIn("simulated_blast_radius", sim)
        self.assertIn("posture_downgrade", sim)

if __name__ == "__main__":
    unittest.main()
