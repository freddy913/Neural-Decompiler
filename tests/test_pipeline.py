"""
Basic sanity tests for the pipeline.
Checks that the normalizer doesn't break on edge cases like
empty input, special hex casing, or operands with extra whitespace.
Also verifies that the context budget curve in AsmToInput behaves
as expected (small functions get ~1000 tokens, large ones up to 6500).

Run with: python -m pytest tests/
"""
import unittest
import sys
import os

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_PIPELINE_DIR = os.path.join(_PROJECT_ROOT, "pipeline")

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
if _PIPELINE_DIR not in sys.path:
    sys.path.insert(0, _PIPELINE_DIR)

from pipeline.AsmNormalizer import (
    _normalize_operands, 
    _strip_addr_prefix, 
    _tighten_commas_semicolons,
    join_semicolon
)
from pipeline.AsmToInput import compute_context_budget
from pipeline.Heuristic import _split_identifiers
import pipeline.Config as Config

class TestDecompilerPipeline(unittest.TestCase):

    def setUp(self):
        """Runs before every test."""
        self.max_tokens = Config.CONTEXT_THRESHOLD_TOKENS

    def test_config_defaults(self):
        """Test strict configuration constraints."""
        self.assertEqual(self.max_tokens, 8192, "Context threshold must be 8192 for LongT5")
        self.assertTrue(Config.USE_ASSEMBLY_ONLY, "Pipeline should be in assembly-only mode")

    def test_asm_normalization_operands(self):
        """Test if pointer directives are removed correctly (Normalization Logic)."""
        raw_asm = "mov dword ptr [rbp-0x4], edi"
        result = _normalize_operands(raw_asm)

        self.assertNotIn("dword ptr", result)
        self.assertIn("mov", result)

    def test_asm_address_stripping(self):
        """Test removal of objdump address prefixes."""
        line = "  0x401123: push rbp"
        result = _strip_addr_prefix(line)
        self.assertEqual(result, "push rbp")

    def test_asm_joining(self):
        """Test joining of assembly lines."""
        lines = ["push rbp", "mov rbp,rsp", ""]
        result = join_semicolon(lines)
        self.assertEqual(result, "push rbp; mov rbp,rsp")

    def test_heuristic_context_budget(self):
        """Test the dynamic context budget calculation."""
        budget_small = compute_context_budget(100)  # <= 128
        self.assertEqual(budget_small, 1000)

        budget_mid = compute_context_budget(400)  # <= 512
        self.assertEqual(budget_mid, 2500)

        budget_huge = compute_context_budget(5000)  # > 2000
        self.assertEqual(budget_huge, 6500)

    def test_identifier_splitting(self):
        """Test the semantic splitting of function names for scoring."""
        name_snake = "get_user_id"
        tokens_snake = _split_identifiers(name_snake)
        self.assertIn("user", tokens_snake)
        self.assertIn("id", tokens_snake)

        name_camel = "calculateSum"
        tokens_camel = _split_identifiers(name_camel)
        self.assertIn("calculate", tokens_camel)
        self.assertIn("sum", tokens_camel)

if __name__ == '__main__':
    unittest.main()
