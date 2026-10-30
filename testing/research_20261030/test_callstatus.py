from concurrent.futures import ThreadPoolExecutor
import unittest
from callstatus_model import Frame, recursive, iterative, vectors

class CallStatusTests(unittest.TestCase):
    def test_58_case_manifest_and_two_evaluators(self):
        cases = vectors()
        self.assertEqual(len(cases), 58)
        for number, expected, frame in cases:
            with self.subTest(case=number):
                if frame is None:
                    # Parent exception has no readable register. Requires actual
                    # engine adapter to check gas/stack/static-context triggers.
                    self.assertIsNone(expected)
                else:
                    self.assertEqual(recursive(frame), expected)
                    self.assertEqual(iterative(frame), expected)

    def test_parallel_and_discarded_speculation_have_no_register_leak(self):
        frames = [f for _, _, f in vectors() if f is not None] * 100
        serial = list(map(recursive, frames))
        with ThreadPoolExecutor(8) as pool:
            parallel = list(pool.map(iterative, frames))
        # Discard a speculative halting result, replay original input from scratch.
        discarded = [iterative(Frame('revert', (Frame('halt'),))) for _ in frames]
        self.assertTrue(all(code == 5 for code in discarded))
        replay = list(map(iterative, frames))
        self.assertEqual(serial, parallel)
        self.assertEqual(serial, replay)

    def test_last_call_and_sticky_halt_are_different_registers(self):
        children = (Frame('halt'), Frame())
        last = recursive(children[-1])
        self.assertEqual(last, 0)
        self.assertEqual(recursive(Frame('revert', children)), 5)
