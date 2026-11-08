"""Host-independent checks for bounded benchmark commands and cleanup."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bench_tun', Path(__file__).with_name('bench-tun.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkLifecycleTest(unittest.TestCase):
    def test_command_deadlines(self):
        with patch.object(bench.subprocess, 'run') as run:
            bench.run('ip', 'link')
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
            bench.run('iperf3', timeout=65)
            self.assertEqual(run.call_args.kwargs['timeout'], 65)

    def test_cleanup_continues_after_failure_or_timeout(self):
        for failure in (subprocess.CalledProcessError(1, 'ip'), subprocess.TimeoutExpired('ip', 30)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(bench, 'run', side_effect=[failure, '']) as run, patch.object(bench.sys, 'stderr'):
                    bench.cleanup_namespaces(['client', 'server'])
                    self.assertEqual([call.args for call in run.call_args_list],
                                     [('ip', 'netns', 'del', 'server'), ('ip', 'netns', 'del', 'client')])


if __name__ == '__main__':
    unittest.main()
