#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Advanced honeypot detection tests for Cowrie
# ABOUTME: Tests command responses, timing, and behavioral fingerprints

import sys
import time
import socket
import paramiko
import subprocess
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class CowrieDetector:
    """Tests for detecting Cowrie honeypot through behavioral analysis"""

    def __init__(self, host: str, port: int, username: str = 'root', password: str = 'root'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.detections: List[str] = []
        self.warnings: List[str] = []

    def test_ping_response(self, client: paramiko.SSHClient) -> bool:
        """
        Test if ping returns fake IP addresses
        Real systems return actual IPs, Cowrie returns fake ones
        """
        logger.info("\n=== Testing ping command responses ===")
        try:
            stdin, stdout, stderr = client.exec_command('ping -c 1 google.com')
            output = stdout.read().decode()
            logger.info(f"Ping output:\n{output}")

            # Check for common fake IP patterns
            fake_ip_patterns = [
                '29.89.32.244',  # Common Cowrie fake IP
                '10.0.0.',       # Private IP ranges that shouldn't be for google.com
                '192.168.',
                '172.16.',
            ]

            for pattern in fake_ip_patterns:
                if pattern in output:
                    self.detections.append(f"Ping returned suspicious IP containing: {pattern}")
                    return True

            # Check if ping actually works (Cowrie simulates it)
            if 'bytes from' in output.lower() and 'time=' in output.lower():
                # This is expected behavior, but timing might be suspicious
                self.warnings.append("Ping appears to work (simulated or real)")

        except Exception as e:
            logger.error(f"Error testing ping: {e}")

        return False

    def test_dev_shm(self, client: paramiko.SSHClient) -> bool:
        """
        Test /dev/shm functionality
        Cowrie may not properly simulate this tmpfs filesystem
        """
        logger.info("\n=== Testing /dev/shm functionality ===")
        try:
            # Try to create a file in /dev/shm
            test_file = f'/dev/shm/test_{int(time.time())}'
            stdin, stdout, stderr = client.exec_command(f'echo "test" > {test_file} && cat {test_file} && rm {test_file}')
            output = stdout.read().decode()
            errors = stderr.read().decode()

            logger.info(f"Output: {output}")
            logger.info(f"Errors: {errors}")

            # Check for simulation issues
            if errors and ('read-only' in errors.lower() or 'cannot create' in errors.lower()):
                self.warnings.append("/dev/shm appears read-only or non-functional")
                return True

        except Exception as e:
            logger.error(f"Error testing /dev/shm: {e}")

        return False

    def test_busybox(self, client: paramiko.SSHClient) -> bool:
        """
        Test busybox binary behavior
        Cowrie simulates busybox but may not handle all operations
        """
        logger.info("\n=== Testing busybox behavior ===")
        try:
            # Try to read the busybox binary itself
            stdin, stdout, stderr = client.exec_command('busybox dd if=/proc/self/exe bs=1 count=4 2>/dev/null | od -A n -t x1')
            output = stdout.read().decode()
            errors = stderr.read().decode()

            logger.info(f"Output: {output}")

            # This command often fails on Cowrie as it doesn't properly simulate /proc/self/exe
            if not output.strip() or 'cannot' in errors.lower():
                self.detections.append("busybox dd from /proc/self/exe failed (typical of simulation)")
                return True

        except Exception as e:
            logger.error(f"Error testing busybox: {e}")

        return False

    def test_proc_filesystem(self, client: paramiko.SSHClient) -> bool:
        """
        Test /proc filesystem for anomalies
        Cowrie may have inconsistent or fake /proc entries
        """
        logger.info("\n=== Testing /proc filesystem ===")
        try:
            # Check if /proc/self/exe exists and is valid
            stdin, stdout, stderr = client.exec_command('ls -la /proc/self/exe')
            output = stdout.read().decode()
            logger.info(f"/proc/self/exe: {output}")

            # Check process list
            stdin, stdout, stderr = client.exec_command('ps aux')
            ps_output = stdout.read().decode()
            logger.info(f"Process list:\n{ps_output}")

            # Cowrie often shows very few processes
            process_count = len(ps_output.strip().split('\n')) - 1  # Subtract header
            if process_count < 10:
                self.warnings.append(f"Suspiciously low process count: {process_count}")

        except Exception as e:
            logger.error(f"Error testing /proc: {e}")

        return False

    def test_command_timing(self, client: paramiko.SSHClient) -> bool:
        """
        Test command execution timing
        Simulated commands may execute too quickly or with consistent timing
        """
        logger.info("\n=== Testing command timing ===")
        try:
            timings = []
            commands = ['ls', 'pwd', 'whoami', 'uname -a', 'cat /etc/passwd']

            for cmd in commands:
                start = time.time()
                stdin, stdout, stderr = client.exec_command(cmd)
                stdout.read()
                elapsed = time.time() - start
                timings.append((cmd, elapsed))
                logger.info(f"{cmd}: {elapsed:.4f}s")

            # Check if all commands execute too quickly (< 10ms)
            fast_commands = [t for t in timings if t[1] < 0.01]
            if len(fast_commands) > len(commands) / 2:
                self.warnings.append(f"{len(fast_commands)}/{len(commands)} commands executed suspiciously fast")

        except Exception as e:
            logger.error(f"Error testing timing: {e}")

        return False

    def test_filesystem_consistency(self, client: paramiko.SSHClient) -> bool:
        """
        Test filesystem for consistency issues
        Cowrie uses a fake filesystem that may have inconsistencies
        """
        logger.info("\n=== Testing filesystem consistency ===")
        try:
            # Check if common binaries exist and have reasonable sizes
            stdin, stdout, stderr = client.exec_command('ls -la /bin/bash /bin/sh /usr/bin/python* 2>/dev/null || echo "MISSING"')
            output = stdout.read().decode()
            logger.info(f"Binary files:\n{output}")

            if 'MISSING' in output:
                self.warnings.append("Some expected binaries are missing")

            # Check for world-writable sensitive files
            stdin, stdout, stderr = client.exec_command('ls -la /etc/passwd /etc/shadow 2>/dev/null')
            output = stdout.read().decode()
            logger.info(f"Sensitive files:\n{output}")

        except Exception as e:
            logger.error(f"Error testing filesystem: {e}")

        return False

    def test_network_tools(self, client: paramiko.SSHClient) -> bool:
        """
        Test network tool behavior
        Cowrie may simulate network tools with fake responses
        """
        logger.info("\n=== Testing network tools ===")
        try:
            # Test netstat
            stdin, stdout, stderr = client.exec_command('netstat -an 2>/dev/null || ss -an')
            output = stdout.read().decode()
            logger.info(f"Network connections (first 20 lines):\n{chr(10).join(output.split(chr(10))[:20])}")

            # Check if it shows the SSH connection we're using
            if str(self.port) not in output and '22' not in output:
                self.warnings.append("SSH connection not visible in netstat/ss output")

            # Test ifconfig/ip
            stdin, stdout, stderr = client.exec_command('ip addr || ifconfig')
            output = stdout.read().decode()
            logger.info(f"Network interfaces (first 30 lines):\n{chr(10).join(output.split(chr(10))[:30])}")

        except Exception as e:
            logger.error(f"Error testing network tools: {e}")

        return False

    def run_all_tests(self) -> Tuple[int, int]:
        """Run all detection tests"""
        logger.info(f"\n{'='*60}")
        logger.info(f"Running Advanced Honeypot Detection Tests")
        logger.info(f"Target: {self.host}:{self.port}")
        logger.info(f"{'='*60}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            logger.info(f"\nConnecting to SSH...")
            client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            logger.info("Connected successfully")

            # Run all tests
            self.test_ping_response(client)
            self.test_dev_shm(client)
            self.test_busybox(client)
            self.test_proc_filesystem(client)
            self.test_command_timing(client)
            self.test_filesystem_consistency(client)
            self.test_network_tools(client)

        except paramiko.AuthenticationException:
            logger.error("Authentication failed - check credentials")
            return -1, 0
        except Exception as e:
            logger.error(f"Error during testing: {e}")
            return -1, 0
        finally:
            client.close()

        # Print results
        logger.info(f"\n{'='*60}")
        logger.info("RESULTS")
        logger.info(f"{'='*60}")

        if self.detections:
            logger.info(f"\n❌ DETECTIONS ({len(self.detections)}):")
            for detection in self.detections:
                logger.info(f"  - {detection}")
        else:
            logger.info("\n✓ No definitive honeypot detections")

        if self.warnings:
            logger.info(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                logger.info(f"  - {warning}")

        logger.info(f"\n{'='*60}")
        logger.info("SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Detections: {len(self.detections)}")
        logger.info(f"Warnings: {len(self.warnings)}")

        if self.detections:
            logger.info("\n❌ LIKELY HONEYPOT - Multiple detection indicators found")
            return 1, len(self.detections)
        elif len(self.warnings) >= 3:
            logger.info("\n⚠️  SUSPICIOUS - Multiple warning signs detected")
            return 0, len(self.warnings)
        else:
            logger.info("\n✓ APPEARS LEGITIMATE - No significant indicators")
            return 0, 0


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port> [username] [password]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3] if len(sys.argv) > 3 else 'root'
    password = sys.argv[4] if len(sys.argv) > 4 else 'root'

    detector = CowrieDetector(host, port, username, password)
    exit_code, detection_count = detector.run_all_tests()

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
