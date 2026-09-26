"""Offline Text-to-Speech Voice Warning module for Device Guardian.

Synthesizes audible warnings locally without internet access or remote servers.
Works cross-platform using operating-system native speech facilities:
- Windows: System.Speech / SAPI SpeechSynthesizer
- macOS: /usr/bin/say
- Linux: spd-say, espeak-ng, espeak
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from typing import Optional

from device_guardian.logger import get_logger

logger = get_logger("detection.voice")

DEFAULT_WARNING_TEXT = (
    "Warning. Multiple failed authentication attempts have been detected on this device."
)


class OfflineVoiceWarning:
    """Manages offline local text-to-speech security warnings."""

    def __init__(
        self,
        enabled: bool = True,
        warning_text: str = DEFAULT_WARNING_TEXT,
        cooldown_seconds: float = 300.0,
    ) -> None:
        """Initialize the voice warning engine.

        Args:
            enabled: Whether voice warnings are enabled.
            warning_text: Default message to synthesize.
            cooldown_seconds: Minimum seconds between consecutive spoken warnings.
        """
        self._enabled = enabled
        self._warning_text = warning_text.strip() or DEFAULT_WARNING_TEXT
        self._cooldown_seconds = max(0.0, cooldown_seconds)
        self._last_spoken_time: Optional[float] = None

    @property
    def enabled(self) -> bool:
        """Whether voice warnings are active."""
        return self._enabled

    @property
    def warning_text(self) -> str:
        """Text template for synthesized warning."""
        return self._warning_text

    def is_available(self) -> bool:
        """Check if local text-to-speech facilities are available on this system."""
        sys_name = platform.system()
        if sys_name == "Windows":
            return bool(shutil.which("powershell.exe") or shutil.which("powershell"))
        elif sys_name == "Darwin":
            return bool(shutil.which("say"))
        elif sys_name == "Linux":
            return any(
                bool(shutil.which(cmd))
                for cmd in ["spd-say", "espeak-ng", "espeak", "festival"]
            )
        return False

    def can_speak(self, current_time: Optional[float] = None) -> bool:
        """Check if speech is enabled and not in voice cooldown."""
        if not self._enabled:
            return False
        if self._last_spoken_time is None:
            return True
        now = current_time if current_time is not None else time.time()
        return (now - self._last_spoken_time) >= self._cooldown_seconds

    def speak(
        self,
        text: Optional[str] = None,
        timeout: float = 8.0,
    ) -> bool:
        """Synthesize and play speech warning locally.

        Fails gracefully without raising exceptions; on any hardware, binary,
        or playback error, logs a warning and returns False.

        Args:
            text: Optional custom speech text (defaults to configured warning_text).
            timeout: Process execution timeout in seconds.

        Returns:
            True if speech was successfully synthesized, False otherwise.
        """
        if not self._enabled:
            logger.debug("Voice warning is disabled in configuration.")
            return False

        if not self.can_speak():
            logger.debug("Voice warning is currently in cooldown; suppressing audio.")
            return False

        msg = (text or self._warning_text).strip()
        sys_name = platform.system()
        logger.info("Triggering local offline voice warning on %s...", sys_name)

        try:
            success = self._synthesize_speech(sys_name, msg, timeout)
            if success:
                self._last_spoken_time = time.time()
                logger.info("Offline voice warning synthesized successfully.")
                return True
            else:
                logger.warning("Offline voice warning unavailable on this system.")
                return False
        except Exception as exc:
            logger.warning("Offline voice warning execution failed: %s", exc)
            return False

    def _synthesize_speech(
        self,
        system_name: str,
        text: str,
        timeout: float,
    ) -> bool:
        """Dispatch speech synthesis command according to operating system."""
        # Sanitize text for shell command arguments (letters, numbers, basic punctuation)
        clean_text = "".join(c for c in text if c.isalnum() or c in " .,!?-")

        if system_name == "Windows":
            ps_cmd = (
                "Add-Type -AssemblyName System.Speech; "
                "$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                f"$synth.Speak('{clean_text}')"
            )
            powershell = shutil.which("powershell.exe") or "powershell"
            proc = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            return proc.returncode == 0

        elif system_name == "Darwin":
            say_bin = shutil.which("say") or "/usr/bin/say"
            proc = subprocess.run(
                [say_bin, clean_text],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            return proc.returncode == 0

        elif system_name == "Linux":
            # Attempt spd-say, then espeak-ng, then espeak
            for cmd_name, args in [
                ("spd-say", ["spd-say", clean_text]),
                ("espeak-ng", ["espeak-ng", clean_text]),
                ("espeak", ["espeak", clean_text]),
            ]:
                if shutil.which(cmd_name):
                    proc = subprocess.run(
                        args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=timeout,
                    )
                    if proc.returncode == 0:
                        return True
            return False

        return False
