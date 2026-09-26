"""First-run Setup Wizard controller for Device Guardian.

Guides users through privacy disclosures, Telegram bot creation, token verification,
chat ID detection, camera testing, location diagnostics, and safe configuration saving.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path
from typing import Callable, Optional

from device_guardian.alerts.pipeline import trigger_alert
from device_guardian.config import (
    AppConfig,
    ConfigurationError,
    load_config,
    mask_chat_id,
    mask_token,
)
from device_guardian.location.geolocation import get_approximate_location
from device_guardian.logger import get_logger
from device_guardian.setup.camera_detector import (
    detect_available_cameras,
    get_permission_guidance,
    verify_camera_lifecycle,
)
from device_guardian.setup.chat_detector import poll_for_chat_id
from device_guardian.setup.status import SetupStatus, determine_setup_status
from device_guardian.setup.storage import safe_save_config
from device_guardian.telegram.bot import TelegramClient

logger = get_logger("setup.wizard")


class SetupWizard:
    """Coordinates the first-run configuration workflow."""

    def __init__(
        self,
        input_fn: Callable[[str], str] = input,
        print_fn: Callable[..., None] = print,
        env_path: Optional[Path | str] = None,
    ) -> None:
        """Initialize SetupWizard with configurable I/O for testability.

        Args:
            input_fn: Input function (defaults to built-in input).
            print_fn: Print function (defaults to built-in print).
            env_path: Destination path for .env file.
        """
        self._input = input_fn
        self._print = print_fn
        self._env_path = Path(env_path) if env_path else Path.cwd() / ".env"

    def _prompt(self, message: str) -> str:
        """Prompt user and strip trailing whitespace."""
        try:
            return self._input(message).strip()
        except (EOFError, KeyboardInterrupt):
            self._print("\nSetup cancelled.")
            sys.exit(0)

    def _prompt_yes_no(self, message: str, default_yes: bool = True) -> bool:
        """Prompt for a Yes/No decision."""
        suffix = " [Y/n]: " if default_yes else " [y/N]: "
        response = self._prompt(message + suffix).lower()
        if not response:
            return default_yes
        return response in {"y", "yes"}

    def run(self) -> bool:
        """Execute the complete interactive Setup Wizard.

        Returns:
            True if setup finished and saved successfully, False if cancelled or aborted.
        """
        # Step 0: Welcome & Reconfiguration check
        status = determine_setup_status(env_path=self._env_path)
        if status == SetupStatus.CONFIGURED:
            self._print("==================================================")
            self._print("              DEVICE GUARDIAN")
            self._print("              RECONFIGURATION")
            self._print("==================================================")
            try:
                existing_cfg = load_config(env_path=self._env_path)
                self._print("\nExisting configuration detected:")
                self._print(f"  - Telegram Chat: {mask_chat_id(existing_cfg.telegram_chat_id)}")
                self._print(f"  - Camera Index:  {existing_cfg.camera_index}")
                self._print(f"  - Location API:  {existing_cfg.location_api_url}")
            except Exception:
                pass

            if not self._prompt_yes_no("\nDo you want to reconfigure Device Guardian?", default_yes=False):
                self._print("Setup cancelled. Existing configuration preserved.")
                return False

        self._print("\n==================================================")
        self._print("              DEVICE GUARDIAN")
        self._print("              FIRST-TIME SETUP")
        self._print("==================================================")
        self._print("\nWelcome to Device Guardian.")
        self._print("\nThis wizard will configure:")
        self._print("  [+] Telegram alerts")
        self._print("  [+] Alert recipient")
        self._print("  [+] Camera")
        self._print("  [+] Location diagnostics")
        self._print("\nDevice Guardian does NOT collect:")
        self._print("  [-] Passwords")
        self._print("  [-] Keystrokes")
        self._print("  [-] Browser history")
        self._print("  [-] Personal files")

        self._prompt("\nPress ENTER to continue...")

        # Step 1: Privacy notice & confirmation
        if not self._step_privacy_notice():
            return False

        # Step 2: Telegram Bot Token
        bot_token, bot_username = self._step_telegram_token()
        if not bot_token:
            return False

        # Step 3: Chat ID Detection
        chat_id = self._step_chat_id(bot_token)
        if not chat_id:
            return False

        # Step 4: Camera Setup & Test
        camera_index = self._step_camera_setup()

        # Step 5: Location Diagnostics Test
        self._step_location_test()

        # Step 6: Summary Review & Save Confirmation
        candidate_config = AppConfig(
            telegram_bot_token=bot_token,
            telegram_chat_id=chat_id,
            location_api_url="https://ipapi.co/json/",
            camera_index=camera_index,
            request_timeout_seconds=10.0,
            log_level="INFO",
            env_file_path=self._env_path,
        )

        if not self._step_review_and_save(candidate_config, bot_username):
            return False

        # Step 7: Final Test Alert (Optional)
        self._step_final_test_alert(candidate_config)

        # Step 8: Completion
        self._print("\n==================================================")
        self._print("              SETUP COMPLETE")
        self._print("==================================================")
        self._print("\nDevice Guardian is now configured and ready.")
        self._print("\nUseful commands:")
        self._print("  python -m device_guardian.main --test-alert   # Trigger test alert")
        self._print("  python -m device_guardian.main --check-config  # Check configuration")
        self._print("  python -m device_guardian.main --setup         # Reconfigure at any time")
        return True

    def _step_privacy_notice(self) -> bool:
        """Display transparent privacy disclosures and seek user consent."""
        self._print("\n==================================================")
        self._print("STEP 1: PRIVACY & PERMISSIONS NOTICE")
        self._print("==================================================")
        self._print("\nPlease review how Device Guardian operates:")
        self._print("\n1. Telegram Notifications:")
        self._print("   Alerts and photographs are sent exclusively to your private Telegram chat.")
        self._print("\n2. Camera Access:")
        self._print("   When an alert triggers, the webcam captures a single still frame.")
        self._print("   The camera is immediately released. No continuous recording occurs.")
        self._print("\n3. Approximate Location:")
        self._print("   Device Guardian estimates location from your public IP address.")
        self._print("   This is APPROXIMATE (city/metro level) and is NOT GPS positioning.")
        self._print("\n4. Local Credentials:")
        self._print("   Bot tokens are stored locally in your .env file and never logged.")

        if not self._prompt_yes_no("\nI understand and want to continue"):
            self._print("\nSetup cancelled.")
            return False
        return True

    def _step_telegram_token(self) -> tuple[Optional[str], str]:
        """Guide user through Telegram Bot creation and verify token."""
        self._print("\n==================================================")
        self._print("STEP 2: TELEGRAM BOT SETUP")
        self._print("==================================================")
        self._print("\nTo receive alerts, you need your own personal Telegram bot:")
        self._print("1. Open Telegram and search for @BotFather.")
        self._print("2. Send: /newbot")
        self._print("3. Follow BotFather's instructions to choose a name and username.")
        self._print("4. Copy the HTTP API token provided by BotFather.")

        while True:
            self._print("\nEnter your Telegram bot token (or 'exit' to cancel):")
            token_input = self._prompt("> ")

            if token_input.lower() in {"exit", "quit", "q"}:
                self._print("Setup cancelled.")
                return None, ""

            if not token_input:
                self._print("Token cannot be empty. Please try again.")
                continue

            self._print("\nVerifying Telegram bot token...")
            client = TelegramClient(bot_token=token_input, chat_id="placeholder", timeout=8.0)
            resp = client.verify_credentials()

            if resp.success and isinstance(resp.data, dict):
                bot_username = resp.data.get("username", "Unknown")
                self._print("[OK] Token valid!")
                self._print(f"[OK] Bot reachable: @{bot_username}")
                return token_input, bot_username
            else:
                self._print(f"[FAIL] Token could not be verified: {resp.error_message}")
                self._print("\nPossible causes:")
                self._print("- Incorrect token string entered")
                self._print("- Internet connection unavailable")
                self._print("- Telegram Bot API temporarily unreachable")

                if not self._prompt_yes_no("\nWould you like to try entering the token again?"):
                    self._print("Setup cancelled.")
                    return None, ""

    def _step_chat_id(self, bot_token: str) -> Optional[str]:
        """Detect or manually configure destination Telegram Chat ID."""
        self._print("\n==================================================")
        self._print("STEP 3: TELEGRAM CHAT DETECTION")
        self._print("==================================================")
        self._print("\nDevice Guardian needs to know which chat to deliver alerts to.")
        self._print("\nInstructions:")
        self._print("1. Open Telegram on your phone or computer.")
        self._print("2. Find your new bot and click START (or send: /start).")
        self._print("3. Send any setup message to your bot, such as:")
        self._print("   DEVICE GUARDIAN SETUP")

        choice = self._prompt("\nPress ENTER to start automatic detection (or 'm' for manual entry): ")
        if choice.lower() == "m":
            return self._manual_chat_id_entry()

        client = TelegramClient(bot_token=bot_token, chat_id="placeholder", timeout=5.0)

        while True:
            self._print("\nWaiting for incoming Telegram message...")

            def progress_cb(current: int, total: int) -> None:
                self._print(f"Waiting... [{current}/{total}]")

            detected_chats = poll_for_chat_id(
                telegram_client=client,
                max_attempts=8,
                poll_interval=2.0,
                progress_callback=progress_cb,
            )

            if detected_chats:
                if len(detected_chats) == 1:
                    chat = detected_chats[0]
                    self._print(f"\n[OK] Chat detected: {chat.summary()}")
                    if self._prompt_yes_no("Confirm this is your Telegram chat?"):
                        return chat.chat_id
                else:
                    self._print("\nMultiple Telegram chats were detected:")
                    for idx, chat in enumerate(detected_chats, 1):
                        self._print(f"  {idx}. {chat.summary()}")

                    sel = self._prompt(f"Select chat to use [1-{len(detected_chats)}]: ")
                    try:
                        chosen_idx = int(sel) - 1
                        if 0 <= chosen_idx < len(detected_chats):
                            return detected_chats[chosen_idx].chat_id
                    except ValueError:
                        pass
                    self._print("Invalid selection.")

            self._print("\n[-] No new message detected.")
            self._print("Options:")
            self._print("1. Retry detection (make sure you sent a message to the bot)")
            self._print("2. Enter Chat ID manually")
            self._print("3. Exit setup")
            opt = self._prompt("Select [1-3]: ")

            if opt == "1":
                continue
            elif opt == "2":
                return self._manual_chat_id_entry()
            else:
                self._print("Setup cancelled.")
                return None

    def _manual_chat_id_entry(self) -> Optional[str]:
        """Prompt user for manual numeric Chat ID entry."""
        self._print("\nManual Chat ID Entry:")
        self._print("(Tip: You can obtain your chat ID from @userinfobot on Telegram)")
        while True:
            raw = self._prompt("Enter your numeric Telegram Chat ID (or 'exit' to cancel): ")
            if raw.lower() in {"exit", "quit", "q"}:
                return None
            if raw.strip().lstrip("-").isdigit():
                return raw.strip()
            self._print("Invalid chat ID. Telegram chat IDs are numeric.")

    def _step_camera_setup(self) -> int:
        """Detect and test webcam capture."""
        self._print("\n==================================================")
        self._print("STEP 4: CAMERA SETUP")
        self._print("==================================================")
        self._print("\nDetecting connected camera devices...")

        cameras = detect_available_cameras(max_to_check=3)
        selected_camera = 0

        if not cameras:
            self._print("\n[-] No camera detected automatically.")
            self._print(get_permission_guidance())
            self._print("\nOptions:")
            self._print("1. Specify camera index manually (default: 0)")
            self._print("2. Continue without camera (text-only alerts)")
            choice = self._prompt("Select [1-2]: ")
            if choice == "1":
                idx_str = self._prompt("Enter camera index [0-9]: ")
                try:
                    selected_camera = int(idx_str)
                except ValueError:
                    selected_camera = 0
            else:
                return 0
        elif len(cameras) == 1:
            selected_camera = cameras[0]
            self._print(f"[OK] Camera {selected_camera} detected.")
        else:
            self._print("\nAvailable cameras:")
            for idx in cameras:
                self._print(f"  - Camera {idx}")
            cam_str = self._prompt(f"Select camera [{'/'.join(map(str, cameras))}]: ")
            try:
                selected_camera = int(cam_str)
            except ValueError:
                selected_camera = cameras[0]

        # Offer camera test
        if self._prompt_yes_no(f"\nTest Camera {selected_camera} capture now?"):
            while True:
                self._print(f"\nTesting Camera {selected_camera}...")
                success, steps, err = verify_camera_lifecycle(selected_camera)
                for step in steps:
                    self._print(f"  {step}")

                if success:
                    self._print("[OK] Camera capture verified successfully!")
                    break
                else:
                    self._print(f"[FAIL] Camera test failed: {err}")
                    self._print("\n" + get_permission_guidance())
                    self._print("\nOptions:")
                    self._print("1. Retry camera test")
                    self._print("2. Select different camera index")
                    self._print("3. Continue without camera testing")
                    opt = self._prompt("Select [1-3]: ")
                    if opt == "1":
                        continue
                    elif opt == "2":
                        idx_str = self._prompt("Enter camera index: ")
                        try:
                            selected_camera = int(idx_str)
                        except ValueError:
                            pass
                    else:
                        break

        return selected_camera

    def _step_location_test(self) -> None:
        """Run diagnostic test on approximate IP geolocation."""
        self._print("\n==================================================")
        self._print("STEP 5: LOCATION TEST")
        self._print("==================================================")
        self._print("\nTesting approximate public-IP geolocation lookup...")

        loc = get_approximate_location(timeout=8.0)
        if loc.is_available:
            self._print("[OK] Location service reachable.")
            self._print(f"  City:        {loc.city}")
            self._print(f"  Region:      {loc.region}")
            self._print(f"  Country:     {loc.country}")
            if loc.latitude is not None and loc.longitude is not None:
                self._print(f"  Coordinates: {loc.latitude:.6f}, {loc.longitude:.6f}")
            self._print("\nNotice: This is approximate IP-based location and not GPS.")
        else:
            self._print("[-] Location service unavailable.")
            self._print("Device Guardian will continue setup; location will show 'Unavailable' during alerts.")

    def _step_review_and_save(self, config: AppConfig, bot_username: str) -> bool:
        """Display configuration summary and save safely upon confirmation."""
        self._print("\n==================================================")
        self._print("STEP 6: CONFIGURATION REVIEW")
        self._print("==================================================")
        self._print("\nReview your settings:")
        self._print(f"  Telegram Bot:   [OK] Verified (@{bot_username})")
        self._print(f"  Telegram Chat:  [OK] {mask_chat_id(config.telegram_chat_id)}")
        self._print(f"  Camera Device:  Index {config.camera_index}")
        self._print(f"  Geolocation:    {config.location_api_url} (Approximate IP)")
        self._print(f"  Config File:    {self._env_path}")

        if not self._prompt_yes_no("\nSave this configuration?"):
            self._print("Setup cancelled. Configuration was not saved.")
            return False

        try:
            safe_save_config(config, target_path=self._env_path)
            self._print(f"\n[OK] Configuration successfully saved to: {self._env_path}")
            return True
        except ConfigurationError as exc:
            self._print(f"\n[FAIL] Failed to save configuration: {exc}")
            return False

    def _step_final_test_alert(self, config: AppConfig) -> None:
        """Optionally send a live test alert through the complete pipeline."""
        self._print("\n==================================================")
        self._print("STEP 7: FINAL VERIFICATION ALERT")
        self._print("==================================================")

        if not self._prompt_yes_no("\nSend a live test alert to your Telegram chat now?"):
            self._print("Skipped live test alert.")
            return

        self._print("\nDispatching test alert via Device Guardian pipeline...")
        result = trigger_alert(
            reason="Device Guardian Setup Complete",
            config=config,
            cleanup_image_on_success=True,
        )

        if result.success:
            self._print("\n[OK] Test alert delivered successfully to your Telegram chat!")
            if result.camera_success:
                self._print("  [+] Photograph included.")
            if result.location_success and result.event:
                loc = result.event.location
                self._print(f"  [+] Approximate location included: {loc.city}, {loc.country}")
        else:
            self._print(f"\n[FAIL] Alert delivery failed: {result.error_message}")
            self._print("You can troubleshoot with: python -m device_guardian.main --check-config")


def run_setup_wizard(env_path: Optional[Path | str] = None) -> bool:
    """Convenience entrypoint to execute the setup wizard.

    Args:
        env_path: Optional explicit path to destination .env file.

    Returns:
        True on successful completion, False otherwise.
    """
    wizard = SetupWizard(env_path=env_path)
    return wizard.run()
