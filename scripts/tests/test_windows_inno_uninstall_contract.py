import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INNO_SCRIPT = ROOT / "packaging" / "windows" / "Gilbreth.iss"


def _function_block(script: str, start: str, end: str) -> str:
    return script.split(start, 1)[1].split(end, 1)[0]


def test_interactive_purge_prompt_visibly_and_suppressed_defaults_to_no() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")

    assert "mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;" in script
    assert "mbConfirmation, MB_YESNO, IDNO) = IDYES;" not in script


def test_purge_receipt_timestamp_uses_runtime_char_separators() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")

    assert "GetDateTimeString('yyyymmdd-hhnnss', #0, #0)" in script
    assert "yyyymmdd-hhnnss-zzz" not in script
    assert not re.search(r"GetDateTimeString\([^\n]*,\s*''\s*,\s*''\s*\)", script)


def test_purge_receipt_path_is_collision_safe_and_reparse_closed() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")

    assert "function NewPurgeReceiptPath(const ReceiptDir: String): String;" in script
    assert "while Suffix < 10000 do" in script
    assert "Candidate := Prefix + '-' + IntToStr(Suffix) + '.json';" in script
    assert "if PathAbsent(Candidate) then" in script
    assert "(not ForceDirectories(ReceiptDir)) or IsReparsePath(ReceiptDir)" in script
    assert "PurgeReceiptPath := NewPurgeReceiptPath(ReceiptDir);" in script


def test_install_metadata_is_gated_by_verified_transaction_state() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")

    assert "CreateUninstallRegKey=InstallMetadataAllowed" in script
    registry = script.split("[Registry]", 1)[1].split("[Files]", 1)[0]
    icons = script.split("[Icons]", 1)[1].split("[Run]", 1)[0]
    assert registry.count("Check: InstallMetadataAllowed") == 3
    assert icons.count("Check: InstallMetadataAllowed") == 2
    assert "TransactionPrepared and PayloadVerified" in script


def test_post_copy_verification_reports_failure_without_swallowed_abort() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")
    verifier = _function_block(
        script,
        "procedure VerifyPayloadInsideInstallTransaction();",
        "procedure CurStepChanged",
    )

    assert "PayloadVerificationFailed := True;" in verifier
    assert "PayloadVerified := True;" in verifier
    assert "Abort" not in verifier
    assert "RaiseException" not in verifier
    assert "function GetCustomSetupExitCode(): Integer;" in script
    assert "TransactionPrepared and (not PayloadVerified)" in script


def test_preflight_payload_hash_is_checked_before_transaction_mutation() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")
    prepare = _function_block(
        script,
        "function PrepareToInstall(var NeedsRestart: Boolean): String;",
        "function VerifyInstalledProgram",
    )

    hash_check = "PreflightPassed := FileMatchesSha256("
    hash_position = prepare.index(hash_check)
    assert (
        "PreflightExe, Lowercase('{#ExpectedAppSha256}'))"
        in prepare[hash_position : hash_position + 180]
    )
    assert hash_position < prepare.index("AcquireLifecycleLock()")
    assert hash_position < prepare.index("WriteInProgressMarker")


def test_failed_clean_install_retires_only_its_created_lifecycle_lock() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")

    assert "LifecycleLockCreated: Boolean;" in script
    assert "LifecycleLockCreated := True;" in script
    assert (
        "LifecycleLockAbsentBeforePreflight := PathAbsent(LifecycleLockPath());"
        in script
    )
    assert "if LifecycleLockAbsentBeforePreflight and" in script
    assert "RemoveCreatedLifecycleLock := LifecycleLockCreated and" in script
    assert "((not TransactionPrepared) or RollbackComplete);" in script
    assert "DeleteIfPresent(LifecycleLockPath())" in script


def test_launcher_and_installed_apps_icons_inherit_the_embedded_app_icon() -> None:
    script = INNO_SCRIPT.read_text(encoding="utf-8")
    icons = script.split("[Icons]", 1)[1].split("[Run]", 1)[0]

    assert "UninstallDisplayIcon={app}\\{#ProductExe}" in script
    assert icons.count('Filename: "{app}\\{#ProductExe}"') == 2
    assert "IconFilename:" not in icons
    assert "SetupIconFile=" not in script
