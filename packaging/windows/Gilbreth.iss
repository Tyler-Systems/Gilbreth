; Gilbreth stable per-user Windows package.
; All values that bind a candidate are supplied by build-windows-package.ps1.

#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef SourceGitSha
  #error SourceGitSha is required
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef InstallerBaseName
  #error InstallerBaseName is required
#endif

#define ProductName "Gilbreth"
#define ProductExe "gilbreth-app.exe"
#define LifecycleGuardExe "gilbreth-lifecycle-guard.exe"
#define InstallIdentityFile "gilbreth-install-identity.txt"
#define StableAppId "{{D8B6A810-61CE-4A62-A8B6-3C9635104DB8}"

#ifdef SigningEnabled
  #define AppFileFlags "ignoreversion signonce"
  #define UnsignedAuthorityArg ""
#else
  #define AppFileFlags "ignoreversion"
  ; The installer-controlled authority flag is internal to unsigned packages;
  ; it is not part of the public builder interface or artifact names.
  #define UnsignedAuthorityArg " --allow-unsigned-package"
#endif

[Setup]
AppId={#StableAppId}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher=Tyler Systems
AppPublisherURL=https://github.com/Tyler-Systems/Gilbreth
AppSupportURL=https://github.com/Tyler-Systems/Gilbreth/issues
DefaultDirName={localappdata}\Programs\Gilbreth
DefaultGroupName=Gilbreth
UsePreviousAppDir=no
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename={#InstallerBaseName}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
AppMutex=Local\GilbrethV2
CloseApplications=no
RestartApplications=no
SetupLogging=yes
UninstallDisplayIcon={app}\{#ProductExe}
UninstallDisplayName={#ProductName}
CreateUninstallRegKey=InstallMetadataAllowed
WizardStyle=modern
#ifdef SigningEnabled
SignTool=artifact_sign
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Tyler Systems\Gilbreth"; ValueType: string; ValueName: "PackageVersion"; ValueData: "{#AppVersion}"; Flags: uninsdeletevalue; Check: InstallMetadataAllowed
Root: HKCU; Subkey: "Software\Tyler Systems\Gilbreth"; ValueType: string; ValueName: "PackageSourceGitSha"; ValueData: "{#SourceGitSha}"; Flags: uninsdeletevalue; Check: InstallMetadataAllowed
Root: HKCU; Subkey: "Software\Tyler Systems\Gilbreth"; ValueType: string; ValueName: "PackageAppSha256"; ValueData: "{#ExpectedAppSha256}"; Flags: uninsdeletevalue uninsdeletekeyifempty; Check: InstallMetadataAllowed

[Files]
; The second entry is extracted to {tmp} for pre-copy fail-closed checks.
Source: "{#StageDir}\gilbreth-app.exe"; DestDir: "{app}"; Flags: {#AppFileFlags}
Source: "{#StageDir}\gilbreth-app.exe"; DestDir: "{app}"; DestName: "{#LifecycleGuardExe}"; Flags: {#AppFileFlags}
Source: "{#StageDir}\gilbreth-app.exe"; DestName: "gilbreth-preflight.exe"; Flags: dontcopy
Source: "{#StageDir}\LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\VERIFY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\licenses\LICENSE-Inter.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#StageDir}\licenses\LICENSE-IBMPlexMono.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
; This generated file is deliberately last. Its callback still runs inside
; Inno's native file-install rollback window, before Icons/ARP finalization.
Source: "{#StageDir}\{#InstallIdentityFile}"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: VerifyPayloadInsideInstallTransaction

[Icons]
Name: "{userprograms}\Gilbreth"; Filename: "{app}\{#ProductExe}"; WorkingDir: "{app}"; Check: InstallMetadataAllowed
Name: "{autodesktop}\Gilbreth"; Filename: "{app}\{#ProductExe}"; WorkingDir: "{app}"; Tasks: desktopicon; Check: InstallMetadataAllowed

[Run]
; skipifsilent is mandatory: silent and WinGet installs never launch capture.
Filename: "{app}\{#ProductExe}"; Description: "Launch Gilbreth"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent; Check: ReleaseLifecycleForLaunch

[Code]
var
  BackupCreated: Boolean;
  InstallCommitted: Boolean;
  PurgeRequested: Boolean;
  LifecycleLock: TFileStream;
  LegacyAppMoved: Boolean;
  LegacyHelperMoved: Boolean;
  LegacyStartMenuMoved: Boolean;
  LegacyDesktopMoved: Boolean;
  LegacyAutostart: Boolean;
  PurgeReceiptPath: String;
  PurgeCapable: Boolean;
  TransactionPrepared: Boolean;
  TransactionOldAppHash: String;
  PayloadVerified: Boolean;
  PayloadVerificationFailed: Boolean;
  LifecycleLockCreated: Boolean;

function PackageGetFileAttributes(const FileName: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';
function PackageFlushFileBuffers(FileHandle: THandle): Boolean;
  external 'FlushFileBuffers@kernel32.dll stdcall';
function PackageMoveFileEx(const ExistingFileName, NewFileName: String;
  Flags: LongWord): Boolean;
  external 'MoveFileExW@kernel32.dll stdcall';

function HasExactParam(const Wanted: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Wanted) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function Q(const Value: String): String;
begin
  Result := '"' + Value + '"';
end;

function BackupDir(): String;
begin
  Result := ExpandConstant('{localappdata}\Programs\Gilbreth.package-backup');
end;

function LifecycleLockPath(): String;
begin
  Result := ExpandConstant('{localappdata}\Gilbreth.lifecycle.lock');
end;

function TransactionInProgressMarkerPath(): String;
begin
  Result := ExpandConstant(
    '{localappdata}\Programs\Gilbreth.package-transaction-in-progress');
end;

function TransactionCommittedMarkerPath(): String;
begin
  Result := ExpandConstant(
    '{localappdata}\Programs\Gilbreth.package-transaction-committed');
end;

function TransactionMarkerTempPath(): String;
begin
  Result := ExpandConstant(
    '{localappdata}\Programs\Gilbreth.package-transaction-marker.tmp');
end;

function PathAbsent(const Path: String): Boolean;
begin
  Result := PackageGetFileAttributes(Path) = $FFFFFFFF;
end;

function NewPurgeReceiptPath(const ReceiptDir: String): String;
var
  Prefix: String;
  Candidate: String;
  Suffix: Integer;
begin
  Prefix := ReceiptDir + '\Gilbreth-uninstall-' +
    GetDateTimeString('yyyymmdd-hhnnss', #0, #0);
  Suffix := 0;
  while Suffix < 10000 do
  begin
    if Suffix = 0 then
      Candidate := Prefix + '.json'
    else
      Candidate := Prefix + '-' + IntToStr(Suffix) + '.json';
    if PathAbsent(Candidate) then
    begin
      Result := Candidate;
      Exit;
    end;
    Suffix := Suffix + 1;
  end;
  Result := '';
end;

function IsReparsePath(const Path: String): Boolean;
var
  Attributes: LongWord;
begin
  Attributes := PackageGetFileAttributes(Path);
  Result := (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0);
end;

function FlushFilePath(const Path: String): Boolean;
var
  Stream: TFileStream;
begin
  Result := False;
  try
    Stream := TFileStream.Create(
      Path, fmOpenReadWrite or fmShareExclusive);
    try
      Result := PackageFlushFileBuffers(Stream.Handle);
    finally
      Stream.Free;
    end;
  except
    Log('Could not flush transaction marker ' + Path + '.');
  end;
end;

function IsHexValue(const Value: String; ExpectedLength: Integer): Boolean;
var
  I: Integer;
begin
  Result := Length(Value) = ExpectedLength;
  if not Result then
    Exit;
  for I := 1 to Length(Value) do
    if Pos(Value[I], '0123456789abcdefABCDEF') = 0 then
    begin
      Result := False;
      Exit;
    end;
end;

function TryGetFileSha256(const Path: String; var Value: String): Boolean;
begin
  Result := False;
  Value := '';
  if (not FileExists(Path)) or IsReparsePath(Path) then
    Exit;
  try
    Value := Lowercase(GetSHA256OfFile(Path));
    Result := IsHexValue(Value, 64);
  except
    Log('Could not hash package file ' + Path + '.');
  end;
end;

function FileMatchesSha256(const Path, ExpectedHash: String): Boolean;
var
  ActualHash: String;
begin
  Result := TryGetFileSha256(Path, ActualHash) and
    (CompareText(ActualHash, Lowercase(ExpectedHash)) = 0);
end;

function ReadTransactionMarker(const Path: String; var NewAppHash,
  OldAppHash: String): Boolean;
var
  Lines: TArrayOfString;
begin
  Result := FileExists(Path) and (not IsReparsePath(Path)) and
    LoadStringsFromFile(Path, Lines) and
    (GetArrayLength(Lines) = 3) and
    (Lines[0] = 'schema=1') and
    (Copy(Lines[1], 1, 15) = 'new-app-sha256=') and
    (Copy(Lines[2], 1, 15) = 'old-app-sha256=');
  if not Result then
    Exit;
  NewAppHash := Copy(Lines[1], 16, Length(Lines[1]));
  OldAppHash := Copy(Lines[2], 16, Length(Lines[2]));
  Result := IsHexValue(NewAppHash, 64) and
    ((OldAppHash = 'absent') or IsHexValue(OldAppHash, 64));
end;

function WriteInProgressMarker(const OldAppHash: String): Boolean;
var
  Contents: String;
  TempPath: String;
  MarkerParent: String;
begin
  Result := False;
  TempPath := TransactionMarkerTempPath();
  MarkerParent := ExtractFileDir(TempPath);
  if ((not DirExists(MarkerParent)) and
      (not ForceDirectories(MarkerParent))) or
     IsReparsePath(MarkerParent) then
    Exit;
  if (not PathAbsent(TransactionInProgressMarkerPath())) or
     (not PathAbsent(TransactionCommittedMarkerPath())) or
     IsReparsePath(TempPath) or DirExists(TempPath) then
    Exit;
  if FileExists(TempPath) and (not DeleteFile(TempPath)) then
    Exit;
  Contents := 'schema=1' + #13#10 +
    'new-app-sha256={#ExpectedAppSha256}' + #13#10 +
    'old-app-sha256=' + OldAppHash;
  if (not SaveStringToFile(TempPath, Contents, False)) or
     (not FlushFilePath(TempPath)) then
  begin
    DeleteFile(TempPath);
    Exit;
  end;
  Result := PackageMoveFileEx(TempPath,
    TransactionInProgressMarkerPath(), $8) and
    FileExists(TransactionInProgressMarkerPath());
  if not Result then
    DeleteFile(TempPath);
end;

function HasValidInProgressMarker(): Boolean;
var
  NewAppHash: String;
  OldAppHash: String;
begin
  Result := FileExists(TransactionInProgressMarkerPath()) and
    ReadTransactionMarker(
      TransactionInProgressMarkerPath(), NewAppHash, OldAppHash);
end;

function HasValidCommittedMarker(): Boolean;
var
  NewAppHash: String;
  OldAppHash: String;
begin
  Result := FileExists(TransactionCommittedMarkerPath()) and
    ReadTransactionMarker(
      TransactionCommittedMarkerPath(), NewAppHash, OldAppHash);
end;

function AcquireLifecycleLock(): Boolean;
var
  LockPath: String;
begin
  Result := LifecycleLock <> nil;
  if Result then
    Exit;
  LockPath := LifecycleLockPath();
  if not FileExists(LockPath) then
  begin
    if (not PathAbsent(LockPath)) or
       (not SaveStringToFile(LockPath, '', False)) then
      Exit;
    LifecycleLockCreated := True;
  end;
  if IsReparsePath(LockPath) then
    Exit;
  try
    LifecycleLock := TFileStream.Create(
      LockPath, fmOpenReadWrite or fmShareExclusive);
    Result := True;
  except
    LifecycleLock := nil;
    if LifecycleLockCreated and DeleteFile(LockPath) then
      LifecycleLockCreated := False;
    Result := False;
  end;
end;

procedure ReleaseLifecycleLock();
begin
  if LifecycleLock <> nil then
  begin
    LifecycleLock.Free;
    LifecycleLock := nil;
  end;
end;

function DeleteIfPresent(const Path: String): Boolean;
begin
  if PathAbsent(Path) then
    Result := True
  else if IsReparsePath(Path) or (not FileExists(Path)) then
    Result := False
  else
    Result := DeleteFile(Path);
end;

function IsAllowedUninstallerName(const Name: String;
  const Extension: String): Boolean;
var
  LowerName: String;
  I: Integer;
begin
  LowerName := Lowercase(Name);
  Result := (Length(LowerName) > 9) and
    (Copy(LowerName, 1, 5) = 'unins') and
    (Copy(LowerName, Length(LowerName) - 3, 4) = Extension);
  if not Result then
    Exit;
  for I := 6 to Length(LowerName) - 4 do
    if Pos(LowerName[I], '0123456789') = 0 then
    begin
      Result := False;
      Exit;
    end;
end;

function ValidateLicenseDirectory(const Root: String;
  RequireFull: Boolean): Boolean;
var
  FindRec: TFindRec;
  InterFound: Boolean;
  PlexFound: Boolean;
  Path: String;
begin
  Result := False;
  InterFound := False;
  PlexFound := False;
  if IsReparsePath(Root) then
    Exit;
  if FindFirst(Root + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          Path := Root + '\' + FindRec.Name;
          if ((FindRec.Attributes and $10) <> 0) or IsReparsePath(Path) then
            Exit;
          if CompareText(FindRec.Name, 'LICENSE-Inter.txt') = 0 then
            InterFound := True
          else if CompareText(FindRec.Name,
            'LICENSE-IBMPlexMono.txt') = 0 then
            PlexFound := True
          else
            Exit;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  Result := (not RequireFull) or (InterFound and PlexFound);
end;

function ValidatePackageDirectory(const Root: String;
  RequireFull: Boolean): Boolean;
var
  FindRec: TFindRec;
  Path: String;
  Name: String;
  AppFound: Boolean;
  GuardFound: Boolean;
  IdentityFound: Boolean;
  LicenseFound: Boolean;
  VerifyFound: Boolean;
  NoticesFound: Boolean;
  LicensesFound: Boolean;
  UninstallerExeCount: Integer;
  UninstallerDatCount: Integer;
  UninstallerMsgCount: Integer;
  UninstallerExeBase: String;
  UninstallerDatBase: String;
  UninstallerMsgBase: String;
begin
  Result := False;
  if (not DirExists(Root)) or IsReparsePath(Root) then
    Exit;
  AppFound := False;
  GuardFound := False;
  IdentityFound := False;
  LicenseFound := False;
  VerifyFound := False;
  NoticesFound := False;
  LicensesFound := False;
  UninstallerExeCount := 0;
  UninstallerDatCount := 0;
  UninstallerMsgCount := 0;
  UninstallerExeBase := '';
  UninstallerDatBase := '';
  UninstallerMsgBase := '';
  if FindFirst(Root + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Name <> '.') and (FindRec.Name <> '..') then
        begin
          Name := FindRec.Name;
          Path := Root + '\' + Name;
          if IsReparsePath(Path) then
            Exit;
          if (FindRec.Attributes and $10) <> 0 then
          begin
            if (CompareText(Name, 'licenses') <> 0) or
               (not ValidateLicenseDirectory(Path, RequireFull)) then
              Exit;
            LicensesFound := True;
          end
          else if CompareText(Name, '{#ProductExe}') = 0 then
            AppFound := True
          else if CompareText(Name, '{#LifecycleGuardExe}') = 0 then
            GuardFound := True
          else if CompareText(Name, '{#InstallIdentityFile}') = 0 then
            IdentityFound := True
          else if CompareText(Name, 'LICENSE.md') = 0 then
            LicenseFound := True
          else if CompareText(Name, 'VERIFY.md') = 0 then
            VerifyFound := True
          else if CompareText(Name, 'THIRD-PARTY-NOTICES.md') = 0 then
            NoticesFound := True
          else if IsAllowedUninstallerName(Name, '.exe') then
          begin
            UninstallerExeCount := UninstallerExeCount + 1;
            UninstallerExeBase := Lowercase(
              Copy(Name, 1, Length(Name) - 4));
          end
          else if IsAllowedUninstallerName(Name, '.dat') then
          begin
            UninstallerDatCount := UninstallerDatCount + 1;
            UninstallerDatBase := Lowercase(
              Copy(Name, 1, Length(Name) - 4));
          end
          else if IsAllowedUninstallerName(Name, '.msg') then
          begin
            UninstallerMsgCount := UninstallerMsgCount + 1;
            UninstallerMsgBase := Lowercase(
              Copy(Name, 1, Length(Name) - 4));
          end
          else
            Exit;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  Result := (UninstallerExeCount <= 1) and
    (UninstallerDatCount <= 1) and (UninstallerMsgCount <= 1) and
    ((UninstallerExeCount = 0) or (UninstallerDatCount = 0) or
      (UninstallerExeBase = UninstallerDatBase)) and
    ((UninstallerExeCount = 0) or (UninstallerMsgCount = 0) or
      (UninstallerExeBase = UninstallerMsgBase)) and
    ((UninstallerDatCount = 0) or (UninstallerMsgCount = 0) or
      (UninstallerDatBase = UninstallerMsgBase)) and
    ((not RequireFull) or
      (AppFound and GuardFound and IdentityFound and LicenseFound and
       VerifyFound and NoticesFound and LicensesFound and
       (UninstallerExeCount = 1) and (UninstallerDatCount = 1)));
end;

function ValidatePackageTreeHash(const Root, ExpectedHash: String;
  RequireFull: Boolean): Boolean;
var
  AppPath: String;
  GuardPath: String;
begin
  if ExpectedHash = 'absent' then
  begin
    Result := PathAbsent(Root);
    Exit;
  end;
  Result := ValidatePackageDirectory(Root, RequireFull);
  if not Result then
    Exit;
  AppPath := Root + '\{#ProductExe}';
  GuardPath := Root + '\{#LifecycleGuardExe}';
  if FileExists(AppPath) then
    Result := FileMatchesSha256(AppPath, ExpectedHash);
  if Result and FileExists(GuardPath) then
    Result := FileMatchesSha256(GuardPath, ExpectedHash);
  if RequireFull then
    Result := Result and FileExists(AppPath) and FileExists(GuardPath);
end;

function RetireKnownLegacyBackups(): Boolean;
var
  LegacyBin: String;
begin
  LegacyBin := ExpandConstant('{localappdata}\Gilbreth\bin');
  Result := True;
  if LegacyAutostart then
  begin
    Result := RegWriteStringValue(HKCU,
      'Software\Microsoft\Windows\CurrentVersion\Run', 'Gilbreth',
      '"' + ExpandConstant('{app}\{#ProductExe}') + '"');
    if not Result then
      RegDeleteValue(HKCU,
        'Software\Microsoft\Windows\CurrentVersion\Run', 'Gilbreth');
  end;
  if LegacyAppMoved then
    Result := DeleteIfPresent(
      LegacyBin + '\gilbreth-app.exe.package-backup') and Result;
  if LegacyHelperMoved then
    Result := DeleteIfPresent(
      LegacyBin + '\gilbreth-elevated-record-helper.exe.package-backup') and Result;
  if LegacyStartMenuMoved then
    Result := DeleteIfPresent(ExpandConstant(
      '{userprograms}\Gilbreth.lnk.package-backup')) and Result;
  if LegacyDesktopMoved then
    Result := DeleteIfPresent(ExpandConstant(
      '{autodesktop}\Gilbreth.lnk.package-backup')) and Result;
  RemoveDir(LegacyBin); { succeeds only when no unknown files remain }
end;

function CleanupCommittedTransactionArtifacts(): Boolean;
var
  LegacyBin: String;
begin
  LegacyBin := ExpandConstant('{localappdata}\Gilbreth\bin');
  Result := True;
  if DirExists(BackupDir()) then
    Result := DelTree(BackupDir(), True, True, True) and Result;
  Result := DeleteIfPresent(
    LegacyBin + '\gilbreth-app.exe.package-backup') and Result;
  Result := DeleteIfPresent(
    LegacyBin + '\gilbreth-elevated-record-helper.exe.package-backup') and Result;
  Result := DeleteIfPresent(ExpandConstant(
    '{userprograms}\Gilbreth.lnk.package-backup')) and Result;
  Result := DeleteIfPresent(ExpandConstant(
    '{autodesktop}\Gilbreth.lnk.package-backup')) and Result;
  RemoveDir(LegacyBin);
end;

function ValidateCommittedTransactionArtifacts(const NewAppHash,
  OldAppHash: String): Boolean;
begin
  Result := ValidatePackageTreeHash(
    ExpandConstant('{app}'), NewAppHash, True);
  if not Result then
    Exit;
  if OldAppHash = 'absent' then
    Result := PathAbsent(BackupDir())
  else if PathAbsent(BackupDir()) then
    Result := True
  else if DirExists(BackupDir()) then
    Result := ValidatePackageTreeHash(BackupDir(), OldAppHash, False)
  else
    Result := False;
end;

procedure FinalizeInstallTransaction();
begin
  if InstallCommitted or (not PayloadVerified) then
    Exit;
  { Verification authenticated both payload copies and durably transitioned
    the marker before Inno processed shortcuts, registry values, or ARP. ssDone
    means those remaining installer operations also completed successfully, so
    finalization has no new failure gate after lifecycle metadata changed. }
  InstallCommitted := True;
  if not RetireKnownLegacyBackups() then
    Log('WARNING: verified install committed; legacy-backup cleanup is pending.');
  if CleanupCommittedTransactionArtifacts() then
  begin
    if not DeleteFile(TransactionCommittedMarkerPath()) then
      Log('WARNING: committed-cleanup marker retirement is pending.');
  end
  else
    Log('WARNING: committed cleanup will be retried by the next setup.');
end;

function InstallMetadataAllowed(): Boolean;
begin
  Result := TransactionPrepared and PayloadVerified and
    (not PayloadVerificationFailed);
end;

function ReleaseLifecycleForLaunch(): Boolean;
begin
  Result := InstallMetadataAllowed();
  if not Result then
    Exit;
  FinalizeInstallTransaction();
  Result := InstallCommitted;
  if not Result then
    Exit;
  ReleaseLifecycleLock();
end;

function MoveKnownFile(const SourcePath, BackupPath: String;
  var Moved: Boolean): Boolean;
begin
  Result := not FileExists(BackupPath);
  if (not Result) or (not FileExists(SourcePath)) then
    Exit;
  Result := RenameFile(SourcePath, BackupPath);
  Moved := Result;
end;

function ShortcutTargetsKnownGilbreth(const ShortcutPath, LegacyExe,
  PackagedExe: String): Boolean;
var
  Shell: Variant;
  Shortcut: Variant;
  Target: String;
begin
  Result := False;
  try
    Shell := CreateOleObject('WScript.Shell');
    Shortcut := Shell.CreateShortcut(ShortcutPath);
    Target := Shortcut.TargetPath;
    Result := (CompareText(Target, LegacyExe) = 0) or
      (CompareText(Target, PackagedExe) = 0);
  except
    Log('Could not inspect an existing Gilbreth-named shortcut.');
  end;
end;

procedure RestoreKnownFile(const SourcePath, BackupPath: String;
  var Moved: Boolean);
begin
  if not Moved then
    Exit;
  DeleteFile(SourcePath);
  if RenameFile(BackupPath, SourcePath) then
    Moved := False
  else
    Log('ERROR: failed to restore a known legacy development artifact.');
end;

function PrepareKnownLegacyDevInstall(): Boolean;
var
  LegacyBin: String;
  StartMenuLink: String;
  DesktopLink: String;
  LegacyExe: String;
  PackagedExe: String;
  MoveDesktop: Boolean;
  RunValue: String;
  LegacyCommand: String;
begin
  LegacyBin := ExpandConstant('{localappdata}\Gilbreth\bin');
  StartMenuLink := ExpandConstant('{userprograms}\Gilbreth.lnk');
  DesktopLink := ExpandConstant('{autodesktop}\Gilbreth.lnk');
  LegacyExe := LegacyBin + '\gilbreth-app.exe';
  PackagedExe := ExpandConstant('{app}\{#ProductExe}');
  if FileExists(StartMenuLink) and
     (not ShortcutTargetsKnownGilbreth(
       StartMenuLink, LegacyExe, PackagedExe)) then
  begin
    Result := False;
    Exit;
  end;
  MoveDesktop := (not FileExists(DesktopLink)) or
    ShortcutTargetsKnownGilbreth(DesktopLink, LegacyExe, PackagedExe);
  if (not MoveDesktop) and WizardIsTaskSelected('desktopicon') then
  begin
    Result := False;
    Exit;
  end;
  Result :=
    MoveKnownFile(LegacyBin + '\gilbreth-app.exe',
      LegacyBin + '\gilbreth-app.exe.package-backup', LegacyAppMoved) and
    MoveKnownFile(LegacyBin + '\gilbreth-elevated-record-helper.exe',
      LegacyBin + '\gilbreth-elevated-record-helper.exe.package-backup',
      LegacyHelperMoved) and
    MoveKnownFile(StartMenuLink, StartMenuLink + '.package-backup',
      LegacyStartMenuMoved);
  if Result and MoveDesktop then
    Result := MoveKnownFile(DesktopLink, DesktopLink + '.package-backup',
      LegacyDesktopMoved);
  if not Result then
    Exit;

  LegacyAutostart := False;
  if RegQueryStringValue(HKCU,
    'Software\Microsoft\Windows\CurrentVersion\Run', 'Gilbreth', RunValue) then
  begin
    LegacyCommand := '"' + LegacyBin + '\gilbreth-app.exe"';
    LegacyAutostart :=
      (CompareText(RunValue, LegacyCommand) = 0) or
      (CompareText(RunValue, LegacyBin + '\gilbreth-app.exe') = 0);
  end;
end;

procedure RestoreKnownLegacyDevInstall();
var
  LegacyBin: String;
  StartMenuLink: String;
  DesktopLink: String;
begin
  LegacyBin := ExpandConstant('{localappdata}\Gilbreth\bin');
  StartMenuLink := ExpandConstant('{userprograms}\Gilbreth.lnk');
  DesktopLink := ExpandConstant('{autodesktop}\Gilbreth.lnk');
  RestoreKnownFile(LegacyBin + '\gilbreth-app.exe',
    LegacyBin + '\gilbreth-app.exe.package-backup', LegacyAppMoved);
  RestoreKnownFile(LegacyBin + '\gilbreth-elevated-record-helper.exe',
    LegacyBin + '\gilbreth-elevated-record-helper.exe.package-backup',
    LegacyHelperMoved);
  RestoreKnownFile(StartMenuLink, StartMenuLink + '.package-backup',
    LegacyStartMenuMoved);
  RestoreKnownFile(DesktopLink, DesktopLink + '.package-backup',
    LegacyDesktopMoved);
end;

function RecoverKnownFile(const SourcePath, BackupPath: String): Boolean;
begin
  if not FileExists(BackupPath) then
  begin
    Result := True;
    Exit;
  end;
  Result := (not FileExists(SourcePath)) and RenameFile(BackupPath, SourcePath);
end;

function RecoverInProgressTransactionArtifacts(const NewAppHash,
  OldAppHash: String): Boolean;
var
  AppDir: String;
  LegacyBin: String;
  PreMutationState: Boolean;
begin
  AppDir := ExpandConstant('{app}');
  LegacyBin := ExpandConstant('{localappdata}\Gilbreth\bin');

  { The durable marker is intentionally written before the first mutation.
    A power loss can therefore leave the complete old package in place and no
    backup directory. That is already a safely rolled-back state. }
  PreMutationState := PathAbsent(BackupDir()) and
    (((OldAppHash = 'absent') and (not DirExists(AppDir))) or
     ((OldAppHash <> 'absent') and
      ValidatePackageTreeHash(AppDir, OldAppHash, True)));
  if PreMutationState then
    Result := True
  else
    Result := ((not DirExists(AppDir)) or
      ValidatePackageTreeHash(AppDir, NewAppHash, False)) and
      ValidatePackageTreeHash(BackupDir(), OldAppHash, True);
  if not Result then
    Exit;

  if not PreMutationState then
  begin
    if DirExists(AppDir) then
      Result := DelTree(AppDir, True, True, True);
    if Result and DirExists(BackupDir()) then
      Result := RenameFile(BackupDir(), AppDir);
  end;
  if Result then
    Result := RecoverKnownFile(LegacyBin + '\gilbreth-app.exe',
      LegacyBin + '\gilbreth-app.exe.package-backup');
  if Result then
    Result := RecoverKnownFile(LegacyBin +
      '\gilbreth-elevated-record-helper.exe', LegacyBin +
      '\gilbreth-elevated-record-helper.exe.package-backup');
  if Result then
    Result := RecoverKnownFile(ExpandConstant('{userprograms}\Gilbreth.lnk'),
      ExpandConstant('{userprograms}\Gilbreth.lnk.package-backup'));
  if Result then
    Result := RecoverKnownFile(ExpandConstant('{autodesktop}\Gilbreth.lnk'),
      ExpandConstant('{autodesktop}\Gilbreth.lnk.package-backup'));
  if Result then
    Result := DeleteIfPresent(TransactionInProgressMarkerPath()) and
      DeleteIfPresent(TransactionCommittedMarkerPath());
end;

function RunCheck(const ExePath, Arguments, LabelText: String): Boolean;
var
  ExitCode: Integer;
begin
  Log(LabelText + ': ' + ExePath + ' ' + Arguments);
  Result := Exec(ExePath, Arguments, '', SW_HIDE, ewWaitUntilTerminated, ExitCode);
  if not Result then
  begin
    Log(LabelText + ' could not be started.');
    Exit;
  end;
  Result := ExitCode = 0;
  if not Result then
    Log(LabelText + ' failed with exit code ' + IntToStr(ExitCode) + '.');
end;

function RunPackageSelfCheck(const ExePath: String): Boolean;
begin
  Result := RunCheck(ExePath,
    '--package-self-check --expect-version ' + Q('{#AppVersion}') +
    ' --expect-git-sha ' + Q('{#SourceGitSha}'), 'package self-check');
end;

function RunLifecyclePreflight(const ExePath: String): Boolean;
begin
  Result := RunCheck(
    ExePath,
    '--lifecycle-preflight --install-root ' + Q(ExpandConstant('{app}')),
    'lifecycle preflight');
end;

function RunUninstallLifecyclePreflight(const ExePath: String;
  InstallerLockHeld: Boolean): Boolean;
var
  Arguments: String;
begin
  Arguments := '--uninstall-lifecycle-preflight --install-root ' +
    Q(ExpandConstant('{app}')) + '{#UnsignedAuthorityArg}';
  if InstallerLockHeld then
    Arguments := Arguments + ' --installer-lock-held';
  Result := RunCheck(ExePath, Arguments, 'uninstall lifecycle preflight');
end;

function RunIdentityAndLifecycleChecks(const ExePath: String): Boolean;
begin
  Result := RunPackageSelfCheck(ExePath);
  if Result then
    Result := RunLifecyclePreflight(ExePath);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  AppDir: String;
  OldDir: String;
  PreflightExe: String;
  MarkerNewHash: String;
  MarkerOldHash: String;
  ExistingAppHash: String;
  ExistingGuardHash: String;
  LifecycleLockAbsentBeforePreflight: Boolean;
  PreflightPassed: Boolean;
begin
  Result := '';
  AppDir := ExpandConstant('{app}');
  OldDir := BackupDir();

  LifecycleLockAbsentBeforePreflight := PathAbsent(LifecycleLockPath());
  ExtractTemporaryFile('gilbreth-preflight.exe');
  PreflightExe := ExpandConstant('{tmp}\gilbreth-preflight.exe');
  PreflightPassed := FileMatchesSha256(
    PreflightExe, Lowercase('{#ExpectedAppSha256}'));
  if PreflightPassed then
    PreflightPassed := RunIdentityAndLifecycleChecks(PreflightExe);
  if LifecycleLockAbsentBeforePreflight and
     FileExists(LifecycleLockPath()) and
     (not IsReparsePath(LifecycleLockPath())) then
    LifecycleLockCreated := True;
  if not PreflightPassed then
  begin
    Result := 'Gilbreth cannot be replaced safely. Close every Gilbreth tray and dashboard process in every signed-in Windows session, then retry.';
    Exit;
  end;

  { The Rust preflight proves the state at one instant. Retain this exclusive
    cross-session sentinel until commit/rollback so no tray or dashboard can
    enter after that probe and race program replacement. }
  if not AcquireLifecycleLock() then
  begin
    Result := 'Gilbreth began running after the lifecycle preflight. Close every Gilbreth process in every signed-in Windows session, then retry.';
    Exit;
  end;
  if (not PathAbsent(TransactionMarkerTempPath())) and
     (IsReparsePath(TransactionMarkerTempPath()) or
      (not FileExists(TransactionMarkerTempPath())) or
      (not DeleteFile(TransactionMarkerTempPath()))) then
  begin
    Result := 'A stale Gilbreth transaction-marker temporary path cannot be retired safely. Close programs using it, then retry.';
    Exit;
  end;
  if DirExists(TransactionInProgressMarkerPath()) or
     DirExists(TransactionCommittedMarkerPath()) then
  begin
    Result := 'The Gilbreth transaction marker is not a regular file. Setup will not alter it.';
    Exit;
  end;
  if FileExists(TransactionCommittedMarkerPath()) and
     (not FileExists(TransactionInProgressMarkerPath())) and
     ReadTransactionMarker(TransactionCommittedMarkerPath(),
       MarkerNewHash, MarkerOldHash) then
  begin
    if (not ValidateCommittedTransactionArtifacts(
         MarkerNewHash, MarkerOldHash)) or
       (not CleanupCommittedTransactionArtifacts()) or
       (not DeleteFile(TransactionCommittedMarkerPath())) then
    begin
      Result := 'A committed Gilbreth cleanup is still locked. Close scanners or other programs using the prior package files, then retry.';
      Exit;
    end;
  end;
  if FileExists(TransactionInProgressMarkerPath()) and
     (not FileExists(TransactionCommittedMarkerPath())) and
     ReadTransactionMarker(TransactionInProgressMarkerPath(),
       MarkerNewHash, MarkerOldHash) then
  begin
    if not RecoverInProgressTransactionArtifacts(
      MarkerNewHash, MarkerOldHash) then
    begin
      Result := 'An interrupted or ambiguous Gilbreth transaction could not be restored safely. Close programs using the package files, then retry.';
      Exit;
    end;
  end;
  if FileExists(TransactionInProgressMarkerPath()) or
     FileExists(TransactionCommittedMarkerPath()) then
  begin
    Result := 'Gilbreth transaction state is ambiguous or unauthenticated. Setup will not alter program files.';
    Exit;
  end;
  if not PathAbsent(OldDir) then
  begin
    Result := 'An uncommitted Gilbreth transaction backup still exists at ' + OldDir + '. Setup will not overwrite it.';
    Exit;
  end;
  ExistingAppHash := 'absent';
  if DirExists(AppDir) then
  begin
    if (not ValidatePackageDirectory(AppDir, True)) or
       (not TryGetFileSha256(
         AppDir + '\{#ProductExe}', ExistingAppHash)) or
       (not TryGetFileSha256(
         AppDir + '\{#LifecycleGuardExe}', ExistingGuardHash)) or
       (CompareText(ExistingAppHash, ExistingGuardHash) <> 0) then
    begin
      Result := 'The installed Gilbreth package inventory is not exact. Repair or remove unexpected program files before updating.';
      Exit;
    end;
    ExistingAppHash := ExistingGuardHash;
  end;
  if (not WriteInProgressMarker(ExistingAppHash)) or
     (not HasValidInProgressMarker()) then
  begin
    DeleteFile(TransactionInProgressMarkerPath());
    DeleteFile(TransactionMarkerTempPath());
    Result := 'Setup could not durably prepare its rollback marker. No replacement was attempted.';
    Exit;
  end;
  TransactionPrepared := True;
  TransactionOldAppHash := ExistingAppHash;
  if not PrepareKnownLegacyDevInstall() then
  begin
    RestoreKnownLegacyDevInstall();
    Result := 'Setup could not preserve the known legacy development files and shortcuts. No replacement was attempted.';
    Exit;
  end;

  if DirExists(AppDir) then
  begin
    if not RenameFile(AppDir, OldDir) then
    begin
      Result := 'Setup could not preserve the current Gilbreth program directory. No replacement was attempted.';
      Exit;
    end;
    BackupCreated := True;
    Log('Preserved previous program directory at ' + OldDir + '.');
  end;
end;

function VerifyInstalledProgram(): Boolean;
var
  InstalledExe: String;
  GuardExe: String;
  ActualHash: String;
begin
  InstalledExe := ExpandConstant('{app}\{#ProductExe}');
  GuardExe := ExpandConstant('{app}\{#LifecycleGuardExe}');
  Result := ValidatePackageTreeHash(
    ExpandConstant('{app}'), Lowercase('{#ExpectedAppSha256}'), True) and
    FileExists(InstalledExe);
  if not Result then
    Exit;

  Result := TryGetFileSha256(InstalledExe, ActualHash) and
    (CompareText(ActualHash, Lowercase('{#ExpectedAppSha256}')) = 0);
  if not Result then
  begin
    Log('Installed app SHA-256 mismatch.');
    Exit;
  end;

  Result := RunPackageSelfCheck(InstalledExe) and
    FileMatchesSha256(GuardExe, Lowercase('{#ExpectedAppSha256}')) and
    RunPackageSelfCheck(GuardExe);
end;

function TransitionInstallTransactionToCommitted(): Boolean;
var
  NewAppHash: String;
  OldAppHash: String;
  CommittedNewAppHash: String;
  CommittedOldAppHash: String;
begin
  Result := False;
  if FileExists(TransactionCommittedMarkerPath()) or
     (not ReadTransactionMarker(TransactionInProgressMarkerPath(),
       NewAppHash, OldAppHash)) or
     (CompareText(NewAppHash, Lowercase('{#ExpectedAppSha256}')) <> 0) then
    Exit;
  if OldAppHash = 'absent' then
  begin
    if not PathAbsent(BackupDir()) then
      Exit;
  end
  else if not ValidatePackageTreeHash(BackupDir(), OldAppHash, True) then
    Exit;

  { MOVEFILE_WRITE_THROUGH makes the same-directory state transition durable
    before Setup can advance beyond Inno's native file rollback window. }
  if not PackageMoveFileEx(TransactionInProgressMarkerPath(),
       TransactionCommittedMarkerPath(), $8) then
    Exit;
  Result := (not FileExists(TransactionInProgressMarkerPath())) and
    ReadTransactionMarker(TransactionCommittedMarkerPath(),
      CommittedNewAppHash, CommittedOldAppHash) and
    (CompareText(CommittedNewAppHash, NewAppHash) = 0) and
    (CompareText(CommittedOldAppHash, OldAppHash) = 0);
end;

function HasExpectedPayloadHash(const Path: String): Boolean;
begin
  Result := FileMatchesSha256(Path, Lowercase('{#ExpectedAppSha256}'));
end;

procedure VerifyPayloadInsideInstallTransaction();
begin
  PayloadVerified := False;
  try
    if HasExactParam('/FORCEVERIFYFAIL') then
    begin
      PayloadVerificationFailed := True;
      Log('ERROR: forced post-copy verification failure requested. Setup will restore the previous program files.');
      Exit;
    end;
    if not VerifyInstalledProgram() then
    begin
      PayloadVerificationFailed := True;
      Log('ERROR: the installed Gilbreth payload did not verify. Setup will restore the previous program files.');
      Exit;
    end;
    if not TransitionInstallTransactionToCommitted() then
    begin
      PayloadVerificationFailed := True;
      Log('ERROR: the durable Gilbreth transaction marker did not verify. Setup will restore the previous program files.');
      Exit;
    end;
    PayloadVerified := True;
  except
    PayloadVerified := False;
    PayloadVerificationFailed := True;
    Log('ERROR: post-copy verification raised an exception: ' +
      GetExceptionMessage() + '. Setup will restore the previous program files.');
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssDone then
  begin
    if PayloadVerified then
      FinalizeInstallTransaction()
    else if TransactionPrepared and (not PayloadVerificationFailed) then
    begin
      PayloadVerificationFailed := True;
      Log('ERROR: post-copy verification did not complete. Setup will restore the previous program files.');
    end;
  end;
end;

function GetCustomSetupExitCode(): Integer;
begin
  if PayloadVerificationFailed or
     (TransactionPrepared and (not PayloadVerified)) then
    Result := 4
  else
    Result := 0;
end;

function ValidateRolledBackTransactionState(): Boolean;
var
  AppDir: String;
begin
  if not TransactionPrepared then
  begin
    Result := False;
    Exit;
  end;
  AppDir := ExpandConstant('{app}');
  if TransactionOldAppHash = 'absent' then
    Result := PathAbsent(AppDir) and PathAbsent(BackupDir())
  else
    Result := ValidatePackageTreeHash(
      AppDir, TransactionOldAppHash, True) and PathAbsent(BackupDir());
end;

procedure DeinitializeSetup();
var
  AppDir: String;
  RollbackComplete: Boolean;
  RemoveCreatedLifecycleLock: Boolean;
begin
  RollbackComplete := False;
  AppDir := ExpandConstant('{app}');
  if BackupCreated and (not InstallCommitted) then
  begin
    if (not IsReparsePath(AppDir)) and
       DelTree(AppDir, True, True, True) and
       RenameFile(BackupDir(), AppDir) then
    begin
      BackupCreated := False;
      Log('Restored the previous Gilbreth program directory.');
    end
    else
      Log('ERROR: failed to restore the previous Gilbreth program directory from ' + BackupDir() + '.');
  end;
  if (not InstallCommitted) and TransactionPrepared and
     (TransactionOldAppHash = 'absent') and (not PathAbsent(AppDir)) then
  begin
    if DirExists(AppDir) and (not IsReparsePath(AppDir)) and
       DelTree(AppDir, True, True, True) then
      Log('Removed the uncommitted Gilbreth program directory.')
    else
      Log('ERROR: failed to remove the uncommitted Gilbreth program directory.');
  end;
  if not InstallCommitted then
  begin
    RestoreKnownLegacyDevInstall();
    RollbackComplete := TransactionPrepared and
      (not BackupCreated) and (not LegacyAppMoved) and
      (not LegacyHelperMoved) and (not LegacyStartMenuMoved) and
      (not LegacyDesktopMoved) and ValidateRolledBackTransactionState();
    if RollbackComplete then
    begin
      if not DeleteIfPresent(TransactionInProgressMarkerPath()) then
        Log('ERROR: rollback completed but its in-progress marker could not be retired.');
      if not DeleteIfPresent(TransactionCommittedMarkerPath()) then
        Log('ERROR: rollback completed but its committed marker could not be retired.');
      if not DeleteIfPresent(TransactionMarkerTempPath()) then
        Log('ERROR: rollback completed but its temporary marker could not be retired.');
    end;
  end;
  RemoveCreatedLifecycleLock := LifecycleLockCreated and
    (not InstallCommitted) and
    ((not TransactionPrepared) or RollbackComplete);
  ReleaseLifecycleLock();
  if RemoveCreatedLifecycleLock then
  begin
    if DeleteIfPresent(LifecycleLockPath()) then
      LifecycleLockCreated := False
    else
      Log('ERROR: failed to retire the lifecycle lock created by the failed setup.');
  end;
end;

function InitializeUninstall(): Boolean;
var
  InstalledExe: String;
  GuardExe: String;
  ReceiptDir: String;
  MarkerNewHash: String;
  MarkerOldHash: String;
begin
  Result := False;
  InstalledExe := ExpandConstant('{app}\{#ProductExe}');
  GuardExe := ExpandConstant('{app}\{#LifecycleGuardExe}');
  if (not HasExpectedPayloadHash(GuardExe)) or
     (not RunUninstallLifecyclePreflight(GuardExe, False)) then
  begin
    if not UninstallSilent() then
      MsgBox('The installed Gilbreth lifecycle guard is missing, untrusted, or detected a live product process. Close Gilbreth in every signed-in session. If the guard is damaged, preserve the separate data root and use supported manual package cleanup before reinstalling.', mbError, MB_OK);
    Exit;
  end;

  if not AcquireLifecycleLock() then
  begin
    if not UninstallSilent() then
      MsgBox('Gilbreth began running after the lifecycle preflight. Close every Gilbreth process in every signed-in Windows session, then retry.', mbError, MB_OK);
    Exit;
  end;

  if (not PathAbsent(TransactionMarkerTempPath())) or
     IsReparsePath(TransactionInProgressMarkerPath()) or
     IsReparsePath(TransactionCommittedMarkerPath()) or
     DirExists(TransactionInProgressMarkerPath()) or
     DirExists(TransactionCommittedMarkerPath()) or
     (FileExists(TransactionInProgressMarkerPath()) and
      (not HasValidInProgressMarker())) or
     (FileExists(TransactionCommittedMarkerPath()) and
      (not HasValidCommittedMarker())) or
     (FileExists(TransactionInProgressMarkerPath()) and
      FileExists(TransactionCommittedMarkerPath())) then
  begin
    if not UninstallSilent() then
      MsgBox('The Gilbreth transaction marker is invalid. Repair by reinstalling before uninstalling.', mbError, MB_OK);
    Exit;
  end;
  if FileExists(TransactionInProgressMarkerPath()) then
  begin
    if not UninstallSilent() then
      MsgBox('An interrupted Gilbreth install must be repaired by rerunning Setup before uninstalling.', mbError, MB_OK);
    Exit;
  end;
  if FileExists(TransactionCommittedMarkerPath()) then
  begin
    if (not ReadTransactionMarker(TransactionCommittedMarkerPath(),
         MarkerNewHash, MarkerOldHash)) or
       (CompareText(MarkerNewHash, Lowercase('{#ExpectedAppSha256}')) <> 0) or
       (not ValidateCommittedTransactionArtifacts(
         MarkerNewHash, MarkerOldHash)) or
       (not CleanupCommittedTransactionArtifacts()) or
       (not DeleteFile(TransactionCommittedMarkerPath())) then
    begin
      if not UninstallSilent() then
        MsgBox('A committed Gilbreth backup is still locked. Close scanners or other programs using it, then retry.', mbError, MB_OK);
      Exit;
    end;
  end;
  if not PathAbsent(BackupDir()) then
  begin
    if not UninstallSilent() then
      MsgBox('An uncommitted Gilbreth rollback directory remains. Reinstall or recover it before uninstalling.', mbError, MB_OK);
    Exit;
  end;

  PurgeCapable := HasExpectedPayloadHash(InstalledExe);
  PurgeRequested := HasExactParam('/PURGEDATA');
  if PurgeRequested and (not PurgeCapable) then
  begin
    if not UninstallSilent() then
      MsgBox('The installed app is unavailable, so destructive data removal cannot be authenticated. Run keep-data uninstall or repair Setup first.', mbError, MB_OK);
    Exit;
  end;
  if PurgeCapable and (not PurgeRequested) and (not UninstallSilent()) then
    PurgeRequested := SuppressibleMsgBox(
      'Also remove Gilbreth user data? This deletes known data classes under %LOCALAPPDATA%\Gilbreth. Exports outside that directory remain. The default is No.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;

  if PurgeRequested then
  begin
    ReceiptDir := ExpandConstant('{localappdata}\Gilbreth-uninstall-receipts');
    if (not ForceDirectories(ReceiptDir)) or IsReparsePath(ReceiptDir) then
      Exit;
    PurgeReceiptPath := NewPurgeReceiptPath(ReceiptDir);
    if PurgeReceiptPath = '' then
      Exit;
  end;

  Result := True;
end;

procedure DeinitializeUninstall();
begin
  ReleaseLifecycleLock();
  DeleteFile(LifecycleLockPath());
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  InstalledExe: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    if PurgeRequested then
    begin
      InstalledExe := ExpandConstant('{app}\{#ProductExe}');
      if (not HasExpectedPayloadHash(InstalledExe)) or
         (not RunCheck(
        InstalledExe,
        '--uninstall-purge --receipt ' + Q(PurgeReceiptPath) +
          ' --installer-lock-held{#UnsignedAuthorityArg}',
        'offline uninstall purge')) then
        RaiseException(
          'Gilbreth data removal did not complete. Program uninstall was stopped; inspect the content-free receipt at ' + PurgeReceiptPath + '.');
    end;
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Gilbreth');
  end;
end;
