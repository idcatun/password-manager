; ===========================================================================
; SecureVault.iss – Inno Setup Script
;
; This creates a Windows installer (.exe) that:
;   - Bundles the SecureVault.exe (built with build_windows.bat)
;   - Installs it to Program Files
;   - Creates a Start Menu shortcut
;   - Creates a desktop shortcut (optional)
;   - Adds an uninstaller
;
; To compile:
;   Download Inno Setup from https://jrsoftware.org/isinfo.php
;   Open this file in Inno Setup Compiler and press Compile (Ctrl+F9)
;   Output: Output\SecureVaultSetup.exe
;
; Run build_windows.bat FIRST to produce SecureVault.exe, then compile this.
; ===========================================================================

#define MyAppName      "SecureVault"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "SecureVault"
#define MyAppExeName   "SecureVault.exe"
#define MyAppURL       ""

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=Output
OutputBaseFilename=SecureVaultSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; The main exe produced by build_windows.bat (OCRA bundle)
Source: "{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";       Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent
