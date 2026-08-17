from enum import Enum
from pymobiledevice3.lockdown import LockdownClient

# Builds supported by the on-device "mond" exploit (https://github.com/rooootdev/mond).
# mond edits MobileGestalt and PosterBoard from the device itself, and works on
# iOS 27.0 dev beta 1-4 / public beta 1-2. It is patched from dev beta 5 / public beta 3.
#   24A5355q = iOS 27.0 dev beta 1 (June 8, 2026)
#   24A5370h = iOS 27.0 dev beta 2 / public beta 1 (June 22, 2026)
#   24A5380h = iOS 27.0 dev beta 3 / public beta 2 (July 6, 2026)
#   24A5390f = iOS 27.0 dev beta 4 (July 20, 2026)
# Patched builds: 24A5408d (dev beta 5 / public beta 3), 24A5418b (dev beta 6) and newer.
MOND_SUPPORTED_BUILDS: frozenset[str] = frozenset((
    "24A5355q",  # dev beta 1
    "24A5370h",  # dev beta 2 / public beta 1
    "24A5380h",  # dev beta 3 / public beta 2
    "24A5390f",  # dev beta 4
))

class Device:
    def __init__(self, 
                udid: int, usb: bool, name: str,
                version: str, build: str,
                model: str, hardware: str, cpu: str, locale: str,
                books_container_uuid: str,
                ld: LockdownClient
            ):
        self.udid = udid
        self.connected_via_usb = usb
        self.name = name
        self.version = version
        self.build = build
        self.model = model
        self.hardware = hardware
        self.cpu = cpu
        self.locale = locale
        self.books_container_uuid = books_container_uuid
        self.ld = ld

    def is_exploit_fully_patched(self) -> bool:
        # mobile gestalt methods are completely patched on iOS 26.2 beta 2+
        # iOS 27.0+ patched both Sparserestore and BookRestore via:
        #   - RestoreAttestationMode upgrade (2 -> 6)
        #   - Path traversal validation in backup domain names
        #   - New trust caches with stricter security policies
        #   - SEP and iBoot security hardening
        return not (self.has_bookrestore() or self.has_partial_sparserestore())
    
    def has_bookrestore(self) -> bool:
        parsed_ver: Version = Version(self.version)
        # BookRestore gap between sparserestore and bookrestore eras
        if (parsed_ver >= Version("18.7.5") and parsed_ver < Version("26.0")):
            return False
        # BookRestore works on iOS 18.2 - 26.1
        # Patched in iOS 26.2+ (RestoreAttestationMode change, path validation)
        if (parsed_ver <= Version("26.1") or self.build == "23C5027f"):
            return True
        return False
    
    def has_partial_sparserestore(self) -> bool:
        parsed_ver: Version = Version(self.version)
        # Sparserestore works on iOS 17.0 - 18.1.1
        if (parsed_ver < Version("18.2")
            or self.build == "22C5109p" or self.build == "22C5125e"):
            return True
        return False

    def has_exploit(self) -> bool:
        parsed_ver: Version = Version(self.version)
        # make sure versions past 17.7.1 but before 18.0 aren't supported
        if (parsed_ver >= Version("17.7.1") and parsed_ver < Version("18.0")):
            return False
        if (parsed_ver < Version("18.1")
            or self.build == "22B5007p" or self.build == "22B5023e"
            or self.build == "22B5034e" or self.build == "22B5045g"):
            return True
        return False

    def supported(self) -> bool:
        return self.has_exploit()

    def has_mond_support(self) -> bool:
        """Whether the on-device mond exploit supports this build.

        mond (https://github.com/rooootdev/mond) is a sideloaded iOS app that
        edits MobileGestalt and PosterBoard on-device. It works on iOS 27.0
        dev beta 1-4 / public beta 1-2 only. This desktop tool cannot use it;
        it is only relevant as an alternative for iOS 27 devices.
        """
        parsed_ver: Version = Version(self.version)
        return parsed_ver == Version("27.0") and self.build in MOND_SUPPORTED_BUILDS

    def get_mond_advice(self) -> str:
        """Human-readable advice about the on-device mond exploit for this build."""
        parsed_ver: Version = Version(self.version)
        if parsed_ver < Version("27.0"):
            return ""
        if self.has_mond_support():
            return ("Your build ({build}) is supported by the on-device mond app "
                    "(https://github.com/rooootdev/mond), which can edit MobileGestalt "
                    "and PosterBoard from the device itself. This desktop tool cannot "
                    "apply tweaks on any iOS 27.0 build.").format(build=self.build)
        return ("Your build ({build}) is not supported by the on-device mond app either: "
                "the exploit was patched from iOS 27.0 dev beta 5 / public beta 3 "
                "(build 24A5408d and newer).").format(build=self.build)

    def get_patched_reason(self) -> str:
        """Returns a human-readable explanation of why the exploit is patched on this version."""
        parsed_ver: Version = Version(self.version)
        if parsed_ver >= Version("27.0"):
            reason = ("iOS 27.0+ has patched both Sparserestore and BookRestore exploits.\n\n"
                    "Apple changed RestoreAttestationMode from 2 to 6, adding path traversal "
                    "validation in backup domain names, new trust caches with stricter security "
                    "policies, and SEP/iBoot security hardening.\n\n"
                    "This desktop tool cannot apply tweaks on iOS 27.0. However, an on-device "
                    "exploit for MobileGestalt and PosterBoard was found and released as the "
                    "mond app (https://github.com/rooootdev/mond), which supports iOS 27.0 "
                    "dev beta 1-4 / public beta 1-2.")
            if self.has_mond_support():
                reason += "\n\nYour build (" + self.build + ") is supported by mond."
            else:
                reason += "\n\nYour build (" + self.build + ") is not supported by mond " \
                           "(patched from dev beta 5 / public beta 3)."
            return reason
        elif parsed_ver >= Version("26.2"):
            return ("iOS 26.2+ has patched Mobile Gestalt and AI Enabler tweaks.\n\n"
                    "BookRestore still works for Feature Flags, PosterBoard, and other tweaks.")
        elif parsed_ver >= Version("18.2") and parsed_ver <= Version("18.7.4"):
            return ("This iOS version is in the gap between Sparserestore and BookRestore eras.\n\n"
                    "Neither exploit method is available for this version.")
        elif parsed_ver >= Version("17.7.1") and parsed_ver < Version("18.0"):
            return ("iOS 17.7.1 - 17.x is not supported.\n\n"
                    "Sparserestore was patched and BookRestore was not yet available.")
        return ""

class Version:
    def __init__(self, major: int, minor: int = 0, patch: int = 0):
        self.major = major
        self.minor = minor
        self.patch = patch

    def __init__(self, ver: str):
        nums: list[str] = ver.split(".")
        self.major = int(nums[0])
        self.minor = int(nums[1]) if len(nums) > 1 else 0
        self.patch = int(nums[2]) if len(nums) > 2 else 0

    # Comparison Functions
    def compare_to(self, other) -> int:
        if self.major > other.major:
            return 1
        elif self.major < other.major:
            return -1
        if self.minor > other.minor:
            return 1
        elif self.minor < other.minor:
            return -1
        if self.patch > other.patch:
            return 1
        elif self.patch < other.patch:
            return -1
        return 0
        
    def __gt__(self, other) -> bool:
        return self.compare_to(other) == 1
    def __ge__(self, other) -> bool:
        comp: int = self.compare_to(other)
        return comp == 0 or comp == 1
    
    def __lt__(self, other) -> bool:
        return self.compare_to(other) == -1
    def __le__(self, other) -> bool:
        comp: int = self.compare_to(other)
        return comp == 0 or comp == -1
    
    def __eq__(self, other) -> bool:
        return self.compare_to(other) == 0
    
class Tweak(Enum):
    StatusBar = 'Status Bar'
    SpringboardOptions = 'SpringBoard Options'
    InternalOptions = 'Internal Options'
    SkipSetup = 'Setup Options'

class FileLocation(Enum):
    # Control Center
    mute = "ControlCenter/ManagedPreferencesDomain/mobile/com.apple.control-center.MuteModule.plist"
    focus = "ControlCenter/ManagedPreferencesDomain/mobile/com.apple.FocusUIModule.plist"
    spoken = "ControlCenter/ManagedPreferencesDomain/mobile/com.apple.siri.SpokenNotificationsModule.plist"
    module_config = "ControlCenter/HomeDomain/Library/ControlCenter/ModuleConfiguration.plist"
    replay_kit_audio = "ControlCenter/ManagedPreferencesDomain/mobile/com.apple.replaykit.AudioConferenceControlCenterModule.plist"
    replay_kit_video = "ControlCenter/ManagedPreferencesDomain/mobile/com.apple.replaykit.VideoConferenceControlCenterModule.plist"

    # Status Bar
    status_bar = "StatusBar/HomeDomain/Library/SpringBoard/statusBarOverrides"
    
    # SpringBoard Options
    springboard = "SpringboardOptions/ManagedPreferencesDomain/mobile/com.apple.springboard.plist"
    footnote = "SpringboardOptions/ConfigProfileDomain/Library/ConfigurationProfiles/SharedDeviceConfiguration.plist"
    wifi = "SpringboardOptions/SystemPreferencesDomain/SystemConfiguration/com.apple.wifi.plist"
    uikit = "SpringboardOptions/ManagedPreferencesDomain/mobile/com.apple.UIKit.plist"
    accessibility = "SpringboardOptions/ManagedPreferencesDomain/mobile/com.apple.Accessibility.plist"
    wifi_debug = "SpringboardOptions/ManagedPreferencesDomain/mobile/com.apple.MobileWiFi.debug.plist"
    airdrop = "SpringboardOptions/ManagedPreferencesDomain/mobile/com.apple.sharingd.plist"
    
    # Internal Options
    global_prefs = "InternalOptions/ManagedPreferencesDomain/mobile/hiddendotGlobalPreferences.plist"
    app_store = "InternalOptions/ManagedPreferencesDomain/mobile/com.apple.AppStore.plist"
    backboardd = "InternalOptions/ManagedPreferencesDomain/mobile/com.apple.backboardd.plist"
    core_motion = "InternalOptions/ManagedPreferencesDomain/mobile/com.apple.CoreMotion.plist"
    pasteboard = "InternalOptions/HomeDomain/Library/Preferences/com.apple.Pasteboard.plist"
    notes = "InternalOptions/ManagedPreferencesDomain/mobile/com.apple.mobilenotes.plist"
    maps = "InternalOptions/AppDomain-com.apple.Maps/Library/Preferences/com.apple.Maps.plist"
    weather = "InternalOptions/AppDomain-com.apple.weather/Library/Preferences/com.apple.weather.plist"
    
    # Setup Options
    cloud_config = "SkipSetup/ConfigProfileDomain/Library/ConfigurationProfiles/CloudConfigurationDetails.plist"