TARGET := iphone:clang:latest:15.0
ARCHS  := arm64 arm64e

# rootless（Dopamine / palera1n rootless）用这套
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LegacyCostTweak
LegacyCostTweak_FILES = Tweak.xm
LegacyCostTweak_CFLAGS = -fobjc-arc -O2 -Wno-unused-function -Wno-deprecated-declarations
LegacyCostTweak_FRAMEWORKS = UIKit Foundation
LegacyCostTweak_PRIVATE_FRAMEWORKS =
LegacyCostTweak_LIBRARIES =

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 LegacyCostCHN || true"
