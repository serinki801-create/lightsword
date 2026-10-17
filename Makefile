export TARGET = iphone:clang:latest:16.0
export SWIFT_OPTFLAG = -Onone -num-threads 1
srk801_ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = srk801

SRC := $(PWD)/Sources
srk801_FILES = $(shell find $(SRC) -type f \( -name '*.c' -o -name '*.m' \))
srk801_SWIFT_FILES = $(shell find $(SRC) -type f -name '*.swift')
srk801_FRAMEWORKS = UIKit Foundation CoreGraphics IOKit WebKit Metal IOSurface
srk801_CFLAGS = -fobjc-arc -Wno-deprecated-declarations \
	-I$(SRC)/Core -I$(SRC)/Diag -I$(SRC)/Probes -I$(SRC)/Kernel -I$(SRC)/Legacy
srk801_SWIFTFLAGS = -import-objc-header $(PWD)/Bridging-Header.h \
	-Xcc -I$(SRC)/Core -Xcc -I$(SRC)/Diag -Xcc -I$(SRC)/Probes -Xcc -I$(SRC)/Kernel -Xcc -I$(SRC)/Legacy
srk801_INSTALL_TARGET_PROCESSES = srk801
srk801_CODESIGN_FLAGS = -S
srk801_RESOURCE_FILES = Info.plist Resources/webkit/exploit.html Resources/webkit/exploit.js

include $(THEOS_MAKE_PATH)/application.mk
