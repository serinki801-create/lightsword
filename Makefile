export TARGET = iphone:clang:latest:16.0
export SWIFT_OPTFLAG = -Onone -num-threads 1
natsuk1_ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = natsuk1

SRC := $(PWD)/Sources
natsuk1_FILES = $(shell find $(SRC) -type f \( -name '*.c' -o -name '*.m' \))
natsuk1_SWIFT_FILES = $(shell find $(SRC) -type f -name '*.swift')
natsuk1_FRAMEWORKS = UIKit Foundation CoreGraphics IOKit WebKit
natsuk1_CFLAGS = -fobjc-arc -Wno-deprecated-declarations \
	-I$(SRC)/Core -I$(SRC)/Diag -I$(SRC)/Probes -I$(SRC)/Kernel -I$(SRC)/Legacy
natsuk1_SWIFTFLAGS = -import-objc-header $(PWD)/Bridging-Header.h \
	-Xcc -I$(SRC)/Core -Xcc -I$(SRC)/Diag -Xcc -I$(SRC)/Probes -Xcc -I$(SRC)/Kernel -Xcc -I$(SRC)/Legacy
natsuk1_INSTALL_TARGET_PROCESSES = natsuk1
natsuk1_CODESIGN_FLAGS = -S
natsuk1_RESOURCE_FILES = Info.plist Resources/webkit/exploit.html Resources/webkit/exploit.js

include $(THEOS_MAKE_PATH)/application.mk
