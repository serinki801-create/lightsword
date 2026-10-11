#include <dispatch/dispatch.h>
#include <CoreFoundation/CoreFoundation.h>

void nk_async_main(void (^block)(void)) {
    dispatch_async(dispatch_get_main_queue(), [block copy]);
}

void nk_async_background(void (^block)(void)) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), [block copy]);
}

void nk_async_main_after(double seconds, void (^block)(void)) {
    dispatch_after(CFAbsoluteTimeGetCurrent() + seconds, dispatch_get_main_queue(), [block copy]);
}
