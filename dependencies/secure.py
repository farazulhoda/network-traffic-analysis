import objc
from Cocoa import NSApplicationDelegate, YES

class AppDelegate(NSApplicationDelegate):
    def applicationSupportsSecureRestorableState_(self, app):
        return YES

# Set up the app delegate
app_delegate = AppDelegate.alloc().init()

# Register the app delegate with the shared NSApplication instance
objc.registerAppDelegate(app_delegate)