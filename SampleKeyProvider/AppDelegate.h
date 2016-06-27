//
//  AppDelegate.h
//  KeyShareProvider

#import <UIKit/UIKit.h>
#import "Pkcs12ViewController.h"
#import "ViewController.h"

@interface AppDelegate : UIResponder <UIApplicationDelegate, P12HandlerDelegate> {
@private
    //----------------------------------------------------------------------------
    // P12 import-related variables
    //----------------------------------------------------------------------------
    //!dirEnum is used to iterate over P12 files shared via the documents directory
    NSDirectoryEnumerator *dirEnum;
    
    //!localFileManager is used to iterate over P12 files shared via the documents directory
    NSFileManager *localFileManager;
    
    //!curFile contains the current PKCS 12 file being imported/skipped/deleted
    NSString* curFile;
}

//----------------------------------------------------------------------------
// Navigation-related variables
//----------------------------------------------------------------------------
@property (nonatomic, retain) IBOutlet UIWindow *window;
@property (nonatomic, retain) IBOutlet UINavigationController *navigationController;

//----------------------------------------------------------------------------
// P12 import-related variables
//----------------------------------------------------------------------------
@property (nonatomic, retain) NSDirectoryEnumerator *dirEnum;
@property (nonatomic, retain) NSFileManager *localFileManager;
@property (nonatomic, retain) NSString *curFile;

// Drives enumeration of P12 files in folder shared with iTunes
- (void) ProcessSharedFiles:(BOOL)animated showAlertOnNothingToDo:(BOOL)showAlertOnNothingToDo;

@end

