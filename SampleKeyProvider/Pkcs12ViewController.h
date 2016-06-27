//
//  Pkcs12ViewController.h
//  PurebredP12Import

#import <UIKit/UIKit.h>
#import "PasswordEntryViewController.h"

/**
 Code that uses the PasswordEntryViewController must implement the PasswordEntryProtocol.
 */
@protocol P12HandlerDelegate <NSObject>

- (void) p12ImportCompletedSuccessfully;
- (void) p12ImportCanceled;
- (void) p12ImportSkip;
- (void) p12DeleteWithoutImporting;
- (void) p12ImportEncounteredError:(int)errorCode errorString:(NSString*)errorString;

@end

@interface Pkcs12ViewController : UIViewController <PasswordEntryDelegate, UITextViewDelegate> {
    
@public
    //!delegate is an object that implements P12HandlerDelegate
    id<P12HandlerDelegate> delegate;
    
    //!The message field displays some text with file name and general instructions.
    UITextView* messageView;
    
    //!The url field is set by the caller and points to the PKCS12 file.
    NSURL* url;
    
    //!deleteAfterImport indicates whether the files referenced by the url variable should
    // be deleted following a successful import.  This is expected to be set to true by the
    // caller when operating on files passed to the application via the file sharing interface.
    bool deleteAfterImport;
    
    //!showDeleteButton indicates whether the Delete button should be displayed.  This is
    // expected to be set to true by the caller when operating on files passed to the application
    // via the file sharing interface.
    bool showDeleteButton;
    
    UINavigationController* navigationController;
    
@private
    UIButton* deleteButton;
    UIButton* importButton;
    UIButton* skipButton;
    UIButton* cancelButton;
    NSString* textToDisplay;
}
- (IBAction) OnCancel;
- (IBAction) OnImport;
- (IBAction) OnSkip;
- (IBAction) OnDeleteFile:(id)sender;

+ (OSStatus) importP12:(NSURL*)pkcs12Url password:(NSString*)password deleteAfterImport:(bool)deleteAfterImport;

@property (nonatomic, retain) id<P12HandlerDelegate> delegate;
@property(nonatomic, retain) NSURL* url;
@property(nonatomic, retain) IBOutlet UITextView* messageView;
@property (nonatomic, assign) bool deleteAfterImport;
@property (nonatomic, assign) bool showDeleteButton;
@property (nonatomic, retain) IBOutlet UIButton *deleteButton;
@property (nonatomic, retain) NSString *textToDisplay;
@property (nonatomic, retain) IBOutlet UINavigationController *navigationController;
@property (nonatomic, retain) IBOutlet UIButton *importButton;
@property (nonatomic, retain) IBOutlet UIButton *skipButton;
@property (nonatomic, retain) IBOutlet UIButton *cancelButton;

@end
