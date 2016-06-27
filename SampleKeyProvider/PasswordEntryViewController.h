//
//  PasswordEntryViewController.h
//  PurebredP12Import

#import <UIKit/UIKit.h>

/**
 Code that uses the PasswordEntryViewController must implement the PasswordEntryProtocol.
 */
@protocol PasswordEntryDelegate <NSObject>

- (void) passwordEntryCompletedSuccessfully:(NSString*)password;
- (void) passwordEntryCanceled;
- (void) passwordSubmissionCompletedSuccessfully;
- (void) passwordSubmissionEncounteredError:(int)errorCode errorString:(NSString*)errorString;

@end

@interface PasswordEntryViewController : UIViewController <UITextFieldDelegate> {
    //delegate
    id<PasswordEntryDelegate> delegate;
    
    //values
    NSString* password;
    NSURL* oneTouchSubmitUrl;
    BOOL revealPassword;
    NSString* label;
    NSString* errorLabel;
    
    //controls
    UITextView* labelTextView;
    UITextField* passwordTextField;
    UISwitch* revealPasswordSwitch;
    UISwitch* submitOnScanSwitch;
    UIButton* submitButton;
    UIButton* cancelButton;
    UIButton* scanPasswordButton;
    UILabel* errorLabelLabel;
}

//Delegate
@property (nonatomic, retain) id<PasswordEntryDelegate> delegate;

//Values
@property (nonatomic, retain) NSString *password;
@property (nonatomic, retain) NSURL *oneTouchSubmitUrl;
@property (nonatomic, assign) BOOL revealPassword;
@property (nonatomic, retain) NSString *label;
@property (nonatomic, retain) NSString *errorLabel;

//Controls
@property (nonatomic, retain) IBOutlet UITextView *labelTextView;
@property (nonatomic, retain) IBOutlet UITextField *passwordTextField;
@property (nonatomic, retain) IBOutlet UISwitch *revealPasswordSwitch;
@property (nonatomic, retain) IBOutlet UIButton *submitButton;
@property (nonatomic, retain) IBOutlet UIButton *cancelButton;
@property (nonatomic, retain) IBOutlet UILabel *errorLabelLabel;

//User action handlers
- (IBAction) onEnterPassword:(id)sender;
- (IBAction) onCancelPasswordEntry:(id)sender;
- (IBAction) revealPasswordChanged:(id)sender;

@end
