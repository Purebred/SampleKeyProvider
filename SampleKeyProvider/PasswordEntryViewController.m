//
//  PasswordEntryViewController.m
//  PurebredP12Import

#import "PasswordEntryViewController.h"

@interface PasswordEntryViewController ()

@end

@implementation PasswordEntryViewController

//Delegate
@synthesize delegate;

//Values
@synthesize password;
@synthesize oneTouchSubmitUrl;
@synthesize revealPassword;
@synthesize label;
@synthesize errorLabel;

//Controls
@synthesize labelTextView;
@synthesize passwordTextField;
@synthesize revealPasswordSwitch;
@synthesize submitButton;
@synthesize cancelButton;
@synthesize errorLabelLabel;

- (id)initWithCoder:(NSCoder *)aDecoder {
    
    self = [super initWithCoder:aDecoder];
    
    if (self) {
        revealPassword = FALSE;
    }
    
    return self;
}

#pragma mark - View lifecycle

- (void)viewWillAppear:(BOOL)animated
{
    //if revealPassword option is on turn off secure text entry (and vice versa)
    [passwordTextField setSecureTextEntry:![self revealPassword]];
    if(animated)
        [super viewWillAppear:YES];
    else
        [super viewWillAppear:NO];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    [self.revealPasswordSwitch setOn:self.revealPassword];
    self.title = @"Sample Key Provider Utility";
    self.automaticallyAdjustsScrollViewInsets = NO; // Avoid the top UITextView space, iOS7 (~bug?)
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark -
#pragma mark User action handlers
//===========================================================
// - (IBAction) onEnterPassword
//
//===========================================================
- (IBAction) onEnterPassword:(id)sender
{
    [self setPassword:[passwordTextField text]];
    
    if(delegate)
    {
        [delegate passwordEntryCompletedSuccessfully:[self password]];
    }
}

//===========================================================
// - (IBAction) onCancelPasswordEntry
//
//===========================================================
- (IBAction) onCancelPasswordEntry:(id)sender
{
    if(delegate)
    {
        [delegate passwordEntryCanceled];
    }
}

//===========================================================
// - (IBAction) revealPasswordChanged
//
//===========================================================
- (IBAction) revealPasswordChanged:(id)sender
{
    //set secure text per the reveal password indicator (reveal = true means no secure text entry)
    [passwordTextField setSecureTextEntry:![revealPasswordSwitch isOn]];
}

@end
