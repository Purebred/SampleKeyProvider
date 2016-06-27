//
//  ViewController.m
//  KeyShareProvider

#import "AppDelegate.h"
#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    self.title = @"Sample Key Provider Utility";
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)onImportPkcs12:(id)sender
{
    AppDelegate* app = (AppDelegate*)[[UIApplication sharedApplication] delegate];
    [app setNavigationController:self.navigationController];
    [app ProcessSharedFiles:YES showAlertOnNothingToDo:YES];
}

- (IBAction)onImportSamplePkcs12:(id)sender
{
    NSString* password = @"password";
    NSURL* first = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"05ab14d4a4870342a18423fa8dc5f4da86c22dd8" ofType:@"p12"]];
    OSStatus stat1 = [Pkcs12ViewController importP12:first password:password deleteAfterImport:false];

    NSURL* second = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"5b50b7acdf0d0164178209c0b7f7208e57ce712f" ofType:@"p12"]];
    OSStatus stat2 = [Pkcs12ViewController importP12:second password:password deleteAfterImport:false];
    
    NSURL* third = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"f1ec5ee9a622c4678270a6245e63fa1aa42e6aad" ofType:@"p12"]];
    OSStatus stat3 = [Pkcs12ViewController importP12:third password:password deleteAfterImport:false];
    
    NSURL* fourth = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"ff709cb728db6569f6be408cd1a5f4f00aabf93c" ofType:@"p12"]];
    OSStatus stat4 = [Pkcs12ViewController importP12:fourth password:password deleteAfterImport:false];
    
    if(0 == stat1 && 0 == stat2 && 0 == stat3 && 0 == stat4)
    {
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:@"Success" message:NSLocalizedString(@"Successfully imported four sample keys",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
    }
    else
    {
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:@"Error" message:NSLocalizedString(@"Failed to import one or more of four sample keys",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
    }
}

-(void)deleteAllKeysForSecClass:(CFTypeRef)secClass {
    NSMutableDictionary* dict = [NSMutableDictionary dictionary];
    [dict setObject:(__bridge id)secClass forKey:(__bridge id)kSecClass];
    OSStatus result = SecItemDelete((__bridge CFDictionaryRef) dict);
    NSAssert(result == noErr || result == errSecItemNotFound, @"Error deleting keychain data (%i)", (int)result);
}

- (IBAction)onClearKeyChain:(id)sender
{
    [self deleteAllKeysForSecClass:kSecClassGenericPassword];
    [self deleteAllKeysForSecClass:kSecClassInternetPassword];
    [self deleteAllKeysForSecClass:kSecClassCertificate];
    [self deleteAllKeysForSecClass:kSecClassKey];
    [self deleteAllKeysForSecClass:kSecClassIdentity];
}

@end
