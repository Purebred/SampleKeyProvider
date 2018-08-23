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
    NSURL* first = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"9a69ba0e332da182a8d718750168135a55acdded" ofType:@"p12"]];
    OSStatus stat1 = [Pkcs12ViewController importP12:first password:password deleteAfterImport:false];

    NSURL* second = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"37f1cca56ad3d10fd35337f2803c7793d22d1099" ofType:@"p12"]];
    OSStatus stat2 = [Pkcs12ViewController importP12:second password:password deleteAfterImport:false];
    
    NSURL* third = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"678b5b37e83a3f70623a33a8450316e7eb0450fc" ofType:@"p12"]];
    OSStatus stat3 = [Pkcs12ViewController importP12:third password:password deleteAfterImport:false];
    
    NSURL* fourth = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"974a6Fd70bba0f77fc2bf9fb192cee4391575173" ofType:@"p12"]];
    OSStatus stat4 = [Pkcs12ViewController importP12:fourth password:password deleteAfterImport:false];

    NSURL* five = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"7274cce984739eaf22d8dB577a323a4daa4e55ef" ofType:@"p12"]];
    OSStatus stat5 = [Pkcs12ViewController importP12:five password:password deleteAfterImport:false];

    NSURL* six = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"bb2Fda1bdcd9f61fe367d7711708316d35ea5b61" ofType:@"p12"]];
    OSStatus stat6 = [Pkcs12ViewController importP12:six password:password deleteAfterImport:false];

    NSURL* seven = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"f63e304424f65258ed3f0b25b2ba74f88e431e82" ofType:@"p12"]];
    OSStatus stat7 = [Pkcs12ViewController importP12:seven password:password deleteAfterImport:false];

    NSURL* eight = [NSURL URLWithString:[[NSBundle mainBundle] pathForResource:@"fed9960aead5f8b1afc9498bb44b3d2016a6a596" ofType:@"p12"]];
    OSStatus stat8 = [Pkcs12ViewController importP12:eight password:password deleteAfterImport:false];

    if(0 == stat1 && 0 == stat2 && 0 == stat3 && 0 == stat4 && 0 == stat5 && 0 == stat6 && 0 == stat7 && 0 == stat8)
    {
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:@"Success" message:NSLocalizedString(@"Successfully imported eight sample keys",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
    }
    else
    {
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:@"Error" message:NSLocalizedString(@"Failed to import one or more of eight sample keys",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
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
