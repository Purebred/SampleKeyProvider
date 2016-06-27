//
//  Pkcs12ViewController.m
//  PurebredP12Import

#import "Pkcs12ViewController.h"

//openssl includes
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

@interface Pkcs12ViewController ()

@end

@implementation Pkcs12ViewController

@synthesize delegate;
@synthesize url;
@synthesize messageView;
@synthesize deleteAfterImport;
@synthesize showDeleteButton;
@synthesize deleteButton;
@synthesize textToDisplay;
@synthesize navigationController;
@synthesize importButton;
@synthesize skipButton;
@synthesize cancelButton;

//-----------------------------------------------------------
// PasswordEntryDelegate implementation
//-----------------------------------------------------------
#pragma mark -
#pragma mark PasswordEntryDelegate
- (void) passwordEntryCompletedSuccessfully:(NSString*)password
{
    [self.navigationController popViewControllerAnimated:NO];
    
    OSStatus stat = [Pkcs12ViewController importP12:url password:password deleteAfterImport:deleteAfterImport];
    if(0 == stat)
    {
        if(delegate)
            [delegate p12ImportCompletedSuccessfully];
    }
    else
    {
        if(delegate)
            [delegate p12ImportEncounteredError:stat errorString:nil];
    }
}

- (void) passwordEntryCanceled
{
    [self.navigationController popViewControllerAnimated:NO];
}

- (void) passwordSubmissionCompletedSuccessfully
{
}

- (void) passwordSubmissionEncounteredError:(int)errorCode errorString:(NSString*)errorString
{
}

//-----------------------------------------------------------
// View lifecycle stuff
//-----------------------------------------------------------
#pragma mark - View lifecycle
-(void)viewDidLayoutSubviews {
    [messageView scrollRangeToVisible:NSMakeRange(0, 0)];
    messageView.contentOffset = CGPointZero;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    
    self.title = @"Sample Key Provider Utility";
    
    NSString* prose = NSLocalizedString(@"may contain cryptographic keys.  Click the Import button below to enter your password and import the keys.  Click the Skip button to skip to the next file, if any.  Click the Delete button to delete this file without importing.", "Text for PKCS#12 view body");
    NSString* text = [NSString stringWithFormat:@"The file named %s %s", [[url lastPathComponent] UTF8String], [prose UTF8String]];
    [self setTextToDisplay:text];
    [messageView setText:[self textToDisplay]];

    [messageView sizeToFit];
    [messageView layoutIfNeeded];
    
    CGRect frame = [messageView frame];
    CGFloat bottom = CGRectGetMaxY(frame);
    CGFloat newY = bottom + 20;
    CGPoint impCenter = [importButton center];
    
    if((impCenter.y - bottom) > 30 ||
       (impCenter.y - bottom) < 20)
    {
        CGPoint impCenterNew = CGPointMake(impCenter.x, newY);
        [importButton setCenter:impCenterNew];
        
        CGPoint skipCenter = [skipButton center];
        CGPoint skipCenterNew = CGPointMake(skipCenter.x, newY);
        [skipButton setCenter:skipCenterNew];
        
        CGPoint delCenter = [deleteButton center];
        CGPoint delCenterNew = CGPointMake(delCenter.x, newY);
        [deleteButton setCenter:delCenterNew];
        
        CGPoint canCenter = [cancelButton center];
        CGPoint canCenterNew = CGPointMake(canCenter.x, newY + (canCenter.y - impCenter.y));
        [cancelButton setCenter:canCenterNew];
    }
}
- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.automaticallyAdjustsScrollViewInsets = NO;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

//-----------------------------------------------------------
// Click handlers
//-----------------------------------------------------------
#pragma mark - Click handlers
- (IBAction) OnImport
{
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:NULL];
    PasswordEntryViewController *p12v=[storyboard instantiateViewControllerWithIdentifier:@"passwordViewController"];
    
    [p12v setDelegate:self];
    
    [self.navigationController pushViewController:p12v animated:YES];
    return;
}

-(IBAction) OnSkip
{
    if(delegate)
    {
        [delegate p12ImportSkip];
    }
}

-(IBAction) OnCancel
{
    if(delegate)
    {
        [delegate p12ImportCanceled];
    }
}

- (IBAction) OnDeleteFile:(id)sender
{
    if(delegate)
    {
        [delegate p12DeleteWithoutImporting];
        [delegate p12ImportSkip];
    }
}

//-----------------------------------------------------------
// Custom methods
//-----------------------------------------------------------
+ (OSStatus) importP12:(NSURL*)pkcs12Url password:(NSString*)password deleteAfterImport:(bool)deleteAfterImport
{
    bool showSuccessMsg = true;
    //read the P12 file
    NSData *PKCS12Data = [NSData dataWithContentsOfURL:pkcs12Url];
    if(nil == PKCS12Data)
    {
        showSuccessMsg = false;
        PKCS12Data = [NSData dataWithContentsOfFile:[pkcs12Url absoluteString]
                      ];
    }
    
    if(nil == PKCS12Data)
    {
        NSString* baseError = NSLocalizedString(@"Could not read PKCS #12 data from", @"Error following failure to read PKCS #12 data");
        const char* pFilename = [[pkcs12Url absoluteString] UTF8String];
        NSLog(@"%s %d %s - %s:  %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], pFilename);
        
        NSString* str = [NSString stringWithFormat:@"%s %s.", [baseError UTF8String], pFilename];
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Error",nil) message:str delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
        
        return errSecDecode;
    }
    
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    
    OSStatus securityError = errSecSuccess;
    
    //SecPKCS12Import requires a dictionary with a single value (only one option is supported)
    NSMutableDictionary * optionsDictionary = [[NSMutableDictionary alloc] init];
    [optionsDictionary setObject:(id)password forKey:(id)kSecImportExportPassphrase];
    [optionsDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
    [optionsDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    [optionsDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    
    //Create an array to receive the data parsed from the PKCS12 blob
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    //Parse the PKCS12 blob
    securityError = SecPKCS12Import(inPKCS12Data, (CFDictionaryRef)optionsDictionary, &items);
    if(errSecSuccess != securityError)
    {
        NSString* baseError = NSLocalizedString(@"Failed to parse PKCS #12 data with error code", @"Error following failure to parse PKCS #12 data");
        NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, [baseError UTF8String], [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
        
        NSString* str = [NSString stringWithFormat:@"%s %d.", [baseError UTF8String], (int)securityError];
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Error",nil) message:str delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
    }
    else
    {
        long count = CFArrayGetCount(items);
        if(count > 1)
        {
            NSLog(@"%s %d %s - %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, "SecPKCS12Import returned more than one item.  Ignoring all but the first item.");
        }
        
        for(int ii = 0; ii < count; ++ii)
        {
            NSString* title = [NSString stringWithFormat:@"Key #%d", ii+1];
            
            //get the first time from the array populated by SecPKCS12Import
            CFDictionaryRef pkcs12Contents = (CFDictionaryRef)CFArrayGetValueAtIndex(items, ii);
            /*
             //these have not been being used.  perhaps they should be.
             CFDataRef keyId = nil;
             CFStringRef label = nil;
             
             //grab the keyId attribute if it is present
             if(errSecSuccess == securityError && CFDictionaryContainsKey(pkcs12Contents, kSecImportItemKeyID))
             {
             keyId = (CFDataRef)CFDictionaryGetValue (pkcs12Contents, kSecImportItemKeyID);
             }
             
             //grab the label attribute if it is present
             if(errSecSuccess == securityError && CFDictionaryContainsKey(pkcs12Contents, kSecImportItemLabel))
             {
             label = (CFStringRef)CFDictionaryGetValue (pkcs12Contents, kSecImportItemLabel);
             }
             */
            //we're primarily interested in the identity value
            if(CFDictionaryContainsKey(pkcs12Contents, kSecImportItemIdentity))
            {
                //Grab the identity from the dictionary
                SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(pkcs12Contents, kSecImportItemIdentity);
                SecCertificateRef cert;
                SecIdentityCopyCertificate(identity, &cert);
                
                NSString* tagstr = @"red.hound.purebred.pkcs12";
                if(cert)
                {
                    //put common name in tagstr
                    CFDataRef cfData = SecCertificateCopyData(cert);
                    
                    const unsigned char* p = (const unsigned char*)CFDataGetBytePtr(cfData);
                    X509 *certificateX509 = d2i_X509(NULL, &p, CFDataGetLength(cfData));
                    CFRelease(cfData);
                    if (certificateX509 != NULL) {
                        X509_NAME *issuerX509Name = X509_get_subject_name(certificateX509);
                        
                        if (issuerX509Name != NULL) {
                            char  subjectCn[256];
                            int cnIndex = X509_NAME_get_text_by_NID(issuerX509Name, NID_commonName, subjectCn, sizeof(subjectCn));
                            if(cnIndex)
                            {
                                tagstr = [NSString stringWithUTF8String:(char *)subjectCn];
                            }
                        }
                    }
                    
                }
                
                NSMutableDictionary* dict = [[NSMutableDictionary alloc]init];
                [dict setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnPersistentRef];
                [dict setObject:(__bridge id)identity forKey:(id)kSecValueRef];
                [dict setObject:tagstr forKey:(id)kSecAttrLabel];
                CFTypeRef persistent_ref;
                securityError = SecItemAdd((CFDictionaryRef)dict, &persistent_ref);
                
                if(errSecSuccess != securityError)
                {
                    NSLog(@"%s %d %s - %s %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, "SecItemAdd failed to import identity harvested from PKCS #12 data with error code ", [[[NSNumber numberWithInt:securityError] stringValue] UTF8String]);
                    
                    if(errSecDuplicateItem == securityError)
                    {
                        if(showSuccessMsg)
                        {
                            UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:title message:NSLocalizedString(@"Import not required.  The key material was already present in the keychain.",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
                            [alertView show];
                        }
                        
                        if(deleteAfterImport)
                        {
                            NSFileManager *localFileManager = [[NSFileManager alloc] init];
                            [localFileManager removeItemAtURL:pkcs12Url error:NULL];
                        }
                        securityError = errSecSuccess;
                    }
                    else
                    {
                        NSString* str = [NSString stringWithFormat:@"Failed to import PKCS #12 data with error code %d.", (int)securityError];
                        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:title message:str delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
                        [alertView show];
                    }
                }
                else
                {
                    if(showSuccessMsg)
                    {
                        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:title message:NSLocalizedString(@"Successfully imported key",nil) delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
                        [alertView show];
                    }
                    
                    if(deleteAfterImport)
                    {
                        NSFileManager *localFileManager = [[NSFileManager alloc] init];
                        [localFileManager removeItemAtURL:pkcs12Url error:NULL];
                    }
                }
            }
            
            if(errSecSuccess == securityError && CFDictionaryContainsKey(pkcs12Contents, kSecImportItemTrust))
            {
                //SecTrustRef trust = (SecTrustRef)CFDictionaryGetValue (pkcs12Contents, kSecImportItemTrust);
                
                //XXX***DEFER evaluate the trust and output an error log if there is a problem
            }
            
            if(errSecSuccess == securityError && CFDictionaryContainsKey(pkcs12Contents, kSecImportItemCertChain))
            {
                //CFArrayRef certChain = (CFArrayRef)CFDictionaryGetValue (pkcs12Contents, kSecImportItemCertChain);
                
                //XXX***DEFER import certificates from chain
            }
        }
    }
    
    return securityError;
}

@end
