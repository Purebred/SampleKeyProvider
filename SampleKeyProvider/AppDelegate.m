//
//  AppDelegate.m
//  KeyShareProvider

#import "AppDelegate.h"
#import "Pkcs12ViewController.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

@synthesize window=_window;
@synthesize navigationController=_navigationController;

@synthesize dirEnum;
@synthesize localFileManager;
@synthesize curFile;

//===========================================================
// UIApplicationDelegate implementations
//===========================================================
- (BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url
{
    // Get the
    UIDocumentInteractionController* docInteractionController = [UIDocumentInteractionController interactionControllerWithURL:url];
    NSString* uti = docInteractionController.UTI;
    NSString* pathExtension = [url pathExtension];
    
    if(NSOrderedSame == [pathExtension compare:@"p12"] ||
       NSOrderedSame == [pathExtension compare:@"pfx"])
    {
        Pkcs12ViewController *p12v = [[Pkcs12ViewController alloc] init];
        p12v.url = url;
        p12v.navigationController = self.navigationController;
        [self.navigationController pushViewController:p12v animated:YES];
    }
    return YES;
}

//===========================================================
// Custom methods
//===========================================================
- (void) ProcessSharedFiles:(BOOL)animated showAlertOnNothingToDo:(BOOL)showAlertOnNothingToDo
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
    
    //get the path to the folder shared with iTunes
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docsDir = [paths objectAtIndex:0];
    
    if(!localFileManager)
    {
        localFileManager = [[NSFileManager alloc] init];
    }
    
    if(!dirEnum)
    {
        dirEnum = [localFileManager enumeratorAtPath:docsDir];
    }
    
    if(dirEnum)
    {
        NSString *file = [dirEnum nextObject];
        do
        {
            //When automatically processing files we can pick up p12 (unlike with files that are launched, which
            //seem to require something other than p12, i.e., rhp12).  Look for both extensions here
            if ([[file pathExtension] isEqualToString: @"p12"] || [[file pathExtension] isEqualToString: @"rhp12"]  || [[file pathExtension] isEqualToString: @"pfx"])
            {
                //create a view to solicit a password from the user
                //Pkcs12ViewController *p12v = [[Pkcs12ViewController alloc] init];
                UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"Main" bundle:NULL];
                Pkcs12ViewController *p12v=[storyboard instantiateViewControllerWithIdentifier:@"p12ViewController"];
                
                [p12v setDeleteAfterImport:true];
                [p12v setShowDeleteButton:true];
                [p12v setDelegate:self];
                [self setCurFile:[docsDir stringByAppendingPathComponent:file]];
                p12v.url = [NSURL fileURLWithPath:curFile];
                p12v.navigationController = _navigationController;
                
                [self.navigationController pushViewController:p12v animated:animated];
                
                return;
            }
            file = [dirEnum nextObject];
        }while(file);
        
        dirEnum = nil;
        localFileManager = nil;
    }
    
    if(showAlertOnNothingToDo)
    {
        NSString* str = @"No PKCS #12 files were found. Use iTunes file sharing to provide one or more PKCS #12 files for importing.";
        UIAlertView* alertView = [[UIAlertView alloc] initWithTitle:@"" message:str delegate:nil cancelButtonTitle:NSLocalizedString(@"Close",nil) otherButtonTitles:nil];
        [alertView show];
    }
}

//===========================================================
// P12HandlerDelegate implementations
//===========================================================
- (void) p12ImportCompletedSuccessfully
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
    
    //dismiss the p12 view...
    [self.navigationController popViewControllerAnimated:NO];
    
    //then look to see if there is more work to do
    [self ProcessSharedFiles:NO showAlertOnNothingToDo:NO];
}

- (void) p12ImportCanceled
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
    
    //dismiss the p12 view
    [self.navigationController popViewControllerAnimated:NO];
}

- (void) p12ImportSkip
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
    
    //dismiss the p12 view...
    [self.navigationController popViewControllerAnimated:NO];
    
    //then look to see if there is more work to do
    [self ProcessSharedFiles:NO showAlertOnNothingToDo:NO];
}

- (void) p12DeleteWithoutImporting
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);

    //delete the currently selected file
    NSFileManager* fm = [[NSFileManager alloc] init];
    if([fm isDeletableFileAtPath:curFile])
    {
        [fm removeItemAtPath:curFile error:NULL];
    }
}

- (void) p12ImportEncounteredError:(int)errorCode errorString:(NSString*)errorString
{
    NSLog(@"%s %d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
}

@end
