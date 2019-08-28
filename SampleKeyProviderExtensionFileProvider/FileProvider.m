//
//  FileProvider.m
//  SampleKeyProviderExtensionFileProvider

#import "FileProvider.h"
#import "FileProviderHelpers.h"
#import "KeyChainDataSource.h"
#import <UIKit/UIKit.h>

@interface FileProvider ()

@end

@implementation FileProvider

- (NSFileCoordinator *)fileCoordinator {
    NSFileCoordinator *fileCoordinator = [[NSFileCoordinator alloc] init];
    [fileCoordinator setPurposeIdentifier:NSFileProviderManager.defaultManager.providerIdentifier];
    return fileCoordinator;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        
        // generate a password for use during a FileProvider session
        NSString *alphabet  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789";
        NSMutableString* s = [NSMutableString stringWithCapacity:20];
        for (NSUInteger i = 0U; i < 20; i++) {
            u_int32_t r = arc4random() % [alphabet length];
            unichar c = [alphabet characterAtIndex:r];
            [s appendFormat:@"%C", c];
        }

        self.password = s;

        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        [pasteboard setString:self.password];
        pasteboard = nil;

        [self.fileCoordinator coordinateWritingItemAtURL:NSFileProviderManager.defaultManager.documentStorageURL options:0 error:nil byAccessor:^(NSURL *newURL) {
            // ensure the documentStorageURL actually exists
            NSError *error = nil;
            [[NSFileManager defaultManager] createDirectoryAtURL:newURL withIntermediateDirectories:YES attributes:nil error:&error];
            if(error)
            {
                NSLog(@"%@", error);
            }
        }];
    }
    return self;
}

#pragma mark - Static helpers

// isZipIdentifier accepts a string notionally containing a UTI and returns true if the UTI
// is of the purebred.zip UTIs and false otherwise.
+ (BOOL) isZipIdentifier:(NSString*)identifier {
    if([@"purebred.zip.all" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.all_user" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.signature" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.encryption" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.authentication" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.device" isEqualToString:(NSString*)identifier] ||
       [@"purebred.zip.no_filter" isEqualToString:(NSString*)identifier])
    {
        return YES;
    }
    return NO;
}

// isSelectIdentifier accepts a string notionally containing a UTI and returns true if the UTI
// is of the purebred.select UTIs and false otherwise.
+ (BOOL) isSelectIdentifier:(NSString*)identifier {
    if([@"com.rsa.pkcs-12" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.all" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.all_user" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.signature" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.encryption" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.authentication" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.device" isEqualToString:(NSString*)identifier] ||
       [@"purebred.select.no_filter" isEqualToString:(NSString*)identifier])
    {
        return YES;
    }
    return NO;
}

// getZipPlaceholderUrl takes a string notionally containing a zip UTI and returns a placeholder URL
// if it is a zip UTI and nil otherwise.
+ (NSURL*) getZipPlaceholderUrl:(NSString*)identifier {
    if(![FileProvider isZipIdentifier:identifier])
        return nil;
    
    NSURL* placeholderURL = placeholderURL = [NSFileProviderManager placeholderURLForURL:[NSFileProviderManager.defaultManager.documentStorageURL URLByAppendingPathComponent:[NSString stringWithFormat:@"%@/%@.zip", identifier, identifier]]];
    return placeholderURL;
}

// getP12PlaceholderUrl takes a string notionally containing a select UTI and returns a placeholder URL
// if it is a not zip UTI and nil if it is (note things that are not select UTIs still pass through).
+ (NSURL*) getP12PlaceholderUrl:(NSString*)identifier {
    if([FileProvider isZipIdentifier:identifier])
        return nil;
    
    NSURL* placeholderURL = placeholderURL = [NSFileProviderManager placeholderURLForURL:[NSFileProviderManager.defaultManager.documentStorageURL URLByAppendingPathComponent:[NSString stringWithFormat:@"%@/tmp.p12", identifier]]];
    return placeholderURL;
}

#pragma mark - FileProvider interface
- (nullable NSFileProviderItem)itemForIdentifier:(NSFileProviderItemIdentifier)identifier error:(NSError * _Nullable *)error {
    // resolve the given identifier to a record in the model
    /*
     The data model is as follows:
     
        <document storage URL>/<identitier>/<file name>
     
     The nature of the identifier will be determined by whether the target UTI is a select UTI or a zip UTI. Where it is a
     zip UTI, the identifier is simply the UTI itself and the file name is <UTI>.zip. Where it is a select UTI, the identifer
     is <UTI>+<index of key in key chain> and the file name is tmp.p12.
     
     In the user interface, the root view shows a set of folders, one each for each select UTI. The contents of the folder
     consist of one item for each key that matches the UTI plus one file corresponding to the related zip UTI. The full
     contents of each folder will always be shown regardless of the UTI sought by the caller, however, items that do not
     match the caller's intent are shown as grayed out.
     */
    
    NSLog(@"begin itemForIdentifier: %@", identifier);
    
    NSURL* placeholderURL = nil;
    if([identifier isEqualToString:@"NSFileProviderRootContainerItemIdentifier"])
    {
        // The root element shows a list of folders only (one for each select UTI)
        int numFolders = [FileProviderEnumerator GetNumberOfFolders];
        
        NSFileProviderItem fi = [[FileProviderItemFolder alloc]initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:@"/" size:numFolders];
        
        NSLog(@"end itemForIdentifier with NSFileProviderRootContainerItemIdentifier");
        return fi;
    }
    else if([FileProvider isSelectIdentifier:identifier]){
        // Number of items will be established later, when enumerating the keys covered by the selected folder (i.e., UTI). Just use 1 here.
        NSFileProviderItem fi = [[FileProviderItemFolder alloc]initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:identifier size:1];
        
        NSLog(@"end itemForIdentifier with %@", identifier);
        return fi;
    }

    // We either have a zip UTI in the identifier or a P12 specific select UTI
    NSString* friendlyName = nil;
    
    // see if it's a zip file
    placeholderURL = [FileProvider getZipPlaceholderUrl:(NSString*)identifier];
    if(nil == placeholderURL)
    {
        // if not get placeholder for select-based file
        placeholderURL = [FileProvider getP12PlaceholderUrl:(NSString*)identifier];
    }
    friendlyName = [placeholderURL absoluteString];

    // parse the value (not necessary for zip but no foul)
    NSArray* a = [identifier componentsSeparatedByString:@"+"];
    NSString* uti = a[0];
    NSString* path = [placeholderURL absoluteString];

    // return a file provider item for the file
    NSFileProviderItem fi = [[FileProviderItemKey alloc]initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:path size:1 uti:identifier friendlyName:friendlyName notBefore:nil parentIdentifier:uti];
    return fi;
}

- (nullable NSURL *)URLForItemWithPersistentIdentifier:(NSFileProviderItemIdentifier)identifier {
    NSURL* placeholderURL = [FileProvider getZipPlaceholderUrl:(NSString*)identifier];
    if(nil == placeholderURL) {
        placeholderURL = [FileProvider getP12PlaceholderUrl:identifier];
    }
    return placeholderURL;
}

- (nullable NSFileProviderItemIdentifier)persistentIdentifierForItemAtURL:(NSURL *)url {
    // resolve the given URL to a persistent identifier using a database
    NSArray <NSString *> *pathComponents = [url pathComponents];
    
    // exploit the fact that the path structure has been defined as
    // <base storage directory>/<item identifier>/<item file name> above
    NSParameterAssert(pathComponents.count > 2);
    
    return pathComponents[pathComponents.count - 2];
}

- (void)providePlaceholderAtURL:(NSURL *)url completionHandler:(void (^)(NSError * _Nullable error))completionHandler {
  
    NSFileProviderItemIdentifier identifier = [self persistentIdentifierForItemAtURL:url];
    if (!identifier) {
        completionHandler([NSError errorWithDomain:NSFileProviderErrorDomain code:NSFileProviderErrorNoSuchItem userInfo:nil]);
        return;
    }

    NSError *error = nil;
    NSFileProviderItem fileProviderItem = [self itemForIdentifier:identifier error:&error];
    if (!fileProviderItem) {
        completionHandler(error);
        return;
    }
    NSURL *placeholderURL = [NSFileProviderManager placeholderURLForURL:url];
    NSURL* parent = [placeholderURL URLByDeletingLastPathComponent];
    [[NSFileManager defaultManager] createDirectoryAtURL:parent withIntermediateDirectories:YES attributes:nil error:&error];
    if(error)
    {
        NSLog(@"%@", error);
    }
    if (![NSFileProviderManager writePlaceholderAtURL:placeholderURL withMetadata:fileProviderItem error:&error]) {
        completionHandler(error);
        return;
    }

    completionHandler(nil);
}

- (void)startProvidingItemAtURL:(NSURL *)url completionHandler:(void (^)(NSError *))completionHandler {
    NSLog(@"begin startProvidingItemAtURL: %@", url);
    // Should ensure that the actual file is in the position returned by URLForItemWithIdentifier:, then call the completion handler

    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    [pasteboard setString:self.password];
    pasteboard = nil;
    
    NSArray* components = [url pathComponents];
    NSString* identifier = components[components.count - 2];
    NSData* zipData = nil;
    NSURL* placeholderURL = nil;
    
    // see if we are targeting a zip file
    placeholderURL = [FileProvider getZipPlaceholderUrl:(NSString*)identifier];
    if(nil != placeholderURL) {
        // if so, create a key chain instance to generate the zip with the desired P12 files
        KeyChainDataSource* keyChain2 = [[KeyChainDataSource alloc]initWithMode:KSM_Identities password:self.password];
        if([identifier isEqualToString:@"purebred.zip.no_filter"]) {
            // if no_filter is passed it pair it with all_user
            [keyChain2 LoadKeyChainContents:[NSArray arrayWithObjects:identifier, @"purebred.zip.all_user", nil]];
        }
        else {
            // if not no_filter, just use the presented UTI
            [keyChain2 LoadKeyChainContents:[NSArray arrayWithObjects:identifier, nil]];
        }
        zipData = [keyChain2 GetPKCS12Zip];
        if(nil == zipData) {
            NSLog(@"Failed to obtain zip file from key chain instance for %@", identifier);
        }
        keyChain2 = nil;
    }
    
    if(nil != zipData) {
        // if we got zip data, then just write it out
        NSURL* parent = [placeholderURL URLByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtURL:parent withIntermediateDirectories:YES attributes:nil error:nil];
        
        NSError* e = nil;
        [self.fileCoordinator coordinateWritingItemAtURL:placeholderURL options:0 error:&e byAccessor:^(NSURL *newURL) {
            BOOL b = [zipData writeToURL:newURL atomically:YES];
            if(!b){
                NSLog(@"Failed to write zip data to %@", newURL);
            }
        }];
    }
    else {
        // if we did not get zip data, the try to get PKCS12 data
        placeholderURL = [FileProvider getP12PlaceholderUrl:(NSString*)identifier];
        
        NSArray* a = [identifier componentsSeparatedByString:@"+"];
        if( 2 != [a count]) {
            NSLog(@"Failed to parse UTI and identifier components from %@", identifier);
            return;
        }
        
        // get the UTI and index from the split identifier
        NSString* uti = a[0];
        int index = [a[1] intValue];
        
        // create a key chain object
        KeyChainDataSource* keyChain = [[KeyChainDataSource alloc]initWithMode:KSM_Identities password:self.password];
        if([uti isEqualToString:@"purebred.select.no_filter"]) {
            // if UTI is no_filter pair it with all_user
            [keyChain LoadKeyChainContents:[NSArray arrayWithObjects:uti, @"purebred.select.all_user", nil]];
        }
        else {
            // if UTI is not no_filter, use it straight up
            [keyChain LoadKeyChainContents:[NSArray arrayWithObjects:uti, nil]];
        }
        
        NSData* d = [keyChain GetPKCS12AtIndex:index];
        NSError* e;
        keyChain = nil;
        [self.fileCoordinator coordinateWritingItemAtURL:placeholderURL options:0 error:&e byAccessor:^(NSURL *newURL) {
            BOOL b = [d writeToURL:newURL atomically:YES];
            if(!b){
                NSLog(@"Failed to write PKCS12 data to %@", newURL);
            }
        }];
    }

    completionHandler(nil);
    NSLog(@"end startProvidingItemAtURL");
}

- (void)stopProvidingItemAtURL:(NSURL *)url {
    NSLog(@"begin stopProvidingItemAtURL");
    // Called after the last claim to the file has been released. At this point, it is safe for the file provider to remove the content file.

    // TODO: look up whether the file has local changes
    BOOL fileHasLocalChanges = NO;

    if (!fileHasLocalChanges) {
        // remove the existing file to free up space
        [[NSFileManager defaultManager] removeItemAtURL:url error:NULL];

        /*
        // write out a placeholder to facilitate future property lookups
        [self providePlaceholderAtURL:url completionHandler:^(NSError * __nullable error) {
            // TODO: handle any error, do any necessary cleanup
        }];
         */
    }
    NSLog(@"end stopProvidingItemAtURL");
}

#pragma mark - Actions

/* TODO: implement the actions for items here
 each of the actions follows the same pattern:
 - make a note of the change in the local model
 - schedule a server request as a background task to inform the server of the change
 - call the completion block with the modified item in its post-modification state
 */

#pragma mark - Enumeration

- (nullable id<NSFileProviderEnumerator>)enumeratorForContainerItemIdentifier:(NSFileProviderItemIdentifier)containerItemIdentifier error:(NSError **)error {
    
    id<NSFileProviderEnumerator> enumerator = nil;
    if ([containerItemIdentifier isEqualToString:NSFileProviderRootContainerItemIdentifier]) {
        // TODO: instantiate an enumerator for the container root
        enumerator = [[FileProviderEnumerator alloc]initWithItemIdentifier:NSFileProviderRootContainerItemIdentifier password:self.password];
    } else if ([containerItemIdentifier isEqualToString:NSFileProviderWorkingSetContainerItemIdentifier]) {
        // TODO: instantiate an enumerator for the working set
        NSLog(@"enumeratorForContainerItemIdentifier with NSFileProviderWorkingSetContainerItemIdentifier");
        enumerator = [[FileProviderEnumerator alloc]initWithItemIdentifier:NSFileProviderRootContainerItemIdentifier password:self.password];
    } else {
        // TODO: determine if the item is a directory or a file
        // - for a directory, instantiate an enumerator of its subitems
        // - for a file, instantiate an enumerator that observes changes to the file
        enumerator = [[FileProviderEnumerator alloc]initWithItemIdentifier:containerItemIdentifier password:self.password];
    }
    
    return enumerator;
}

@end
