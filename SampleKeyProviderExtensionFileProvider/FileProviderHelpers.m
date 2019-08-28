//
//  FileProviderHelpers.m
//  SampleKeyProviderExtensionFileProvider
//

#import <Foundation/Foundation.h>
#import "FileProviderHelpers.h"
#import "KeyChainDataSource.h"


//----------------------------------------------------------------------------------------------------------------------------------------------------
// FileProviderEnumerator
//----------------------------------------------------------------------------------------------------------------------------------------------------
@interface FileProviderEnumerator ()
    @property (readwrite) NSString* password;
    @property (readwrite) NSFileProviderItemIdentifier identifier;
@end

@implementation FileProviderEnumerator
    @synthesize identifier;
    - (instancetype)initWithItemIdentifier:(NSFileProviderItemIdentifier)identifier {
        if (self = [super init]) {
            self.identifier = identifier;
        }
        return self;
    }
    - (instancetype)initWithItemIdentifier:(NSFileProviderItemIdentifier)identifier password:(NSString*)password {
        if (self = [super init]) {
            self.identifier = identifier;

            // populate the dictionaries used to map UTIs onto friendlier names
            self.zipNameDictionary = [[NSMutableDictionary alloc] init];
            self.zipNameDictionary[@"purebred.zip.all"] = @"Purebred Credentials (all)";
            self.zipNameDictionary[@"purebred.zip.all_user"] = @"Purebred Credentials (all user)";
            self.zipNameDictionary[@"purebred.zip.signature"] = @"Purebred Credentials (signature)";
            self.zipNameDictionary[@"purebred.zip.encryption"] = @"Purebred Credentials (encryption)";
            self.zipNameDictionary[@"purebred.zip.authentication"] = @"Purebred Credentials (auth)";
            self.zipNameDictionary[@"purebred.zip.device"] = @"Purebred Credentials (device)";
            self.zipNameDictionary[@"purebred.zip.no_filter"] = @"Purebred Credentials (unfiltered)";

            self.selectNameDictionary = [[NSMutableDictionary alloc] init];
            self.selectNameDictionary[@"com.rsa.pkcs-12"] = @"All Credentials (PKCS-12)";
            self.selectNameDictionary[@"purebred.select.all"] = @"All Credentials";
            self.selectNameDictionary[@"purebred.select.all_user"] = @"All User Credentials";
            self.selectNameDictionary[@"purebred.select.signature"] = @"Digital Signature Credentials";
            self.selectNameDictionary[@"purebred.select.encryption"] = @"Encryption Credentials";
            self.selectNameDictionary[@"purebred.select.authentication"] = @"Authentication Credentials";
            self.selectNameDictionary[@"purebred.select.device"] = @"Device Credentials";
            self.selectNameDictionary[@"purebred.select.no_filter"] = @"All Credentials (unfiltered)";

            self.password = password;
        }
        return self;
    }

    + (int) GetNumberOfFolders
    {
        NSArray* selectUtis = [FileProviderEnumerator getSelectUtis];
        return (int)[selectUtis count];
    }

    + (NSArray*) getSelectUtis
    {
        NSMutableArray* selectUtis = [[NSMutableArray alloc]init];
        [selectUtis addObject:@"com.rsa.pkcs-12"];
        [selectUtis addObject:@"purebred.select.all"];
        [selectUtis addObject:@"purebred.select.all_user"];
        [selectUtis addObject:@"purebred.select.signature"];
        [selectUtis addObject:@"purebred.select.encryption"];
        [selectUtis addObject:@"purebred.select.authentication"];
        [selectUtis addObject:@"purebred.select.device"];
        [selectUtis addObject:@"purebred.select.no_filter"];
        return selectUtis;
    }
    + (NSArray*) getZipUtis;
    {
        NSMutableArray* zipUtis = [[NSMutableArray alloc]init];
        [zipUtis addObject:@"purebred.zip.all"];
        [zipUtis addObject:@"purebred.zip.all_user"];
        [zipUtis addObject:@"purebred.zip.signature"];
        [zipUtis addObject:@"purebred.zip.encryption"];
        [zipUtis addObject:@"purebred.zip.authentication"];
        [zipUtis addObject:@"purebred.zip.device"];
        [zipUtis addObject:@"purebred.zip.no_filter"];
        return zipUtis;
    }

    - (void)currentSyncAnchorWithCompletionHandler:(void(^)(_Nullable NSFileProviderSyncAnchor currentAnchor))completionHandler
    {
        NSTimeInterval d = [[NSDate date] timeIntervalSince1970];
        completionHandler([NSData dataWithBytes:&d length:sizeof(NSTimeInterval)]);
    }

    - (void)enumerateChangesForObserver:(id<NSFileProviderChangeObserver>)observer fromSyncAnchor:(NSFileProviderSyncAnchor)anchor {
        // TODO implement by having the sync anchor be a serialized list of files
        [observer finishEnumeratingChangesUpToSyncAnchor:anchor moreComing:NO];
    }

    - (void) invalidate
    {
    }

    - (void) enumerateItemsForObserver:(id<NSFileProviderEnumerationObserver>)observer startingAtPage:(NSFileProviderPage)page
    {
        NSMutableArray* items = [[NSMutableArray alloc]init];

        NSArray* selectUtis = [FileProviderEnumerator getSelectUtis];
        //[selectUtis addObject:@"purebred.select.no_filter"];

        if([self.identifier isEqualToString:NSFileProviderRootContainerItemIdentifier]){
            for(int ii = 0; ii < selectUtis.count; ++ii) {
                NSString* curSelectUti = selectUtis[ii];
                KeyChainDataSource* keyChain = [[KeyChainDataSource alloc]initWithMode:KSM_Identities password:self.password];
                [keyChain LoadKeyChainContents:[NSArray arrayWithObjects:curSelectUti, nil]];
                int numKeys = (int)[keyChain numItems];
                
                FileProviderItemFolder* fUti = [[FileProviderItemFolder alloc]initWithIdentifier:(NSFileProviderItemIdentifier)curSelectUti path:self.selectNameDictionary[curSelectUti] size:numKeys];
                [items addObject:fUti];
                keyChain = nil;
            }
        }
        else {
            for(int ii = 0; ii < selectUtis.count; ++ii) {
                if([self.identifier isEqualToString:selectUtis[ii]]) {
                    NSString* curSelectUti = selectUtis[ii];
                    KeyChainDataSource* keyChain = [[KeyChainDataSource alloc]initWithMode:KSM_Identities password:self.password];
                    if([curSelectUti isEqualToString:@"purebred.select.no_filter"]) {
                        [keyChain LoadKeyChainContents:[NSArray arrayWithObjects:curSelectUti, @"purebred.select.all_user", nil]];
                    }
                    else {
                        [keyChain LoadKeyChainContents:[NSArray arrayWithObjects:curSelectUti, nil]];
                    }
                    int numKeys = (int)[keyChain numItems];
                    
                    // include zip in folder
                    if(0 < numKeys && ![curSelectUti isEqualToString:@"com.rsa.pkcs-12"])
                    {
                        NSString* correspondingZipUti = [curSelectUti stringByReplacingOccurrencesOfString:@"select" withString:@"zip"];
                        NSString* filename = [NSString stringWithFormat:@"%@.zip", correspondingZipUti];
                        NSFileProviderItem fi = [[FileProviderItemKey alloc]initWithIdentifier:(NSFileProviderItemIdentifier)correspondingZipUti path:filename size:1 uti:correspondingZipUti friendlyName:self.zipNameDictionary[correspondingZipUti] notBefore:nil parentIdentifier:curSelectUti];
                        [items addObject:fi];
                    }

                    for (int jj = 0; jj < numKeys; ++jj) {
                        NSString *strPath = [NSString stringWithFormat:@"%@+%d.p12",curSelectUti, jj];
                        NSString *strId = [NSString stringWithFormat:@"%@+%d",curSelectUti, jj];
                        NSString* t = [keyChain getNotBeforeAt:jj];
                        NSString* n = [keyChain GetIdentityNameAtIndex:jj];
                        NSFileProviderItem fi = [[FileProviderItemKey alloc]initWithIdentifier:(NSFileProviderItemIdentifier)strId path:strPath size:1 uti:curSelectUti  friendlyName:n notBefore:t parentIdentifier:curSelectUti];
                        [items addObject:fi];
                    }
                    keyChain = nil;
                    break;
                }
            }
        }
        
        [observer didEnumerateItems:items];
        [observer finishEnumeratingUpToPage:nil];
    }
@end

//----------------------------------------------------------------------------------------------------------------------------------------------------
// FileProviderItemFolder
//----------------------------------------------------------------------------------------------------------------------------------------------------
@interface FileProviderItemFolder ()
@end

@implementation FileProviderItemFolder
    @synthesize filename;
    @synthesize itemIdentifier; 
    @synthesize parentItemIdentifier;
    @synthesize typeIdentifier;
    @synthesize documentSize;
    - (instancetype)initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:(NSString*)path size:(NSUInteger)size {
        if (self = [super init]) {
            filename = path;
            itemIdentifier = identifier;
            documentSize = [NSNumber numberWithInteger:size];
            
            if([itemIdentifier isEqualToString:NSFileProviderRootContainerItemIdentifier]) {
                //parentItemIdentifier = nil;
                parentItemIdentifier = NSFileProviderRootContainerItemIdentifier;
            }
            else {
                parentItemIdentifier = NSFileProviderRootContainerItemIdentifier;
            }
            
            typeIdentifier = (NSString*)kUTTypeFolder;
        }
        return self;
    }
@end

//----------------------------------------------------------------------------------------------------------------------------------------------------
// FileProviderItemKey
//----------------------------------------------------------------------------------------------------------------------------------------------------
@interface FileProviderItemKey ()
    @property (readonly) NSString* path;
    @property (readonly) NSFileProviderItemIdentifier identifier;
    @property (readonly) NSFileProviderItemIdentifier parentIdentifier;
    @property (readonly) NSUInteger size;
@end

@implementation FileProviderItemKey
    @synthesize typeIdentifier;
    @synthesize creationDate;
    @synthesize friendlyName;
- (instancetype)initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:(NSString*)path size:(NSUInteger)size uti:(NSString*)uti friendlyName:(NSString*)friendlyName notBefore:(NSString*)notBefore parentIdentifier:(NSFileProviderItemIdentifier)parentIdentifier {
        if (self = [super init]) {
            _path = identifier;
            _identifier = identifier;
            _size = size;
            typeIdentifier = uti;
            _parentIdentifier = parentIdentifier;
            
            NSDateFormatter* f = [[NSDateFormatter alloc]init];
            notBefore = [notBefore stringByReplacingOccurrencesOfString:@"  " withString:@" "];
            [f setDateFormat:@"MM d HH:mm:ss yyyy zzz"];
            creationDate = [f dateFromString:notBefore];
            self.friendlyName = friendlyName;
        }
        return self;
    }
    - (NSString *)filename {
        // The UI dislikes the periods in UTIs. Replace with spaces for display purposes.
        NSString* t = [self.friendlyName stringByReplacingOccurrencesOfString:@"." withString:@" "];
        return t;
    }
    - (NSNumber* )documentSize {
        return [NSNumber numberWithInteger:_size];
    }
     - (NSFileProviderItemCapabilities)capabilities {
         return NSFileProviderItemCapabilitiesAllowsReading;
     }
    - (BOOL) isRoot {
        BOOL b = [self.path isEqualToString:NSFileProviderRootContainerItemIdentifier];
        return b;
    }
    - (NSFileProviderItemIdentifier)parentItemIdentifier {
        return _parentIdentifier;
    }
    -
    (NSFileProviderItemIdentifier) itemIdentifier {
        return _identifier;
    }
@end
