//
//  FileProviderHelpers.m
//  SampleKeyProviderExtensionFileProvider
//

#import <Foundation/Foundation.h>
#import <FileProvider/FileProvider.h>
#import <MobileCoreServices/MobileCoreServices.h>

@interface FileProviderItemKey : NSObject <NSFileProviderItem>

- (instancetype)initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:(NSString*)path size:(NSUInteger)size uti:(NSString*)uti friendlyName:(NSString*)friendlyName notBefore:(NSString*)notBefore parentIdentifier:(NSFileProviderItemIdentifier)parentIdentifier;
@property (nonatomic, retain) NSString* friendlyName;

@end

@interface FileProviderItemFolder : NSObject <NSFileProviderItem>

- (instancetype)initWithIdentifier:(NSFileProviderItemIdentifier)identifier path:(NSString*)path size:(NSUInteger)size;

@end

@interface FileProviderEnumerator : NSObject <NSFileProviderEnumerator>

+ (NSArray*) getSelectUtis;
+ (NSArray*) getZipUtis;
+ (int) GetNumberOfFolders;

- (instancetype)initWithItemIdentifier:(NSFileProviderItemIdentifier)identifier;
- (instancetype)initWithItemIdentifier:(NSFileProviderItemIdentifier)identifier password:(NSString*)password;
@property (nonatomic, retain) NSMutableDictionary* zipNameDictionary;
@property (nonatomic, retain) NSMutableDictionary* selectNameDictionary;

@end

// poached from https://stackoverflow.com/questions/1305225/best-way-to-serialize-an-nsdata-into-a-hexadeximal-string/9009321
@interface NSData (NSData_Conversion)

#pragma mark - String Conversion
- (NSString *)hexadecimalString;

@end
