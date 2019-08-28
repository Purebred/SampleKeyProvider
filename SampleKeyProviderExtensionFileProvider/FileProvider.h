//
//  FileProvider.h
//  SampleKeyProviderExtensionFileProvider

#import <UIKit/UIKit.h>

#import <FileProvider/FileProvider.h>
#import <MobileCoreServices/MobileCoreServices.h>

@interface FileProvider : NSFileProviderExtension

+ (BOOL) isZipIdentifier:(NSString*)identifier;
+ (NSURL*) getZipPlaceholderUrl:(NSString*)identifier;
+ (NSURL*) getP12PlaceholderUrl:(NSString*)identifier;

@property (nonatomic, retain) NSString* password;
@end
