//
//  DocumentPickerViewController.h
//  KeyShareProviderExtension

#import <UIKit/UIKit.h>
#import "KeyChainDataSource.h"

@interface DocumentPickerViewController : UIDocumentPickerExtensionViewController <UITableViewDelegate, UITableViewDataSource>
{
    KeyChainDataSource* keyChain;
    //int imageWidth;
    IBOutlet UITableView* tableView;
}

- (void)import:(long)index;
- (void)dismissAndUnselect;

@property (nonatomic, retain) UITableView *tableView;
@property (nonatomic, retain) KeyChainDataSource *keyChain;
@property (nonatomic, assign) int imageWidth;
@end
