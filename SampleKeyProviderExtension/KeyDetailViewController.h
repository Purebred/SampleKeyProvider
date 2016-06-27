//
//  KeyDetailViewController.h
//  PurebredRegistration

#import <UIKit/UIKit.h>
#import "KeyChainDataSource.h"
#import "DocumentPickerViewController.h"

@interface KeyDetailViewController : UIViewController<UITableViewDelegate, UITableViewDataSource>
{
    KeyChainDataSource* keyChain;
    //IBOutlet UITableView* tableView;
}
@property (nonatomic, retain) IBOutlet UITableView *tableView;
@property (nonatomic, retain) IBOutlet UIButton *importButton;
@property (nonatomic, retain) IBOutlet UIButton *cancelButton;
@property (nonatomic, retain) KeyChainDataSource *keyChain;
@property (nonatomic, retain) DocumentPickerViewController *dpvc;
@property (nonatomic, assign) long itemIndex;
@end
