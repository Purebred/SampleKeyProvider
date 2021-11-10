//
//  DocumentPickerViewController.m
//  KeyShareProviderExtension

#import "DocumentPickerViewController.h"

#import "KeyDetailViewController.h"

bool IsZipType(NSArray* utis)
{
    if([utis containsObject:@"purebred.zip.all"] ||
       [utis containsObject:@"purebred.zip.all_user"] ||
       [utis containsObject:@"purebred.zip.all-user"] ||
       [utis containsObject:@"purebred.zip.device"] ||
       [utis containsObject:@"purebred.zip.signature"] ||
       [utis containsObject:@"purebred.zip.encryption"] ||
       [utis containsObject:@"purebred.zip.authentication"] ||
       [utis containsObject:@"purebred.zip.no_filter"] ||
       [utis containsObject:@"purebred.zip.no-filter"])
    {
        return true;
    }
    else{
        return false;
    }
}


@interface DocumentPickerViewController ()
@end

@implementation DocumentPickerViewController
@synthesize tableView;
@synthesize keyChain;


- (void)viewDidLoad {
    [super viewDidLoad];
    
    //Set this view controller as the delegate for the tableView. This class
    //will mediate access to the actual data source instead of having the key
    //chain class itself play this role.
    [tableView setDelegate:self];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    NSIndexPath *indexPath = self.tableView.indexPathForSelectedRow;
    if (indexPath) {
        [self.tableView deselectRowAtIndexPath:indexPath animated:animated];
    }
}

- (void)dismissAndUnselect
{
    NSIndexPath *indexPath = self.tableView.indexPathForSelectedRow;
    if (indexPath) {
        [self.tableView deselectRowAtIndexPath:indexPath animated:FALSE];
    }
}

-(void)prepareForPresentationInMode:(UIDocumentPickerMode)mode {
    // TODO: present a view controller appropriate for picker mode here
    keyChain = [[KeyChainDataSource alloc] initWithMode:KSM_Identities];
    [keyChain LoadKeyChainContents:self.validTypes];
}

#pragma mark - Table view data source
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    //The KeyChainDataSource is written to supply cells in groups where each group is an identity.
    //This view is written to list each identity on one row.  Thus, return the number of sections
    //recognized by the data source.
    return [keyChain numItems];
}
#define FONT_SIZE 14.0f
#define CELL_CONTENT_MARGIN 10.0f

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath;
{
    NSString *text = [keyChain GetIdentityNameAtIndex:indexPath.row];
    
    CGRect frameRect = [self.tableView frame];
    //CGSize constraint = CGSizeMake(frameRect.size.width - (CELL_CONTENT_MARGIN * 2), 20000.0f);
    
    //CGSize size = [text sizeWithFont:[UIFont systemFontOfSize:FONT_SIZE] constrainedToSize:constraint lineBreakMode:NSLineBreakByCharWrapping];
 
    NSAttributedString *attributedText =
        [[NSAttributedString alloc]
            initWithString:text
            attributes:@
            {
                NSFontAttributeName: [UIFont systemFontOfSize:FONT_SIZE]
            }];
    CGRect rect = [attributedText boundingRectWithSize:(CGSize){frameRect.size.width, CGFLOAT_MAX}
                                               options:NSStringDrawingUsesLineFragmentOrigin
                                               context:nil];
    CGSize size = rect.size;

    CGFloat height = MAX(size.height, 44.0f);
    
    return height + (CELL_CONTENT_MARGIN * 2);
}

- (UITableViewCell *)tableView:(UITableView *)tableViewParam cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    static NSString *CellIdentifier = @"Cell";
    
    UILabel* label = nil;
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];
    if (cell == nil)
    {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier] ;
        
        label = [[UILabel alloc] initWithFrame:CGRectZero] ;
        [label setLineBreakMode:NSLineBreakByCharWrapping];
        //[label setMinimumFontSize:FONT_SIZE];
        [label setNumberOfLines:0];
        [label setFont:[UIFont systemFontOfSize:FONT_SIZE]];
        [label setTag:1];
        
        [[cell contentView] addSubview:label];
        
    }
    NSString *text = [keyChain GetIdentityNameAtIndex:indexPath.row];
    
    CGRect frameRect = [self.tableView frame];
    //CGSize constraint = CGSizeMake(frameRect.size.width - (CELL_CONTENT_MARGIN * 2), 20000.0f);
    
    //CGSize size = [text sizeWithFont:[UIFont systemFontOfSize:FONT_SIZE] constrainedToSize:constraint lineBreakMode:NSLineBreakByCharWrapping];
    
    NSAttributedString *attributedText =
        [[NSAttributedString alloc]
            initWithString:text
            attributes:@
            {
                NSFontAttributeName: [UIFont systemFontOfSize:FONT_SIZE]
            }];
    CGRect rect = [attributedText boundingRectWithSize:(CGSize){frameRect.size.width, CGFLOAT_MAX}
                                               options:NSStringDrawingUsesLineFragmentOrigin
                                               context:nil];
    CGSize size = rect.size;

    if (!label)
        label = (UILabel*)[cell viewWithTag:1];
    
    //display the keys icon for each entry in the table
    UIImage* image = [UIImage imageNamed:@"0155-keys.png"];
    [cell.imageView setImage:image];
    
    self.imageWidth = 44;
    
    [label setText:text];
    [label setFrame:CGRectMake((CELL_CONTENT_MARGIN*2) + self.imageWidth, CELL_CONTENT_MARGIN, frameRect.size.width - (CELL_CONTENT_MARGIN * 2) - self.imageWidth, MAX(size.height, 44.0f))];
    
    cell.accessoryType = UITableViewCellAccessoryDetailDisclosureButton;
    
    return cell;
}

- (UITableViewCellEditingStyle)tableView:(UITableView *)aTableView
           editingStyleForRowAtIndexPath:(NSIndexPath *)indexPath
{
    return UITableViewCellEditingStyleDelete;
}

- (void)tableView:(UITableView *)tableViewParam commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath
{
    // If the table view is asking to commit a delete command...
    if (editingStyle == UITableViewCellEditingStyleDelete)
    {
        // We remove the row being deleted from the source
        [keyChain removeObjectAtIndex:[indexPath row]];
        
        [tableView reloadData];
    }
}

#pragma mark - Table view delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    UIStoryboard *storyboard = [UIStoryboard storyboardWithName:@"MainInterface" bundle: nil];
    KeyDetailViewController *kdvc = [storyboard instantiateViewControllerWithIdentifier:@"KeyDetailViewController"];
    [kdvc setKeyChain:[self keyChain]];
    [kdvc setItemIndex:indexPath.row];
    [kdvc setDpvc:self];
    [self presentViewController:kdvc animated:YES completion:nil];
}

- (void) import:(long)row
{
    //check validTypes for zip file type
    if(IsZipType(self.validTypes))
    {
        NSData* p12 = [keyChain GetPKCS12Zip];
        if(!p12)
        {
            //XXXDEFER Really need a UI here. UIAlertView and friends are not available. Apparently simulated Toast messages are possible and
            //should be investigated for next release.
            NSLog(@"Failed to retrieve PKCS #12 item from key chain");
            return;
        }
        NSFileCoordinator *fileCoordinator = [[NSFileCoordinator alloc] init];
        [fileCoordinator setPurposeIdentifier:[self providerIdentifier]];
        NSURL *placeholderURL = [NSFileProviderExtension placeholderURLForURL:[self.documentStorageURL URLByAppendingPathComponent:@"tmp.zip"]];
        
        [p12 writeToFile:placeholderURL.path atomically:YES];
        
        NSLog(@"Allowing access to %@ for %lu bytes", placeholderURL.path, (unsigned long)p12.length);
        
        [self dismissGrantingAccessToURL:placeholderURL];
    }
    else
    {
        NSData* p12 = [keyChain GetPKCS12AtIndex:row];
        if(!p12)
        {
            //XXXDEFER Really need a UI here. UIAlertView and friends are not available. Apparently simulated Toast messages are possible and
            //should be investigated for next release.
            NSLog(@"Failed to retrieve PKCS #12 item from key chain");
            return;
        }
        NSFileCoordinator *fileCoordinator = [[NSFileCoordinator alloc] init];
        [fileCoordinator setPurposeIdentifier:[self providerIdentifier]];
        NSURL *placeholderURL = [NSFileProviderExtension placeholderURLForURL:[self.documentStorageURL URLByAppendingPathComponent:@"tmp.p12"]];
        
        [p12 writeToFile:placeholderURL.path atomically:YES];
        
        NSLog(@"Allowing access to %@ for %lu bytes", placeholderURL.path, (unsigned long)p12.length);
        
        [self dismissGrantingAccessToURL:placeholderURL];
    }
}

@end
