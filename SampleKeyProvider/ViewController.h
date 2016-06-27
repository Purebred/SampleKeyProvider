//
//  ViewController.h
//  KeyShareProvider

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

// import from iTunes
- (IBAction)onImportPkcs12:(id)sender;

// import P12s from app bundle
- (IBAction)onImportSamplePkcs12:(id)sender;

// clear provider key chain
- (IBAction)onClearKeyChain:(id)sender;


@end
