The SampleKeyProvider app is intended to provide an implementation of the document provider interface exposed by the Purebred Registration app to facilitate testing without needing to enroll with a Purebred server. PKCS 12 files can be imported into the SampleKeyProvider app using iTunes file sharing. Alternative, four P12 files similar to credentials from a test Red Hat CA instance are included in the app and can be imported into the key chain directly.  

Document provider extensions were introduced in iOS 8 and are described [here](https://developer.apple.com/library/ios/documentation/General/Conceptual/ExtensibilityPG/FileProvider.html). As additional background, a sample document provider was presented during the WWDC 2014 conference. Source code is available [here](https://github.com/master-nevi/WWDC-2014/tree/master/NewBox%20An%20Introduction%20to%20iCloud%20Document%20enhancements%20in%20iOS%208.0).

Purebred Registration provides the key sharing interface as an easier alternative to importing PKCS12 files using iTunes file sharing or implementing support for a certificate enrollment protocol. Using the interface requires your app to present the `UIDocumentPickerViewController`, which will enable the user to select which key to import, and implement the `UIDocumentPickerDelegate` interface, which will enable your app to import keys. In the Key Share Consumer sample, this code is present in `ViewController.m`. A `UIDocumentPickerViewController` instance is displayed in the click handler for the "Import Key" button. The `ViewController` class implements `UIDocumentPickerDelegate`.

When the user uses the Purebred Registration app interface, the PKCS12 password is passed to your app via the pasteboard. When the user selects a file from their iCloud account, the user will need to be prompted to enter a password. In either case, the PKCS12 file and password are processed in the `importP12` method of the `ViewController` class. To enable the Purebred Registration interface tap Import Key then tap Locations. This will display a list of providers including More. Tap More. If the Purebred Registration app is installed, it will be listed on the Manage Storage Providers view. Turn the switch on for the Purebred Key Chain row then tap Done. Now when Import Key and Locations are tapped, the Purebred Key Chain option will be available.

The list of keys displayed by a provider can be filtered using a uniform type identifier (UTI) value that indicates the type of key the caller wants to import. The list of UTIs currently supported by the Purebred Registration app and SampleKeyProvider app are as follows:

* com.rsa.pkcs-12
* purebred.select.all
* purebred.select.all-user
* purebred.select.device
* purebred.select.signature
* purebred.select.encryption
* purebred.select.authentication
* purebred.zip.all
* purebred.zip.all-user
* purebred.zip.device
* purebred.zip.signature
* purebred.zip.encryption
* purebred.zip.authentication
* purebred.zip.no-filter

NOTE* For custom app UTIs with "_" have been replaced with "-". 

By default, the Purebred Registration app serves up the most recent keys for the indicated types. The no_filter option can be used to cause all available keys for the indicated types to be displayed. 

Details on obtaining and testing the Purebred Registration app will be posted soon. See [here](https://cyber.mil/pki-pke/purebred).






