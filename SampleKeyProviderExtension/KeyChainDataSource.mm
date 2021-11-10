//
//  KeyChainDataSource.mm
//  FileAssocTest

#import "KeyChainDataSource.h"
#import <UIKit/UIKit.h>

#include <string>
#include <sstream>

//openssl includes
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#import "ZipFile.h"
#import "ZipException.h"
#import "FileInZipInfo.h"
#import "ZipWriteStream.h"
#import "ZipReadStream.h"

enum CertType
{
    CT_UNKNOWN = 0,
    CT_DEVICE,
    CT_SIGNATURE,
    CT_ENCRYPTION,
    CT_AUTHENTICATION,
    CT_MULTI
};

bool HasEmailAddress(SecCertificateRef cert)
{
    CFDataRef cfData = SecCertificateCopyData(cert);
    
    const unsigned char* p = (const unsigned char*)CFDataGetBytePtr(cfData);
    X509 *certificateX509 = d2i_X509(NULL, &p, CFDataGetLength(cfData));
    CFRelease(cfData);
    if (certificateX509 != NULL) {
        
        STACK_OF(GENERAL_NAME) *subjectAltNames = NULL;
        
        // Try to extract the names within the SAN extension from the certificate
        subjectAltNames = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i((X509 *) certificateX509, NID_subject_alt_name, NULL, NULL);
        
        int altNameCount = sk_GENERAL_NAME_num(subjectAltNames);
        for (int ii = 0; ii < altNameCount; ++ii)
        {
            GENERAL_NAME* generalName = sk_GENERAL_NAME_value(subjectAltNames, ii);
            if (generalName->type == GEN_EMAIL)
            {
                return true;
            }
        }
    }
    return false;
}

CertType GetCertType(SecCertificateRef cert)
{
    CFDataRef cfData = SecCertificateCopyData(cert);
    
    const unsigned char* p = (const unsigned char*)CFDataGetBytePtr(cfData);
    X509 *certificateX509 = d2i_X509(NULL, &p, CFDataGetLength(cfData));
    CFRelease(cfData);
    if (certificateX509 != NULL) {
        
        int digitalSignature = 0;
        int nonRepudiation = 0;
        int keyEncipherment = 0;
        ASN1_BIT_STRING *keyUsage = (ASN1_BIT_STRING *)X509_get_ext_d2i((X509 *) certificateX509, NID_key_usage, NULL, NULL);
        if(NULL == keyUsage)
        {
            return CT_DEVICE;
        }
        else
        {
            digitalSignature = ASN1_BIT_STRING_get_bit(keyUsage, 0);
            nonRepudiation = ASN1_BIT_STRING_get_bit(keyUsage, 1);
            keyEncipherment = ASN1_BIT_STRING_get_bit(keyUsage, 2);
            
            if(digitalSignature && keyEncipherment)
                return CT_MULTI;
            else if(digitalSignature && nonRepudiation)
            {
                return CT_SIGNATURE;
            }
            else if(digitalSignature)
            {
                if(HasEmailAddress(cert))
                    return CT_SIGNATURE;
                else
                    return CT_AUTHENTICATION;
            }
            else if(keyEncipherment)
                return CT_ENCRYPTION;
        }
    }
    
    return CT_UNKNOWN;
}

bool IsZipType(NSArray* utis)
{
    if([utis containsObject:@"purebred.zip.all"] ||
       [utis containsObject:@"purebred.zip.all_user"] ||
       [utis containsObject:@"purebred.zip.all-user"] ||
       [utis containsObject:@"purebred.zip.device"] ||
       [utis containsObject:@"purebred.zip.signature"] ||
       [utis containsObject:@"purebred.zip.encryption"] ||
       [utis containsObject:@"purebred.zip.authentication"])
    {
        return true;
    }
    else{
        return false;
    }
}

bool ZippedCertTypeRequested(SecCertificateRef cert, NSArray* utis)
{
    if(nil == utis || [utis containsObject:@"purebred.zip.all"])
    {
        return true;
    }
    
    CertType ct = GetCertType(cert);
    if(CT_UNKNOWN == ct)
        return false;
    else if(CT_DEVICE != ct && [utis containsObject:@"purebred.zip.all_user"])
        return true;
    else if(CT_DEVICE != ct && [utis containsObject:@"purebred.zip.all-user"])
        return true;
    else if(CT_DEVICE == ct && [utis containsObject:@"purebred.zip.device"])
        return true;
    else if(CT_SIGNATURE == ct && [utis containsObject:@"purebred.zip.signature"])
        return true;
    else if(CT_ENCRYPTION == ct && [utis containsObject:@"purebred.zip.encryption"])
        return true;
    else if(CT_AUTHENTICATION == ct && [utis containsObject:@"purebred.zip.authentication"])
        return true;
    
    return false;
}

bool CertTypeRequested(SecCertificateRef cert, NSArray* utis)
{
    if(nil == utis || [utis containsObject:@"com.rsa.pkcs-12"] || [utis containsObject:@"purebred.select.all"])
    {
        return true;
    }
    
    CertType ct = GetCertType(cert);
    if(CT_UNKNOWN == ct)
        return false;
    else if(CT_DEVICE != ct && [utis containsObject:@"purebred.select.all_user"])
        return true;
    else if(CT_DEVICE != ct && [utis containsObject:@"purebred.select.all-user"])
        return true;
    else if(CT_DEVICE == ct && [utis containsObject:@"purebred.select.device"])
        return true;
    else if(CT_SIGNATURE == ct && [utis containsObject:@"purebred.select.signature"])
        return true;
    else if(CT_ENCRYPTION == ct && [utis containsObject:@"purebred.select.encryption"])
        return true;
    else if(CT_AUTHENTICATION == ct && [utis containsObject:@"purebred.select.authentication"])
        return true;
    
    return false;
}

int PrepareAndExportPkcs12(
    //![in]
    unsigned char* keyBuf,
    int keyBufLen,
    //![in]
    unsigned char* certBuf,
    int certBufLen,
    //![out]
    unsigned char** p12Buf,
    int* p12BufLen,
    //![in]
    const char* inputPassword,
    //![out]
    std::string& password)
{
    password = inputPassword;
    
    int rv = FIPS_mode_set(0);
    OpenSSL_add_all_algorithms();
    
    rv = 0;
    
    PKCS8_PRIV_KEY_INFO *p8i = 0;
    EVP_PKEY *privkey = 0;
    X509 *cert = 0;
    PKCS12 *p12 = 0;
    
    BIO *berr = NULL;
    BIO *keybio = NULL;
    BIO *certbio = NULL;
    BIO *p12bio = NULL;
    
    //create bio for stderr but don't fail if not created (just don't use and don't free below)
    berr = BIO_new_fp(stderr, BIO_NOCLOSE);
    
    //create a bio containing the PKCS8 object passed in
    keybio = BIO_new_mem_buf((void *) keyBuf, keyBufLen);
    if (!keybio) {
        BIO_free(berr);
        return -1;
    }
    
    //create a buffer containing the certificate passed in
    certbio = BIO_new_mem_buf((void *) certBuf, certBufLen);
    if (!certbio) {
        BIO_free(berr);
        BIO_free(keybio);
        return -2;
    }
    
    //create a bio to receive the encoded PKCS12
    p12bio = BIO_new(BIO_s_mem());
    if (!p12bio) {
        BIO_free(berr);
        BIO_free(keybio);
        BIO_free(certbio);
        return -3;
    }
    
    try {
        //try to parse the PKCS8 buffer loaded into the keybio above
        p8i = d2i_PKCS8_PRIV_KEY_INFO_bio(keybio, NULL);
        if (!p8i)
        {
            BIO_free(keybio);
            keybio = BIO_new_mem_buf((void *) keyBuf, keyBufLen);
            if (!keybio) {
                BIO_free(berr);
                return -1;
            }
            privkey = d2i_PrivateKey_bio(keybio, NULL);
            if(!privkey) throw std::runtime_error("Error converting key from PKCS#8 structure to RSA structure");
        }
        else
        {
            //extract the private key from the PKCS8 object
            privkey = EVP_PKCS82PKEY(p8i);
            if (!privkey)
                throw std::runtime_error("Error converting key from PKCS#8 structure to RSA structure");
        }
        
        //try to parse the certificate loaded into the certbio above
        cert = d2i_X509_bio(certbio, NULL);
        if (!cert)
            throw std::runtime_error("Error reading certificate.");
        
        //create a new PKCS12 object containing the certificate and private key
        p12 = PKCS12_create(const_cast<char *>(password.c_str()), cert->name, privkey, cert, 0, 0, -1, 0, 0, 0);
        if (!p12)
        {
            long errcode = ERR_get_error();
            while( errcode ) {
                char errstring[1024];
                memset(errstring, 0x00, sizeof(errstring));
                ERR_error_string_n(errcode, errstring, sizeof(errstring));
                errcode = ERR_get_error();
            }
            ERR_clear_error();
            throw std::runtime_error("Error constructing PKCS#12 object");
        }
        
        //encode the PKCS12 object into the p12bio
        if (!i2d_PKCS12_bio(p12bio, p12))
            throw std::runtime_error("Unable to emit p12");
        
        //get a pointer to the encoded PKCS 12 object
        BUF_MEM *ptr = NULL;
        BIO_get_mem_ptr(p12bio, &ptr);
        
        *p12BufLen = (int)ptr->length;
        (*p12Buf) = (unsigned char*)malloc(*p12BufLen);
        memcpy(*p12Buf, ptr->data, *p12BufLen);
    }
    catch (std::exception &e) {
        //log_openssl_errors();
        std::ostringstream oss;
        oss << "Caught exception in PrepareAndExportPkcs12: " << e.what() << std::endl;
        if (berr)
            ERR_print_errors(berr);
        rv = -4;
    }
    
    //clean-up
    if (p12) PKCS12_free(p12);
    if (cert) X509_free(cert);
    if (p8i) PKCS8_PRIV_KEY_INFO_free(p8i);
    if (privkey) EVP_PKEY_free(privkey);
    if (berr) BIO_free(berr);
    BIO_free(keybio);
    BIO_free(certbio);
    BIO_free(p12bio);
    
    //return will either be 0 or -4 (because an exception was caught)
    return rv;
}

//--------------------------------------------------------------
// Arrays containing attributes for each type of item associated
// with this class: certificate, key, identity
//--------------------------------------------------------------
CFTypeRef g_certAttrs[] = {
    kSecAttrAccessible,
    kSecAttrAccessGroup,
    kSecAttrCertificateType,
    kSecAttrCertificateEncoding,
    kSecAttrLabel,
    kSecAttrSubject,
    kSecAttrIssuer,
    kSecAttrSerialNumber,
    kSecAttrSubjectKeyID,
    kSecAttrPublicKeyHash,
    NULL
};

CFTypeRef g_keyAttrs[] = {
    kSecAttrAccessible,
    kSecAttrAccessGroup,
    kSecAttrKeyClass,
    kSecAttrLabel,
    kSecAttrApplicationLabel,
    kSecAttrIsPermanent,
    kSecAttrApplicationTag,
    kSecAttrKeyType,
    kSecAttrKeySizeInBits,
    kSecAttrEffectiveKeySize,
    kSecAttrCanEncrypt,
    kSecAttrCanDecrypt,
    kSecAttrCanDerive,
    kSecAttrCanSign,
    kSecAttrCanVerify,
    kSecAttrCanWrap,
    kSecAttrCanUnwrap,
    NULL
};

CFTypeRef g_identityAttrs[] = {
    kSecAttrAccessible,
    kSecAttrAccessGroup,
    kSecAttrCertificateType,
    kSecAttrCertificateEncoding,
    kSecAttrLabel,
    kSecAttrSubject,
    kSecAttrIssuer,
    kSecAttrSerialNumber,
    kSecAttrSubjectKeyID,
    kSecAttrPublicKeyHash,
    kSecAttrKeyClass,
    kSecAttrApplicationLabel,
    kSecAttrIsPermanent,
    kSecAttrApplicationTag,
    kSecAttrKeyType,
    kSecAttrKeySizeInBits,
    kSecAttrEffectiveKeySize,
    kSecAttrCanEncrypt,
    kSecAttrCanDecrypt,
    kSecAttrCanDerive,
    kSecAttrCanSign,
    kSecAttrCanVerify,
    kSecAttrCanWrap,
    kSecAttrCanUnwrap,
    NULL
};

//--------------------------------------------------------------
// Arrays containing attributes that are grouped together in a 
// single table cell for display purposes, i.e., a single string
// is returned containing information for all attributes in the 
// group.
//--------------------------------------------------------------
CFTypeRef g_keyRelatedAttrs[] = {
    kSecAttrKeyClass,
    kSecAttrKeyType,
    kSecAttrKeySizeInBits,
    kSecAttrEffectiveKeySize,
    NULL
};

CFTypeRef g_capabilityRelatedAttrs[] = {
    kSecAttrCanEncrypt,
    kSecAttrCanDecrypt,
    kSecAttrCanDerive,
    kSecAttrCanSign,
    kSecAttrCanVerify,
    kSecAttrCanWrap,
    kSecAttrCanUnwrap,
    NULL
};

CFTypeRef g_certRelatedAttrs[] = {
    kSecAttrCertificateType,
    kSecAttrCertificateEncoding,
    kSecAttrSubject,
    kSecAttrIssuer,
    kSecAttrSerialNumber,
    kSecAttrSubjectKeyID,
    kSecAttrPublicKeyHash,
    NULL
};

CFTypeRef g_miscRelatedAttrs[] = {
    kSecAttrLabel,
    kSecAttrAccessible,
    kSecAttrAccessGroup,
    kSecAttrApplicationLabel,
    kSecAttrIsPermanent,
    kSecAttrApplicationTag,
    NULL
};

//--------------------------------------------------------------
// Internal conversion helper functions
//--------------------------------------------------------------
@interface KeyChainDataSource (ConversionRoutines)

    //These return strings that should be autoreleased
    + (NSString*) getCFDateAsString:(CFDateRef) date;
    + (NSString*) getCFNumberAsString:(CFNumberRef) number;
    + (NSString*) getCFBooleanAsString:(CFBooleanRef) cfBool;
    + (NSString*) getCertificateTypeAsString:(CFNumberRef) number;
    + (NSString*) getKeyTypeAsString:(CFNumberRef) number;
    + (NSString*) getKeyClassAsString:(CFNumberRef) number;
    + (NSString*) getCertificateEncodingAsString:(CFNumberRef) number;
    + (NSString*) getAttrAccessibleAsString:(CFStringRef) attrAccessible;

    //The return freshly alloc'ed string
    + (NSString*) getDataAsAsciiHexString:(NSData*)data;
    + (NSString*) getDataAsNameString:(NSData*)data;

@end

@implementation KeyChainDataSource (ConversionRoutines)

+ (NSString*) getCFDateAsString:(CFDateRef) date
{
    NSDate* nsDate = (__bridge NSDate*)date;
    return [nsDate description];
}

+ (NSString*) getCFNumberAsString:(CFNumberRef) number
{
    NSNumber* nsNumber = (__bridge NSNumber*)number;
    return [nsNumber stringValue];
}

+ (NSString*) getCFBooleanAsString:(CFBooleanRef) cfBool
{
    if(CFBooleanGetValue(cfBool))
        return NSLocalizedString(@"Yes", nil);
    else
        return NSLocalizedString(@"No", nil);
}

+ (NSString*) getCertificateTypeAsString:(CFNumberRef) number
{
    NSNumber* nsNumber = (__bridge NSNumber*)number;
    switch([nsNumber intValue])
    {
        case 1:
            return NSLocalizedString(@"X509v1", nil);
        case 2:     
            return NSLocalizedString(@"X509v2", nil);
        case 3:    
            return NSLocalizedString(@"X509v3", nil);
        default:
            return NSLocalizedString(@"Unknown type", nil);
    }
}

+ (NSString*) getKeyClassAsString:(CFNumberRef) number
{
    NSString* nStr = [self getCFNumberAsString:number];

    if(NSOrderedSame == [(NSString*)kSecAttrKeyClassPublic compare:nStr])
        return NSLocalizedString(@"Public key", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrKeyClassPrivate compare:nStr])
        return NSLocalizedString(@"Private key", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrKeyClassSymmetric compare:nStr])
        return NSLocalizedString(@"Symmetric key", nil);
    else
        return NSLocalizedString(@"Unknown type", nil);
}

+ (NSString*) getKeyTypeAsString:(CFNumberRef) number
{
    NSString* nStr = [self getCFNumberAsString:number];
    
    if(NSOrderedSame == [(NSString*)kSecAttrKeyTypeRSA compare:nStr])
        return NSLocalizedString(@"RSA", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrKeyTypeRSA compare:nStr])
        return NSLocalizedString(@"Elliptic curve", nil);
    else
        return NSLocalizedString(@"Unknown type", nil);
}

+ (NSString*) getAttrAccessibleAsString:(CFStringRef) attrAccessible
{
    NSString* nStr = (__bridge NSString*)attrAccessible;

    if(NSOrderedSame == [(NSString*)kSecAttrAccessibleWhenUnlocked compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleWhenUnlocked", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrAccessibleAfterFirstUnlock compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleAfterFirstUnlock", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrAccessibleAlways compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleAlways", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrAccessibleWhenUnlockedThisDeviceOnly compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleWhenUnlockedThisDeviceOnly", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", nil);
    else if(NSOrderedSame == [(NSString*)kSecAttrAccessibleAlwaysThisDeviceOnly compare:nStr])
        return NSLocalizedString(@"kSecAttrAccessibleAlwaysThisDeviceOnly", nil);
    else
        return NSLocalizedString(@"Unknown type", nil);
}

+ (NSString*) getCertificateEncodingAsString:(CFNumberRef) number
{
    NSNumber* nsNumber = (__bridge NSNumber*)number;
    if(3 == [nsNumber intValue])
        return NSLocalizedString(@"DER", nil);
    else
        return NSLocalizedString(@"Unknown type", nil);
}

//poached from http://stackoverflow.com/questions/7520615/how-to-convert-an-nsdata-into-an-nsstring-hex-string
static inline char itoh(int i) {
    if (i > 9) return 'A' + (i - 10);
    return '0' + i;
}

+ (NSString*) getDataAsAsciiHexString:(NSData*)data
{
    NSUInteger i, len;
    unsigned char *buf, *bytes;
    
    len = data.length;
    bytes = (unsigned char*)data.bytes;
    buf = (unsigned char*)malloc(len*2);
    
    for (i=0; i<len; i++) {
        buf[i*2] = itoh((bytes[i] >> 4) & 0xF);
        buf[i*2+1] = itoh(bytes[i] & 0xF);
    }
    
    NSString* retval = [[NSString alloc] initWithBytesNoCopy:buf
                                          length:len*2
                                        encoding:NSASCIIStringEncoding
                                    freeWhenDone:YES];
    return retval;
}

+ (NSString*) getDataAsNameString:(NSData*)data
{
    //The value that gets stored is (for whatever reason) a Name value minus the initial sequence and
    //length bytes. Put them back (albeit this code won't handle long strings)
    
    if([data length] <= 127)
    {
        uint8_t nameLen = [data length];
        NSMutableData* completeNameEncoding = [[NSMutableData alloc]initWithLength:nameLen+2];
        unsigned char* p1 = (unsigned char*)[completeNameEncoding bytes];
        p1[0] = 0x30;
        p1[1] = nameLen;
        
        const unsigned char* p = (const unsigned char*)[data bytes];
        memcpy(&p1[2], p, nameLen);
        X509_NAME *issuerX509Name = d2i_X509_NAME(NULL, (const unsigned char**)&p1, [data length]+2);
        NSString *issuer = nil;
        if (issuerX509Name != NULL) {
            BIO *outbio=NULL;
            
            outbio=BIO_new(BIO_s_mem());
            if(X509_NAME_print_ex(outbio,issuerX509Name,0,XN_FLAG_ONELINE)>0) {
                int numWritten = (int)BIO_number_written(outbio);
                char* buf = (char*)malloc(numWritten+1);
                BIO_read(outbio,buf,numWritten);
                BIO_free(outbio);
                issuer = [NSString stringWithUTF8String:buf];
                free(buf);
            }
       }
        return issuer;
    }
    else{
        NSString* s = [self getDataAsAsciiHexString:data];
        NSLog(@"%@", s);
        return s;
    }
}

@end

//--------------------------------------------------------------
// Internal conversion helper functions
//--------------------------------------------------------------
@interface KeyChainDataSource (PrivateMethods)

- (void) populateAttrMap;
- (int) countAttributesAtIndex:(long)index;
- (NSString*) getAttrValueAsString:(CFTypeRef)attribute value:(CFTypeRef)value;

@end

@implementation KeyChainDataSource (PrivateMethods)

- (void) populateAttrMap
{
    if(attrNames)
    {
        //[attrNames release];
        attrNames = nil;
    }
    
    attrNames = [[NSMutableDictionary alloc] init];
    
    //Set up the friendly names for each attribute that can be read from one 
    //of the three types of items this class cares about.
    [attrNames setObject:(id)@"Accessible" forKey:(id)kSecAttrAccessible];
    [attrNames setObject:(id)@"Access group" forKey:(id)kSecAttrAccessGroup];
    [attrNames setObject:(id)@"Certificate type" forKey:(id)kSecAttrCertificateType];
    [attrNames setObject:(id)@"Certificate encoding" forKey:(id)kSecAttrCertificateEncoding];
    [attrNames setObject:(id)@"Label" forKey:(id)kSecAttrLabel];
    [attrNames setObject:(id)@"Subject" forKey:(id)kSecAttrSubject];
    [attrNames setObject:(id)@"Issuer" forKey:(id)kSecAttrIssuer];
    [attrNames setObject:(id)@"Serial number" forKey:(id)kSecAttrSerialNumber];
    [attrNames setObject:(id)@"Subject key ID" forKey:(id)kSecAttrSubjectKeyID];
    [attrNames setObject:(id)@"Public key hash" forKey:(id)kSecAttrPublicKeyHash];
    [attrNames setObject:(id)@"Key class" forKey:(id)kSecAttrKeyClass];
    [attrNames setObject:(id)@"Application label" forKey:(id)kSecAttrApplicationLabel];
    [attrNames setObject:(id)@"Is permanent" forKey:(id)kSecAttrIsPermanent];
    [attrNames setObject:(id)@"Application tag" forKey:(id)kSecAttrApplicationTag];
    [attrNames setObject:(id)@"Key type" forKey:(id)kSecAttrKeyType];
    [attrNames setObject:(id)@"Key size in bits" forKey:(id)kSecAttrKeySizeInBits];
    [attrNames setObject:(id)@"Effective key size" forKey:(id)kSecAttrEffectiveKeySize];
    [attrNames setObject:(id)@"Can encrypt" forKey:(id)kSecAttrCanEncrypt];
    [attrNames setObject:(id)@"Can decrypt" forKey:(id)kSecAttrCanDecrypt];
    [attrNames setObject:(id)@"Can derive" forKey:(id)kSecAttrCanDerive];
    [attrNames setObject:(id)@"Can sign" forKey:(id)kSecAttrCanSign];
    [attrNames setObject:(id)@"Can verify" forKey:(id)kSecAttrCanVerify];
    [attrNames setObject:(id)@"Can wrap" forKey:(id)kSecAttrCanWrap];
    [attrNames setObject:(id)@"Can unwrap" forKey:(id)kSecAttrCanUnwrap];
}

- (int) countAttributesAtIndex:(long)index
{
    if(nil != zip_items)
        return (int)zip_items.count;
    
    int count = 0;
    
    CFTypeRef* attrs = NULL;
    
    switch (mode) {
        case KSM_Certificates:
            attrs = g_certAttrs;
            break;
        case KSM_Identities:
            attrs = g_identityAttrs;
            break;
        case KSM_Keys:
            attrs = g_keyAttrs;
            break;
        default:
            return 0;
    }
    
    @try 
    {
        CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:index];
        
        for(int ii = 0; attrs[ii]; ++ii)
        {
            if(true == CFDictionaryGetValueIfPresent(dict, attrs[ii], NULL)) 
                ++count;
        }
    } 
    @catch (NSException* rangeException) 
    {
        return 0;
    }
    
    return count;
}

- (NSString*) getAttrValueAsString:(CFTypeRef)attribute value:(CFTypeRef)value
 {
    NSString* attributeValueString = nil;
    
    if(kSecAttrAccessible == attribute)
    {
        attributeValueString = [KeyChainDataSource getAttrAccessibleAsString:(CFStringRef)value];
    }
    else if(kSecAttrAccessGroup == attribute)
    {
        attributeValueString = [[NSString alloc] initWithString:(__bridge NSString*)value] ;
    }
    else if(kSecAttrCertificateType == attribute)
    {
        attributeValueString = [KeyChainDataSource getCertificateTypeAsString:(CFNumberRef)value];
    }
    else if(kSecAttrCertificateEncoding == attribute)
    {
        attributeValueString = [KeyChainDataSource getCertificateEncodingAsString:(CFNumberRef)value];
    }
    else if(kSecAttrLabel == attribute)
    {
        attributeValueString = [[NSString alloc] initWithString:(__bridge NSString*)value] ;
    }
    else if(kSecAttrSubject == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsNameString:(__bridge NSData*)value];
    }
    else if(kSecAttrIssuer == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsNameString:(__bridge NSData*)value];
    }
    else if(kSecAttrSerialNumber == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsAsciiHexString:(__bridge NSData*)value];
    }
    else if(kSecAttrSubjectKeyID == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsAsciiHexString:(__bridge NSData*)value];
    }
    else if(kSecAttrPublicKeyHash == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsAsciiHexString:(__bridge NSData*)value];
    }
    else if(kSecAttrKeyClass == attribute)
    {
        attributeValueString = [KeyChainDataSource getKeyClassAsString:(CFNumberRef)value];
    }
    else if(kSecAttrApplicationLabel == attribute)
    {
        attributeValueString = [KeyChainDataSource getDataAsAsciiHexString:(__bridge NSData*)value];
    }
    else if(kSecAttrIsPermanent == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrApplicationTag == attribute)
    {
        if(CFGetTypeID(value) == CFDataGetTypeID())
        {
            NSData* d = (__bridge NSData*)value;
            attributeValueString = [NSString stringWithUTF8String:(char*)[d bytes]];
        }
        else
        {
            attributeValueString = [[NSString alloc] initWithString:(__bridge NSString*)value] ;
        }
    }
    else if(kSecAttrKeyType == attribute)
    {
        attributeValueString = [KeyChainDataSource getKeyTypeAsString:(CFNumberRef)value];
    }
    else if(kSecAttrKeySizeInBits == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFNumberAsString:(CFNumberRef)value];
    }
    else if(kSecAttrEffectiveKeySize == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFNumberAsString:(CFNumberRef)value];
    }
    else if(kSecAttrCanEncrypt == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanDecrypt == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanDerive == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanSign == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanVerify == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanWrap == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else if(kSecAttrCanUnwrap == attribute)
    {
        attributeValueString = [KeyChainDataSource getCFBooleanAsString:(CFBooleanRef)value];
    }
    else
    {
        attributeValueString = @"Unknown value";
    }
    
    return attributeValueString;
}

@end

//--------------------------------------------------------------
// KeyChainDataSource implementation
//--------------------------------------------------------------
@implementation KeyChainDataSource

//Public members
@synthesize displayEmptyAttributes;
@synthesize userQuery;

//Private members
@synthesize items;
@synthesize utis;
@synthesize mode;
@synthesize initialized;
@synthesize attrNames;

- (int) numAttrGroups:(long)index
{
    return [self countAttributesAtIndex:index];
}

- (NSString*) getAttrStringForGroup:(CFTypeRef*)attrArray forItem:(long)index
{
    std::ostringstream oss;
    for(int ii = 0; attrArray[ii]; ++ii)
    {
        NSString* attrName = (NSString*)[attrNames objectForKey:(__bridge id)attrArray[ii]];
        if(attrName)
        {
            NSString* attrValue = [self getAttrValueAtSection:index attrType:attrArray[ii]];
            if(attrValue)
            {
                oss << [attrName UTF8String] << ": " << [attrValue UTF8String] << std::endl;
            }
        }
    }
    NSString* retVal = [[NSString alloc] initWithCString:oss.str().c_str() encoding:NSUTF8StringEncoding] ;
    return retVal;
}

- (NSString*) getAttrStringAtIndex:(long)index attrGroup:(long)attrGroup
{
    return [self getAttrValueAtSection:index attrIndex:attrGroup];
}

/**
 LoadKeyChainContents prepares a dictionary containing a query filter based on the current mode.
 The results are stored in the items member variable with mode-specific contents.
 */
- (void) LoadKeyChainContents:(NSArray*)configuredUtis
{
    [self ClearContents];
    
    if(nil == [self utis])
        self.utis = configuredUtis;
    
    OSStatus resultCode = noErr;
    
    if(nil == userQuery)
    {
        NSMutableDictionary * query = [[NSMutableDictionary alloc] init];
        
        //Set up the invariant pieces of the query
        [query setObject:(id)kSecMatchLimitAll forKey:(id)kSecMatchLimit];
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnRef];
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
        [query setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
        
        //Set up the mode-specific pieces of the query
        switch(mode)
        {
            case KSM_Certificates:
            {
                [query setObject:(id)kSecClassCertificate forKey:(id)kSecClass];
                break;
            }
            case KSM_Identities:
            {
                [query setObject:(id)kSecClassIdentity forKey:(id)kSecClass];
                [query setObject:(id)kSecAttrKeyClassPrivate forKey:(id)kSecAttrKeyClass];
                break;
            }
            case KSM_Keys:
            {
                [query setObject:(id)kSecClassKey forKey:(id)kSecClass];
                break;
            }
        }
        
        CFTypeRef result = nil;
        //Execute the query saving the results in items.
        resultCode = SecItemCopyMatching((CFDictionaryRef)query, &result);
        
        if(!IsZipType(self.utis))
        {
            NSArray* resultCerts = (__bridge_transfer NSMutableArray*)result;
            for(id item in resultCerts)
            {
                SecCertificateRef cert;
                if(mode == KSM_Certificates)
                {
                    CFDictionaryRef dict = (__bridge CFDictionaryRef)item;
                    cert = (SecCertificateRef)CFDictionaryGetValue(dict, kSecValueRef);
                }
                else if(mode == KSM_Identities)
                {
                    CFDictionaryRef dict = (__bridge CFDictionaryRef)item;
                    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecValueRef);
                    OSStatus stat = SecIdentityCopyCertificate(identity, &cert);
                    if(errSecSuccess != stat)
                        continue;
                }
                else
                    continue;
                
                
                if(CertTypeRequested(cert, self.utis))
                {
                    if(nil == items)
                    {
                        items = [[NSMutableArray alloc]init];
                    }
                    [items addObject:item];
                }
            }
        }
        else{
            NSArray* resultCerts = (__bridge_transfer NSMutableArray*)result;
            for(id item in resultCerts)
            {
                SecCertificateRef cert;
                if(mode == KSM_Certificates)
                {
                    CFDictionaryRef dict = (__bridge CFDictionaryRef)item;
                    cert = (SecCertificateRef)CFDictionaryGetValue(dict, kSecValueRef);
                }
                else if(mode == KSM_Identities)
                {
                    CFDictionaryRef dict = (__bridge CFDictionaryRef)item;
                    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecValueRef);
                    OSStatus stat = SecIdentityCopyCertificate(identity, &cert);
                    if(errSecSuccess != stat)
                        continue;
                }
                else
                    continue;
                
                
                if(ZippedCertTypeRequested(cert, self.utis))
                {
                    if(nil == items)
                    {
                        items = [[NSMutableArray alloc]init];
                        zip_items = [[NSMutableArray alloc]init];
                        [items addObject:@"Zip File"];
                        
                        zip_names = [[NSMutableArray alloc]init];
                        zip_sub_names = [[NSMutableArray alloc]init];
                    }
                    CertType ct = GetCertType(cert);
                    if(CT_DEVICE == ct)
                        [zip_names addObject:@"Device certificate"];
                    else if(CT_SIGNATURE == ct)
                        [zip_names addObject:@"Signature certificate"];
                    else if(CT_ENCRYPTION == ct)
                        [zip_names addObject:@"Encryption certificate"];
                    else if(CT_AUTHENTICATION == ct)
                        [zip_names addObject:@"Authentication certificate"];
                    else //if(CT_UNKNOWN == ct)
                        [zip_names addObject:@"Unknown certificate type"];
                    
                    [zip_sub_names addObject:(__bridge NSString *)SecCertificateCopySubjectSummary(cert)];
                    
                    [zip_items addObject:item];
                }
            }
        }
        if(nil == items)
        {
            NSLog(@"No keys found");
        }

        //[query release];
    }
    else
    {
        CFTypeRef result = nil;
        resultCode = SecItemCopyMatching((CFDictionaryRef)userQuery, &result);
        items = (__bridge_transfer NSMutableArray*)result;
    }
    
    if(resultCode != noErr)
    {
        //clean up anything that might have landed in items
        [self ClearContents];
    }
    else
    {
        //set the initialized flag
        initialized = true;
    }
    
    return;
}

//--------------------------------------------------------------
// KeyChainDataSource initialization/destruction
//--------------------------------------------------------------
- (id) init
{
    self = [super init];
    if(self)
    {
        mode = KSM_Identities;
        initialized = false;
        items = nil;
        displayEmptyAttributes = false;
        utis = nil;
        [self populateAttrMap];
    }
    return self;
}

- (id) initWithMode:(enum KeyChainDataSourceMode)kcdsMode;
{
    self = [super init];
    if(self)
    {
        mode = kcdsMode;
        initialized = false;
        items = nil;
        displayEmptyAttributes = false;
        utis = nil;
        [self populateAttrMap];
    }
    return self;
}

- (void)dealloc
{
    //[items release];
    items = nil;

    //[attrNames release];
    attrNames = nil;
    
    //[userQuery release];
    userQuery = nil;
    
    [self ClearContents];
    //[super dealloc];
}

- (void) ClearContents
{
    //[items release];
    items = nil;

    initialized = false;
}

- (size_t) numItems
{
    if(nil != zip_items)
        return 1;
    //each item gets its own section
    else if(nil == items)
        return 0;
    else
        return [items count];
} 

- (NSString*) GetEmailAddressAtIndex:(long)index
{
    NSLog(@"GetEmailAddressAtIndex: index %ld", index);
    SecCertificateRef certRef = [self getCertificateAt:index];
    if(certRef)
    {
        CFDataRef cfData = SecCertificateCopyData(certRef);
    
        const unsigned char* p = (const unsigned char*)CFDataGetBytePtr(cfData);
        X509 *certificateX509 = d2i_X509(NULL, &p, CFDataGetLength(cfData));
        CFRelease(cfData);
        if (certificateX509 != NULL) {
    
            STACK_OF(GENERAL_NAME) *subjectAltNames = NULL;
            
            // Try to extract the names within the SAN extension from the certificate
            subjectAltNames = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i((X509 *) certificateX509, NID_subject_alt_name, NULL, NULL);

            
            int altNameCount = sk_GENERAL_NAME_num(subjectAltNames);
            for (int ii = 0; ii < altNameCount; ++ii)
            {
                GENERAL_NAME* generalName = sk_GENERAL_NAME_value(subjectAltNames, ii);
                if (generalName->type == GEN_EMAIL)
                {
                    char* subjectAltName = (char*)generalName->d.rfc822Name->data;
                    NSString* s = [NSString stringWithUTF8String:subjectAltName];
                    return s;
                }
            }
            
        }
    }

    return nil;
}

- (NSString*) GetCommonNameAtIndex:(long)index
{
    NSLog(@"GetCommonNameAtIndex: index %ld", index);
    SecCertificateRef certRef = [self getCertificateAt:index];
    if(certRef)
    {
        CFDataRef cfData = SecCertificateCopyData(certRef);
        
        const unsigned char* p = (const unsigned char*)CFDataGetBytePtr(cfData);
        X509 *certificateX509 = d2i_X509(NULL, &p, CFDataGetLength(cfData));
        CFRelease(cfData);
        NSString *issuer = nil;
        if (certificateX509 != NULL) {
            X509_NAME *issuerX509Name = X509_get_subject_name(certificateX509);
            
            if (issuerX509Name != NULL) {
                char  subjectCn[256];
                int cnIndex = X509_NAME_get_text_by_NID(issuerX509Name, NID_commonName, subjectCn, sizeof(subjectCn));
                if(cnIndex)
                {
                    issuer = [NSString stringWithUTF8String:(char *)subjectCn];
                }
            }
        }
        
        return issuer;
    }
    return nil;
}

- (NSString*) GetIdentityNameAtIndex:(long)index
{
    NSLog(@"GetIdentityNameAtIndex: index %ld", index);
    
    if(nil != zip_items)
    {
        return @"Zip file";
    }
    else {
        //look for email address first, failing that use the default keychain label
        NSString* emailAddress = [self GetEmailAddressAtIndex:index];
        if(!emailAddress)
        {
            NSString* subject = [self GetCommonNameAtIndex:index];
            if(!subject)
                return [self getAttrValueAtSection:index attrType:kSecAttrLabel];
            else
                return subject;
        }
        else
            return emailAddress;
    }
}

- (SecIdentityRef) GetIdentityAtIndex:(long)index
{
    NSLog(@"GetIdentityAtIndex: index %ld", index);

    NSArray* tmpitems = zip_items;
    if(nil == tmpitems)
    {
        tmpitems = items;
    }
   
    if(index >= [tmpitems count])
        return nil;
    CFDictionaryRef item = (__bridge CFDictionaryRef)[tmpitems objectAtIndex:index];
    
    SecIdentityRef identity = nil;
    CFTypeRef value;
    if(CFDictionaryGetValueIfPresent(item, kSecValueRef, &value))
    {
        identity = (SecIdentityRef)value;
    }

    return identity;
}

- (NSData*) GetPrivateKeyAtIndex:(long)index
{
    NSArray* tmpitems = zip_items;
    if(nil == tmpitems)
    {
        tmpitems = items;
    }
    
    if(index >= [tmpitems count])
        return nil;
    CFDictionaryRef item = (__bridge CFDictionaryRef)[tmpitems objectAtIndex:index];
    
    NSData* privateKey = nil;
    CFTypeRef label;
    if(CFDictionaryGetValueIfPresent(item, kSecValueData, &label))
    {
        CFDataRef aCFString = (CFDataRef)label;
        privateKey = (__bridge NSData *)aCFString;
    }
    return privateKey;
}

- (void) removeObjectAtIndex:(long)index
{
    if(index >= [items count])
        return;
    
    CFDictionaryRef item = (__bridge CFDictionaryRef)[items objectAtIndex:index];
    
    CFTypeRef value;
    if(CFDictionaryGetValueIfPresent(item, kSecValueRef, &value))
    {
        SecIdentityRef identity = (SecIdentityRef)value;
        
        NSMutableDictionary * query = [[NSMutableDictionary alloc] init];
        
        //Set up the invariant pieces of the query
        [query setObject:(__bridge id)identity forKey:(id)kSecValueRef];
   
        //Execute the query saving the results in items.
        OSStatus resultCode = SecItemDelete((CFDictionaryRef) query);
        //[query release];
        query = nil;

        if(errSecSuccess == resultCode)
        {
            //Managing the array doesn't really cut it when other apps 
            //may also contribute to the key chain (or at least it does
            //not appear to cut it).
            //[items removeObjectAtIndex:index];
            [self LoadKeyChainContents:[self utis]];
        }
        else
        {
            NSString *errormsg = [NSString stringWithFormat:@"Failed to delete selected identity with error code %d.", (int)resultCode];
            NSLog(@"%@", errormsg);
        }
    }
}

- (NSString*) getAttrNameAtSection:(long)sectionIndex attrIndex:(long)attrIndex
{
    if(nil != zip_names)
        return zip_names[attrIndex];
    
    CFTypeRef attribute, value;
    NSString* attrFriendlyName = nil;
    
    @try 
    {
        CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:sectionIndex];
        CFTypeRef* attrs = NULL;
        
        switch (mode) {
            case KSM_Certificates:
                attrs = g_certAttrs;
                break;
            case KSM_Identities:
                attrs = g_identityAttrs;
                break;
            case KSM_Keys:
                attrs = g_keyAttrs;
                break;
            default:
                return 0;
        }
        
        for(int ii = 0, jj = 0; attrs[ii]; ++ii)
        {
            if(CFDictionaryGetValueIfPresent(dict, attrs[ii], &value))
            {
                if(jj == attrIndex)
                {
                    attribute = attrs[ii];
                    break;
                }
                else
                    ++jj;
            }
        }
    } 
    @catch (NSException* rangeException) 
    {
        return 0;
    }
    
    //get the friendly name of the attribute
    attrFriendlyName = (NSString*)[attrNames objectForKey:(__bridge id)attribute];
    if(nil == attrFriendlyName)
        attrFriendlyName = NSLocalizedString(@"Unrecognized attribute",nil);
    
    return attrFriendlyName;
}

/**
 This function returns the attrIndexth present value from the sectionIndexth item
 */
- (NSString*) getAttrValueAtSection:(long)sectionIndex attrIndex:(long)attrIndex
{
    if(nil != zip_sub_names)
        return zip_sub_names[attrIndex];
    
    CFTypeRef attribute, value;
    
    @try 
    {
        CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:sectionIndex];
        CFTypeRef* attrs = NULL;
        
        switch (mode) {
            case KSM_Certificates:
                attrs = g_certAttrs;
                break;
            case KSM_Identities:
                attrs = g_identityAttrs;
                break;
            case KSM_Keys:
                attrs = g_keyAttrs;
                break;
            default:
                return 0;
        }
        
        for(int ii = 0, jj = 0; attrs[ii]; ++ii)
        {
            if(CFDictionaryGetValueIfPresent(dict, attrs[ii], &value))
            {
                if(jj == attrIndex)
                {
                    attribute = attrs[ii];
                    break;
                }
                else
                    ++jj;
            }
        }
    } 
    @catch (NSException* rangeException) 
    {
        return nil;
    }
    
    return [self getAttrValueAsString:attribute value:value];
}


- (NSString*) getAttrValueAtSection:(long)sectionIndex attrType:(CFTypeRef)attrType
{
    CFTypeRef value;
    
    @try 
    {
        CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:sectionIndex];
        if(!CFDictionaryGetValueIfPresent(dict, attrType, &value))
        {
            return nil;
        }
    } 
    @catch (NSException* rangeException) 
    {
        return nil;
    }
    
    return [self getAttrValueAsString:attrType value:value];
}

- (SecCertificateRef) getCertificateAt:(long)index
{
    if(index >= [items count])
       return nil;
    
    switch (mode) {
        case KSM_Certificates:
        {
            CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:index];
            SecCertificateRef cert = (SecCertificateRef)CFDictionaryGetValue(dict, kSecValueRef);
            return cert;
        }
        case KSM_Identities:
        {
            CFDictionaryRef dict = (__bridge CFDictionaryRef)[items objectAtIndex:index];
            SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecValueRef);
            SecCertificateRef cert = nil;
            OSStatus stat = SecIdentityCopyCertificate(identity, &cert);
            if(errSecSuccess == stat)
                return cert;
            else
                return nil;
        }
        case KSM_Keys:
        {
            return nil;
        }
        default:
        {
            return nil;
        }
    }
}

- (NSData*) GetPKCS12Zip
{
    if(NULL == zip_items)
    {
        return NULL;
    }

    NSString *alphabet  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789";
    NSMutableString* s = [NSMutableString stringWithCapacity:20];
    for (NSUInteger i = 0U; i < 20; i++) {
        u_int32_t r = arc4random() % [alphabet length];
        unichar c = [alphabet characterAtIndex:r];
        [s appendFormat:@"%C", c];
    }
    
    NSString *documentsDir= [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *filePath= [documentsDir stringByAppendingPathComponent:@"test.zip"];
    ZipFile *zipFile= [[ZipFile alloc] initWithFileName:filePath mode:ZipFileModeCreate];
    
    unsigned long count = [zip_items count];
    for(long ii = 0; ii < count; ++ii)
    {
        NSString* filename = [NSString stringWithFormat:@"%lu.p12", ii];
        NSData* d = [self GetPKCS12AtIndex:ii pw:s];
        ZipWriteStream *stream1= [zipFile writeFileInZipWithName:filename fileDate:[NSDate dateWithTimeIntervalSinceNow:-86400.0] compressionLevel:ZipCompressionLevelBest];
        [stream1 writeData:d];
        [stream1 finishedWriting];
    }
    [zipFile close];
    
    //Put the PKCS 12 password on the pasteboard
    UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
    [pasteboard setString:s];
    
    NSData *data = [[NSFileManager defaultManager] contentsAtPath:filePath];
    return data;
}

- (NSData*) GetPKCS12AtIndex:(long)index
{
    return [self GetPKCS12AtIndex:index pw:NULL];
}
- (NSData*) GetPKCS12AtIndex:(long)index pw:(NSString*)pw
{
    SecIdentityRef identity = [self GetIdentityAtIndex:index];
    if(!identity)
    {
        std::ostringstream oss;
        oss << "Failed to obtain SecIdentityRef for item at index " << index;
        return nil;
    }
    
    NSData* privateKeyBits = [self GetPrivateKeyAtIndex:index];
    if(!privateKeyBits)
    {
        std::ostringstream oss;
        oss << "Failed to export private key for item at index " << index;
        return nil;
    }
    
    SecKeyRef pk = nil;
    OSStatus status = SecIdentityCopyPrivateKey ( identity, &pk );
    if(0 != status)
    {
        std::ostringstream oss;
        oss << "Failed to copy private key for item at index " << index << " with error " << status;
        return nil;
    }
    
    SecCertificateRef cert = nil;
    status = SecIdentityCopyCertificate(identity, &cert );
    if(0 != status)
    {
        std::ostringstream oss;
        oss << "Failed to copy certificate for item at index " << index << " with error " << status;
        return nil;
    }
    
    CFStringRef summaryRef = SecCertificateCopySubjectSummary(cert);
    if(summaryRef)
    {
        NSString* subjectName = (__bridge_transfer NSString*)summaryRef;
        if(subjectName)
        {
            std::ostringstream oss;
            oss << "Preparing PKCS #12 for item at index " << index << " with subject name " << [subjectName UTF8String];
        }
    }
    
    const unsigned char* bits = (const unsigned char*)[privateKeyBits bytes];
    size_t pkLen = [privateKeyBits length];
    NSData *decodedData = (__bridge_transfer NSData *) SecCertificateCopyData(cert);
    if(!bits || 0 == pkLen || !decodedData)
    {
        std::ostringstream oss;
        oss << "Failed to preparing PKCS #12 for item at index " << index << " because private key or certificate data is not available";
        return nil;
    }
    
    unsigned char* p12Buf = NULL;
    int p12BufLen = 0;
    std::string password;
    
    if(NULL == pw)
    {
        NSString *alphabet  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789";
        NSMutableString* s = [NSMutableString stringWithCapacity:20];
        for (NSUInteger i = 0U; i < 20; i++) {
            u_int32_t r = arc4random() % [alphabet length];
            unichar c = [alphabet characterAtIndex:r];
            [s appendFormat:@"%C", c];
        }
        pw = s;
    }
    
    int rv = PrepareAndExportPkcs12((unsigned char*)bits, (int)pkLen, (unsigned char*)[decodedData bytes], (int)[decodedData length], &p12Buf, &p12BufLen, [pw UTF8String], password);
    if(0 == rv)
    {
        const char* pw = password.c_str();
        NSString* pwForPasteboard = [NSString stringWithUTF8String:pw];
        
        //Put the PKCS 12 password on the pasteboard
        UIPasteboard *pasteboard = [UIPasteboard generalPasteboard];
        [pasteboard setString:pwForPasteboard];
        
        //Prepare the data to return
        NSData* p12Data = [NSData dataWithBytes:p12Buf length:p12BufLen];
        free(p12Buf);
        return p12Data;
    }
    else
    {
        if(p12Buf)
            free(p12Buf);
        
        std::ostringstream oss;
        oss << "Failed to preparing PKCS #12 for item at index " << index << " with error code " << rv;
        return nil;
    }

    return nil;
}

@end
