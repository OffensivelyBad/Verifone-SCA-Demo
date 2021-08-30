//
//  VFDataManager.m
//  PointSample
//
//  Copyright (c) 2014 VeriFone. All rights reserved.
//

#import "VFDataManager.h"
#import <CommonCrypto/CommonHMAC.h>

// Identifiers for creating a key in the keychain
static const UInt8 publicKeyIdentifier[] = "com.techstyle.publicKey\0";
static const UInt8 privateKeyIdentifier[] = "com.techstyle.privateKey\0";

// References to the keychain objects
static SecKeyRef privateKey;
static SecKeyRef publicKey;

@interface VFDataManager ()

@property (assign, nonatomic) NSInteger _keySize;

// Tags (using the identifiers) to find keys in the keychain
@property (strong, nonatomic) NSData *_publicTag;
@property (strong, nonatomic) NSData *_privateTag;

@end

@implementation VFDataManager

#pragma mark - Initialization

+ (VFDataManager *)sharedInstance
{
    static VFDataManager *sharedInstance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
        
        [sharedInstance generateKeyPair];
        
        NSDictionary *defaultsDict = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        if(defaultsDict[@"verifoneMacBytes"] != nil && [defaultsDict[@"verifoneMacBytes"] isKindOfClass:[NSData class]]){
            sharedInstance.macKeyDecryptedBytes = defaultsDict[@"verifoneMacBytes"];
        }
        if(defaultsDict[@"verifoneMacLabel"] != nil && [defaultsDict[@"verifoneMacLabel"] isKindOfClass:[NSString class]]){
            sharedInstance.macLabel = defaultsDict[@"verifoneMacLabel"];
        }
        if(defaultsDict[@"verifoneMacKey"] != nil && [defaultsDict[@"verifoneMacKey"] isKindOfClass:[NSString class]]){
            sharedInstance.macKey = defaultsDict[@"verifoneMacKey"];
        }
        if(defaultsDict[@"verifoneCounter"] != nil && [defaultsDict[@"verifoneCounter"] isKindOfClass:[NSNumber class]]){
            sharedInstance.counter = [defaultsDict[@"verifoneCounter"] intValue];
        }
        else{
            sharedInstance.counter = 1;
        }
    });
    return sharedInstance;
}

- (id)init
{
    if (self = [super init]) {
        [self set_keySize:2048];
    }
    return self;
}

#pragma mark - Public methods

- (void)generateKeyPair
{
    OSStatus keyStatus = noErr;

    NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary new];
    NSMutableDictionary *publicKeyAttributes = [NSMutableDictionary new];
    NSMutableDictionary *keyPairAttributes = [NSMutableDictionary new];

    [privateKeyAttributes setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttributes setObject:self._privateTag forKey:(__bridge id)kSecAttrApplicationTag];

    [publicKeyAttributes setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttributes setObject:self._publicTag forKey:(__bridge id)kSecAttrApplicationTag];

    [keyPairAttributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttributes setObject:[NSNumber numberWithInteger:self._keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [keyPairAttributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttributes setObject:publicKeyAttributes forKey:(__bridge id)kSecPublicKeyAttrs];

    keyStatus = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttributes, &publicKey, &privateKey);
}

- (NSData *)decryptWithPrivateKeyUsingData:(NSData *)dataToDecrypt
{
    OSStatus status = noErr;

    NSDictionary *privateKeyQuery = [self keyQueryWithApplicationTag:self._privateTag requestingData:NO];

    status = SecItemCopyMatching ((__bridge CFDictionaryRef)privateKeyQuery, (CFTypeRef *)&privateKey);

    size_t cipherBufferSize = [dataToDecrypt length];
    uint8_t *cipherBuffer = (uint8_t *)[dataToDecrypt bytes];

    size_t plainBufferSize = 16; //SecKeyGetBlockSize(privateKey);
    uint8_t *plainBuffer = malloc(plainBufferSize);

    if (plainBufferSize > cipherBufferSize) {
        NSLog(@"----- (VFDataManager) Error decrypting the data. Packet too large -----");
        return nil;
    }

    status = SecKeyDecrypt(privateKey, kSecPaddingPKCS1, cipherBuffer, cipherBufferSize, plainBuffer, &plainBufferSize);
    
    NSData *data = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    
    NSLog(@"%@", [data description]);
    
    return data;
}

#pragma mark - Utility methods

/**
 * Access the keychain object for the public tag and assign the important
 * info to a dictionary.
 * The tag is either the public tag or the private tag
 * Requesting data determines if we want to extract a security reference or data from the key query
 */
- (NSDictionary *)keyQueryWithApplicationTag:(NSData *)tag requestingData:(BOOL)data
{
    NSMutableDictionary *keyQuery = [NSMutableDictionary new];
    [keyQuery setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyQuery setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyQuery setObject:tag forKey:(__bridge id)kSecAttrApplicationTag];
    if (data) {
        [keyQuery setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    } else {
        [keyQuery setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    }
    return keyQuery;
}

// Helper function for ASN.1 encoding
size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

//Method to get the MACHash
-(void)calculateMAC{
    NSData* macKeyData = self.macKeyDecryptedBytes;
    [self setCounter:self.counter+1];
    
    // Convert the counter string to data
    NSString *counterString = [NSString stringWithFormat:@"%i", self.counter];
    NSData *counterData = [counterString dataUsingEncoding:NSUTF8StringEncoding];
    
    // Hash the decrypted mac key with the counter data
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           [macKeyData bytes],
           [macKeyData length],
           [counterData bytes],
           [counterData length],
           hash);
    
    // Extract the hash from the hashing as a data object
    NSData *hashData = [[NSData alloc] initWithBytes:hash length:sizeof(hash)];
    
    // Encode the hash with base64
    NSString *hashString = [hashData vfbase64String];
    
    // Set the data manager's has to the final value
    [self setMAChash:hashString];
}

#pragma mark - Overridden properties

/**
 * Getter for public key string
 * We base 64 encode the public key data and set it as the string
 */
- (NSString *)publicKeyString
{
    if (!_publicKeyString) {
        //_publicKeyString = [self.publicKeyData base64String];
        
        static const unsigned char _encodedRSAEncryptionOID[15] = {
            
            /* Sequence of length 0xd made up of OID followed by NULL */
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            
        };
        
        unsigned char builder[15];
        NSMutableData * encKey = [[NSMutableData alloc] init];
        int bitstringEncLength;
        
        // When we get to the bitstring - how will we encode it?
        if  ([self.publicKeyData length ] + 1  < 128 )
            bitstringEncLength = 1 ;
        else
            bitstringEncLength = (int)(([self.publicKeyData length ] +1 ) / 256 ) + 2 ;
        
        // Overall we have a sequence of a certain length
        builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
        // Build up overall size made up of -
        // size of OID + size of bitstring encoding + size of actual key
        size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
        [self.publicKeyData length];
        size_t j = encodeLength(&builder[1], i);
        [encKey appendBytes:builder length:j +1];
        
        // First part of the sequence is the OID
        [encKey appendBytes:_encodedRSAEncryptionOID
                     length:sizeof(_encodedRSAEncryptionOID)];
        
        // Now add the bitstring
        builder[0] = 0x03;
        j = encodeLength(&builder[1], [self.publicKeyData length] + 1);
        builder[j+1] = 0x00;
        [encKey appendBytes:builder length:j + 2];
        
        // Now the actual key
        [encKey appendData:self.publicKeyData];
        
        // Now translate the result to a Base64 string
        _publicKeyString = [encKey vfbase64String];
        
    }

    return _publicKeyString;
}

/**
 * Getter for private key string
 * We base 64 encode the private key data and set it as the string
 */
- (NSString *)privateKeyString
{
    if (!_privateKeyString) {
        _privateKeyString = [self.privateKeyData vfbase64String];
    }
    return _privateKeyString;
}

/**
 * Getter for public key data
 * Essentially queries the keychain for the key and returs the data for the key
 */
- (NSData *)publicKeyData
{
    if (!_publicKeyData) {

        if (!self._publicTag) {
            [self generateKeyPair];
        }

        OSStatus keyStatus = noErr;
        CFDataRef publicKeyBits = nil;

        NSDictionary *publicKeyQuery = [self keyQueryWithApplicationTag:self._publicTag requestingData:YES];

        keyStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyQuery, (CFTypeRef *)&publicKeyBits);

        NSData *publicKeyBitsData = (__bridge_transfer NSData *)publicKeyBits;
        _publicKeyData = publicKeyBitsData;

        if (keyStatus != noErr) publicKeyBits = nil;
    }
    return _publicKeyData;
}

/**
 * Getter for private key data
 * Does the same as public key data, except extracting the private key
 */
- (NSData *)privateKeyData
{
    if (!_privateKeyData) {

        if (!self._privateTag) {
            [self generateKeyPair];
        }

        OSStatus keyStatus = noErr;
        CFDataRef privateKeyBits = nil;

        NSDictionary *publicKeyQuery = [self keyQueryWithApplicationTag:self._privateTag requestingData:YES];

        keyStatus = SecItemCopyMatching((__bridge CFDictionaryRef)publicKeyQuery, (CFTypeRef *)&privateKeyBits);

        NSData *privateKeyBitsData = (__bridge_transfer NSData *)privateKeyBits;
        _privateKeyData = privateKeyBitsData;

        if (keyStatus != noErr) privateKeyBits = nil;
    }
    return _privateKeyData;
}

/**
 * Getter for public tag
 * Assign the public tag the data of the public key identifier
 */
- (NSData *)_publicTag
{
    if (!__publicTag) {
        __publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *)publicKeyIdentifier)];
    }
    return __publicTag;
}

/**
 * Getter for private tag
 * Assign the private tag the data of the private key identifier
 */
- (NSData *)_privateTag
{
    if (!__privateTag) {
        __privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
    }
    return __privateTag;
}

- (void)setCounter:(int)counter
{
    _counter = counter;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:@(_counter) forKey:@"verifoneCounter"];
    [defaults synchronize];
}

- (void)setMacKey:(NSString *)macKey
{
    _macKey = macKey;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:_macKey forKey:@"verifoneMacKey"];
    [defaults synchronize];
}

- (void)setMacLabel:(NSString *)macLabel
{
    _macLabel = macLabel;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:_macLabel forKey:@"verifoneMacLabel"];
    [defaults synchronize];
}

- (void)setMacKeyDecryptedBytes:(NSData *)macKeyDecryptedBytes
{
    _macKeyDecryptedBytes = macKeyDecryptedBytes;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:_macKeyDecryptedBytes forKey:@"verifoneMacBytes"];
    [defaults synchronize];
}

@end
