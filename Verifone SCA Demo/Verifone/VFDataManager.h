//
//  DataManager.h
//  PointSample
//
//  Copyright (c) 2014 VeriFone. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "NSData+VFBase64.h"

@interface VFDataManager : NSObject

@property (strong, nonatomic) NSString *publicKeyString;
@property (strong, nonatomic) NSString *privateKeyString;

@property (strong, nonatomic) NSData *publicKeyData;
@property (strong, nonatomic) NSData *privateKeyData;

@property (strong, nonatomic) NSString *macLabel;
@property (strong, nonatomic) NSString *macKey;
@property (strong, nonatomic) NSData *macKeyDecryptedBytes;
@property (strong, nonatomic) NSString *MAChash;
@property (nonatomic) int counter;

/**
 * Shared instance
 * Follows the singleton design pattern to get the global data manager object
 * We'll use this to handle all of the connection logic and variables
 */
+ (VFDataManager *)sharedInstance;

/**
 * Generate key pair
 * Generates an RSA asymmetric keypair and stores the info in the class properties
 */
- (void)generateKeyPair;

/**
 * Decrypt with private key
 * Decrypts the given data with the previously generated private key
 */
- (NSData *)decryptWithPrivateKeyUsingData:(NSData *)dataToDecrypt;
-(void)calculateMAC;

@end
