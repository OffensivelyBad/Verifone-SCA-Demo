//
//  RSA.swift
//  Verifone SCA Demo
//
//  Created by Shawn Roller on 8/29/21.
//

import Foundation
import SwiftyRSA

let bitSize = 2048

func generatePEMKeys() -> (privateKey: String, publicKey: String) {
    do {
        let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: bitSize)
        let privateKey = keyPair.privateKey
        let publicKey = keyPair.publicKey
        
        let pemPrivateKey = try privateKey.pemString()
        let pemPublicKey = try publicKey.pemString()
        
        return (pemPrivateKey, pemPublicKey)
    }
    catch {
        fatalError("Couldn't generate the RSA PEM keys!")
    }
}

func generateKeys() -> (privateKey: PrivateKey, publicKey: PublicKey) {
    do {
        let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: bitSize)
        let privateKey = keyPair.privateKey
        let publicKey = keyPair.publicKey
        
        return (privateKey, publicKey)
    }
    catch {
        fatalError("Couldn't generate the RSA PEM keys!")
    }
}

func generateBase64Keys() -> (privateKey: String, publicKey: String) {
    do {
        let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: bitSize)
        let privateKey = keyPair.privateKey
        let publicKey = keyPair.publicKey
        
        let privateB64 = try privateKey.base64String()
        let publicB64 = try publicKey.base64String()
        
        return (privateB64, publicB64)
    }
    catch {
        fatalError("Couldn't generate the RSA PEM keys!")
    }
}

