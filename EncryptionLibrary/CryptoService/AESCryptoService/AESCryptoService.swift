//
//  EASCryptoService.swift
//  EncryptionLibrary
//
//  Created by Ayush Kumar Sinha on 28/03/24.
//

import Foundation
import CommonCrypto

enum AESMode {
    case cbc
}

enum CryptographyStandards {
    case pkcs7
}

class AESCryptoService {
    private let secretKey: String
    private let initializationVector: String
    private let mode: AESMode
    private let standards: CryptographyStandards
    
    private let jsonDecoder: JSONDecoder = JSONDecoder()
    
    private var sercretKeyStream: [UInt8] {
        Array(self.secretKey.utf8)
    }
    
    private var initializationVectorStream: [UInt8] {
        Array(self.initializationVector.utf8)
    }
    
    init(secretKey: String, initializationVector: String, mode: AESMode = .cbc, standards: CryptographyStandards = .pkcs7) throws {
        
        // The key size must be 128, 192, or 256.
        //
        // The IV size must match the block size.
        guard
            [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(secretKey.count),
            initializationVector.count == kCCBlockSizeAES128
        else {
            throw CryptoServiceError.invalidParameters
        }
        
        self.secretKey = secretKey
        self.initializationVector = initializationVector
        self.mode = mode
        self.standards = standards
    }
    
    /// Encrypts data using AES with PKCS#7 padding in CBC mode.
    ///
    /// - note: PKCS#7 padding is also known as PKCS#5 padding.
    ///
    ///     - Parameters:
    ///     - key: The key to encrypt with; must be a supported size (128, 192, 256).
    ///     - iv: The initialisation vector; must be of size 16.
    ///     - plaintext: The data to encrypt; the PKCS#7 padding means there are no
    ///     constraints on its length.
    /// - Returns: The encrypted data; it’s length with always be an even multiple of 16.

    func QCCAESPadCBCEncrypt(plaintext: [UInt8]) throws -> [UInt8] {

        // Padding can expand the data, so we have to allocate space for that.  The
        // rule for block cyphers, like AES, is that the padding only adds space on
        // encryption (on decryption it can reduce space, obviously, but we don't
        // need to account for that) and it will only add at most one block size
        // worth of space.

        var cyphertext = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
        var cyphertextCount = 0
        let err = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            self.sercretKeyStream, self.sercretKeyStream.count,
            self.initializationVectorStream,
            plaintext, plaintext.count,
            &cyphertext, cyphertext.count,
            &cyphertextCount
        )
        
        guard err == kCCSuccess else {
            throw CryptoServiceError.serviceError
        }
        
        // The cyphertext can expand by up to one block but it doesn’t always
        // use the full block, so trim off any unused bytes.
        
        cyphertext.removeLast(cyphertext.count - cyphertextCount)
        
        guard cyphertextCount <= cyphertext.count, cyphertext.count.isMultiple(of: kCCBlockSizeAES128) else {
            throw CryptoServiceError.serviceError
        }

        return cyphertext
    }

    /// Decrypts data that was encrypted using AES with PKCS#7 padding in CBC mode.
    ///
    /// - note: PKCS#7 padding is also known as PKCS#5 padding.
    ///
    ///     - Parameters:
    ///     - key: The key to encrypt with; must be a supported size (128, 192, 256).
    ///     - iv: The initialisation vector; must be of size 16.
    ///     - cypherText: The encrypted data; it’s length must be an even multiple of
    ///     16.
    /// - Returns: The decrypted data.

    func QCCAESPadCBCDecrypt(cyphertext: [UInt8]) throws -> [UInt8] {

        // The ciphertext must be a multiple of the block size.

        guard
            cyphertext.count.isMultiple(of: kCCBlockSizeAES128)
        else {
            throw CryptoServiceError.invalidParameters
        }

        // Padding can expand the data on encryption, but on decryption the data can
        // only shrink so we use the cyphertext size as our plaintext size.

        var plaintext = [UInt8](repeating: 0, count: cyphertext.count)
        var plaintextCount = 0
        let err = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            self.sercretKeyStream, self.sercretKeyStream.count,
            self.initializationVectorStream,
            cyphertext, cyphertext.count,
            &plaintext, plaintext.count,
            &plaintextCount
        )
        guard err == kCCSuccess else {
            throw CryptoServiceError.serviceError
        }
        
        // Trim any unused bytes off the plaintext.
        
        plaintext.removeLast(plaintext.count - plaintextCount)
        
        guard plaintextCount <= plaintext.count else {
            throw CryptoServiceError.serviceError
        }
        
        return plaintext
    }
 
    
}

extension AESCryptoService: EncryptionService, DecryptionService {
    func decrypt<T: Codable>(cypherText: String) throws -> T {
        switch (self.mode, self.standards) {
        case (AESMode.cbc, CryptographyStandards.pkcs7):
            guard let cypherTextEncodedData = Data(base64Encoded: cypherText) else {
                throw CryptoServiceError.invalidOperation
            }
            let cypherTextEncodedStream: [UInt8] = Array(cypherTextEncodedData)
            
            let plainTextEncodedStream = try QCCAESPadCBCDecrypt(cyphertext: cypherTextEncodedStream)
            let plainTextEncodedData = Data(plainTextEncodedStream)
            
            guard let plainText = try? jsonDecoder.decode(T.self, from: plainTextEncodedData) else {
                throw CryptoServiceError.invalidOperation
            }
            return plainText
        }
    }
    
    
    func encrypt<T: Codable>(plainText: T) throws -> String {
        switch (self.mode, self.standards) {
        case (AESMode.cbc, CryptographyStandards.pkcs7):
            let jsonEncoder = JSONEncoder()
            guard
                let plainTextEncodedData: Data = try? jsonEncoder.encode(plainText),
                let plainTextEncodedString: String = String(data: plainTextEncodedData, encoding: .utf8) else {
                throw CryptoServiceError.invalidOperation
            }
            
            let plainTextDataStream: [UInt8] = Array(plainTextEncodedString.utf8)
            
            let cypherTextEncodedStream = try QCCAESPadCBCEncrypt(plaintext: plainTextDataStream)
            let cypherTextEncodedData = Data(cypherTextEncodedStream)
            let cypherText = cypherTextEncodedData.base64EncodedString()
            
            return cypherText
        }
    }
    func encryptArray<T: Codable>(plainText: [T]) throws -> String {
        switch (self.mode, self.standards) {
        case (AESMode.cbc, CryptographyStandards.pkcs7):
            let jsonEncoder = JSONEncoder()
            jsonEncoder.outputFormatting = .sortedKeys
            guard
                let plainTextEncodedData: Data = try? jsonEncoder.encode(plainText),
                let plainTextEncodedString: String = String(data: plainTextEncodedData, encoding: .utf8) else {
                throw CryptoServiceError.invalidOperation
            }
            
            let plainTextDataStream: [UInt8] = Array(plainTextEncodedString.utf8)
            
            let cypherTextEncodedStream = try QCCAESPadCBCEncrypt(plaintext: plainTextDataStream)
            let cypherTextEncodedData = Data(cypherTextEncodedStream)
            let cypherText = cypherTextEncodedData.base64EncodedString()
            
            return cypherText
        }
    }
}
