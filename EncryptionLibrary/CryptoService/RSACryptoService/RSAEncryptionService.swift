//
//  RSAEncryptionService.swift
//  EncryptionLibrary
//
//  Created by Ayush Kumar Sinha on 29/03/24.
//

import Foundation
import Security

class RSAEncryptionService {
    private var publicKey: SecKey
    
    private var jsonDecoder: JSONDecoder = JSONDecoder()
    private var jsonEncoder: JSONEncoder = JSONEncoder()

    init(publicKey: String) throws {
        
        var pemKeyString = publicKey

        // Remove headers and footers from the PEM, leaving us with DER encoded data split by new lines
        [
            "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
        ].forEach { pemKeyString = pemKeyString.replacingOccurrences(of: $0, with: "") }

        // Convert PEM string to DER Data
        guard let der = Data(base64Encoded: pemKeyString, options: .ignoreUnknownCharacters) else {
            print("Failed to convert PEM string to Data")
            throw CryptoServiceError.invalidParameters
        }
        
        // Define a public key query dictionary
        let keyDict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        // Create a SecKey object from the DER data
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(der as CFData, keyDict as CFDictionary, &error) else {
            print("Failed to create SecKey from DER data: \(error!.takeRetainedValue() as Error)")
            throw CryptoServiceError.invalidParameters
        }
        
        self.publicKey = publicKey
    }
    
    // Function to encrypt data with RSA public key
    func encryptWithPublicKey(data: Data) throws -> Data {
        guard SecKeyIsAlgorithmSupported(self.publicKey, .encrypt, .rsaEncryptionOAEPSHA512) else {
            print("Encryption with the public key is not supported")
            throw CryptoServiceError.invalidOperation
        }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA512, data as CFData, &error) as Data? else {
            print("Encryption failed: \(error!.takeRetainedValue() as Error)")
            throw CryptoServiceError.serviceError
        }
        
        return encryptedData
    }
}

extension RSAEncryptionService: EncryptionService {
    func encrypt<T: Codable>(plainText: T) throws -> String {
        guard
            let plainTextEncodedData: Data = try? jsonEncoder.encode(plainText) else {
            throw CryptoServiceError.invalidOperation
        }
        
        let cypherTextEncodedData = try self.encryptWithPublicKey(data: plainTextEncodedData)
        let cypherText = cypherTextEncodedData.base64EncodedString()
        
        return cypherText
    }
}
