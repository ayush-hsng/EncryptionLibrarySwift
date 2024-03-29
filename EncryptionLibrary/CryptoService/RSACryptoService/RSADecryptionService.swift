//
//  RSADecryptionService.swift
//  EncryptionLibrary
//
//  Created by Ayush Kumar Sinha on 29/03/24.
//

import Foundation

class RSADecryptionService {
    private var privateKey: SecKey
    
    private var jsonDecoder: JSONDecoder = JSONDecoder()
    private var jsonEncoder: JSONEncoder = JSONEncoder()

    init(privateKey: String) throws {
        var pemKeyString = privateKey

        // Remove headers and footers from the PEM, leaving us with DER encoded data split by new lines
        [
            "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
        ].forEach { pemKeyString = pemKeyString.replacingOccurrences(of: $0, with: "") }

        // Convert PEM string to DER Data
        guard let der = Data(base64Encoded: pemKeyString, options: .ignoreUnknownCharacters) else {
            print("Failed to convert PEM string to Data")
            throw CryptoServiceError.invalidParameters
        }
        
        // Create attributes dictionary
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048 // Adjust the key size if needed
        ]

        // Create a SecKey object from the raw RSA private key data
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            if let error = error {
                print("Error: \(error.takeRetainedValue() as Error)")
            } else {
                print("Error: Unable to create SecKey from RSA private key data")
            }
            throw CryptoServiceError.invalidParameters
        }

        self.privateKey = secKey
    }
    
    // Function to decrypt data with RSA private key
    func decryptWithPrivateKey(data: Data) throws -> Data{
        guard SecKeyIsAlgorithmSupported(self.privateKey, .decrypt, .rsaEncryptionOAEPSHA512) else {
            print("Decryption with the private key is not supported")
            throw CryptoServiceError.invalidOperation
        }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(self.privateKey, .rsaEncryptionOAEPSHA512, data as CFData, &error) as Data? else {
            print("Decryption failed: \(error!.takeRetainedValue() as Error)")
            throw CryptoServiceError.serviceError
        }
        
        return decryptedData
    }
}

extension RSADecryptionService: DecryptionService {
    func decrypt<T: Codable>(cypherText: String) throws -> T  {
        guard let cypherTextEncodedData = Data(base64Encoded: cypherText) else {
            throw CryptoServiceError.invalidOperation
        }
        
        let plainTextEncodedData = try self.decryptWithPrivateKey(data: cypherTextEncodedData)
        
        guard let plainText = try? jsonDecoder.decode(T.self, from: plainTextEncodedData) else {
            throw CryptoServiceError.invalidOperation
        }
        return plainText
    }
}

