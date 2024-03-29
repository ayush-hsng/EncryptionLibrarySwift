//
//  CryptoService.swift
//  EncryptionLibrary
//
//  Created by Ayush Kumar Sinha on 28/03/24.
//

import Foundation

protocol EncryptionService {
    func encrypt<T: Codable>(plainText: T) throws -> String
}

protocol DecryptionService {
    func decrypt<T: Codable>(cypherText: String) throws -> T
}

enum CryptoServiceError: Error {
    case invalidParameters
    case invalidOperation
    case serviceError
}
