//
//  EncryptionLibraryTests.swift
//  EncryptionLibraryTests
//
//  Created by Ayush Kumar Sinha on 28/03/24.
//

import XCTest
@testable import EncryptionLibrary

/// This class contains unit tests for the EncryptionLibrary.
final class EncryptionLibraryTests: XCTestCase {
    var cryptoService: AESCryptoService!
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        super.setUp()
        do {
            cryptoService = try AESCryptoService(secretKey: "0123456789ABCDEF", initializationVector: String("0123456789ABCDEF".prefix(16)))
        } catch {
            XCTFail("Failed to initialize EASCryptoService: \(error)")
        }
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        self.cryptoService = nil
    }
    
    /// Test encryption and decryption of a Codable object.
    func testEncryptionDecryption() {
        struct TestObject: Codable {
            let property: String
        }
        let originalObject = TestObject(property: "test")
        
        do {
            let encryptedString = try cryptoService.encrypt(plainText: originalObject)
            let decryptedObject: TestObject = try cryptoService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedObject.property, originalObject.property)
        } catch {
            XCTFail("Encryption/Decryption failed: \(error)")
        }
    }
    
    /// Test encryption of a Codable object.
    func testEncryption() {
        struct TestObject: Codable {
            let property: String
        }
        let originalObject = TestObject(property: "test")
        
        do {
            let encryptedString = try cryptoService.encrypt(plainText: originalObject)
            XCTAssertNotNil(encryptedString)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }
    
    /// Test encryption and decryption of a particular Codable object.
    func testEncryptionForParticularCodableObject() {
        struct TestObject: Codable {
            let name: String
            let id: Int
        }
        let originalObject = TestObject(name: "John Doe", id: 12345)
        
        do {
            let encryptedString = try cryptoService.encrypt(plainText: originalObject)
            XCTAssertEqual(encryptedString, "IP9QaAoK8WBrY/dzq72c+FTv2hYGW3laRbDYTd2rMd0=")
            let decryptedObject: TestObject = try cryptoService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedObject.name, originalObject.name)
            XCTAssertEqual(decryptedObject.id, originalObject.id)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }
    
    /// Test encryption and decryption of an array of Codable objects with a single element.
    func testEncryptionForParticularArrayOfCodableObjectsWithSingeElements() {
        struct TestObject: Codable {
            let name: String
            let power: String
        }
        let originalObjects: [TestObject] = [
            TestObject(name: "Flash", power: "Speed")
            ]
        
        do {
            let encryptedString = try cryptoService.encryptArray(plainText: originalObjects)
            XCTAssertEqual(encryptedString, "dwUIEcvaqX5QeHt02RX1lbHDZG4bHQAbdZYl9TH3YwETNzGuw8RJZtV+OZ5VpLoc")
            let decryptedObjects: [TestObject] = try cryptoService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedObjects.count, originalObjects.count)
            XCTAssertEqual(decryptedObjects[0].name, originalObjects[0].name)
            XCTAssertEqual(decryptedObjects[0].power, originalObjects[0].power)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }
    
    /// Test encryption and decryption of an array of Codable objects with multiple elements.
    func testEncryptionForParticularArrayOfCodableObjectsWithMultipleElements() {
        struct TestObject: Codable {
            let name: String
            let power: String
        }
        let originalObjects: [TestObject] = [
            TestObject(name: "Arrow", power: "Archer"),
            TestObject(name: "Flash", power: "Speed")
        ]
        
        do {
            let encryptedString = try cryptoService.encryptArray(plainText: originalObjects)
            
            XCTAssertEqual(encryptedString, "zQ7LM4URw4bW5Vyljjf8DKNdfISIB7dd0nvNMsukbx1YAknK0bKSnrYoVtARQxkVszNtOadBgzdkEuqzkfpt5Lzpl21G46hmwpCF5laf7+0=")
            let decryptedObjects: [TestObject] = try cryptoService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedObjects.count, originalObjects.count)
            XCTAssertEqual(decryptedObjects[0].name, originalObjects[0].name)
            XCTAssertEqual(decryptedObjects[0].power, originalObjects[0].power)
            XCTAssertEqual(decryptedObjects[1].name, originalObjects[1].name)
            XCTAssertEqual(decryptedObjects[1].power, originalObjects[1].power)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }
    
    /// Test encryption and decryption of a primitive type string.
    func testEncryptionForPrimitiveTypeString() {
        let originalText = "Hello Gamers!!!"
        
        do {
            let encryptedString = try cryptoService.encrypt(plainText: originalText)
            XCTAssertEqual(encryptedString, "g3Rrp4j/T/Hz/FVKEkOpOay3IMwdLLwl5WpWejEo0F8=")
            let decryptedString: String = try cryptoService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedString, originalText)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }
}
