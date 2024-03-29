//
//  RSACryptoServiceTest.swift
//  EncryptionLibraryTests
//
//  Created by Ayush Kumar Sinha on 29/03/24.
//

import XCTest

final class RSACryptoServiceTest: XCTestCase {
    let publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4TnAjys/drPWRhkHy63kHU0+xT/JF7pwv+qBdDphBqH/82FS9s/8KfDoxxHS3VycHEIw+1CR4/agtBstjEPGlc9ga+TbQJd6JTOEYpyGsDdtMuRmqysYOjGzx+OHgZIwUuSVjq1ltUC4sKjB9SJNhFpBpPy8vL9nXWHH3MmYqg8EDEIuMKv9pNx+Lgxt0mMfDToORH9oGTEQfPuwon9vqWp/ZCAE5cv64Senvi+VkRb5OKM8scpL5GzXMsCYYIgJzTA4UDtYuPT/pKUe0ZEjKYbRskCW81fpHZC5/noaaX/UutgERahqO7BFPVVQk2c3YjXkqR3ue2CWmNEzFZSTQIDAQAB-----END PUBLIC KEY-----"
    
    let privateKey = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEAz4TnAjys/drPWRhkHy63kHU0+xT/JF7pwv+qBdDphBqH/82FS9s/8KfDoxxHS3VycHEIw+1CR4/agtBstjEPGlc9ga+TbQJd6JTOEYpyGsDdtMuRmqysYOjGzx+OHgZIwUuSVjq1ltUC4sKjB9SJNhFpBpPy8vL9nXWHH3MmYqg8EDEIuMKv9pNx+Lgxt0mMfDToORH9oGTEQfPuwon9vqWp/ZCAE5cv64Senvi+VkRb5OKM8scpL5GzXMsCYYIgJzTA4UDtYuPT/pKUe0ZEjKYbRskCW81fpHZC5/noaaX/UutgERahqO7BFPVVQk2c3YjXkqR3ue2CWmNEzFZSTQIDAQABAoIBAQCuyANBcRVK4iZNpit9z/0voGg1KWQToBVG9cqgB2sGpsnw+4rPbySVbtdp5AFwXsU6SxnU21o9p72k/CLz+LH9v4jAV77Vy26I2/wL7g1Y1yRkiChknBa7sJLyFGPAig5xL1NbaStUlKhPkRt7FtlSPqu0rJutYFeXbUuXg4bLA94LV6HwVDqBFe7cJqdoCyhJ1fTQ3ybC7BbZfJbZUQAPJEMgOpDyz3z9LJ+bovYeBopOOr4AeDamZARgStQyNOiaetgD/8+0yuMr8vworMcuz2nLfsjKUmGpEUzdGnd/kWIDjFizAUjeNU05no2aO10uiPb/Rp5dIPrbmLtPp4TJAoGBAPc/YHqzF9varPTmoBoz2lpxb2SFC4VOh5lPqORxiPv0lxQVJd4a5RkR86I6pu8jKeana6gqctOI5kb25NqohVQprOGA9Gb654zHufhd4kgXlZIXv+Mp2cBD4tmgqyxSIOP3SYSM4fCkiWGd2bZLA5Z5aMx113bXfKzk4atYePiPAoGBANbdfvzUbl2deHXhsh3rcK2Um3b2vtqh7+V9811mN9kKXSilq4eAY0iqpHO0N8FM0AJ6QwN9Hv5+aPWhbMVnmO5QMsZm7o3l7ZqsUBbvl5QIi6GAGkCz/dNvXblMUc1c8chravZ3II31Fx3RHsv+7+euA8OTw26/QHYL54HfOh1jAoGAGc/6CJVN9lv8Fo1FRbcIIs0Y7gudyksKiQzx+veHb5Z3d1dF3sw8AsQHBXbOGsU3CKeN676SwlbWg64e8l0JnmHDdL97xIyJQ/9OAQn8J76elOP52oNyAkqUElhdxoDEgkg82qPCqtbiqNhL9GYcd8cxE7dxySxyDbLPhI32Ay0CgYEAoPMiYLmwQqfmyEbcadUnfp9HJYIHzTZowXvrhRdA1nARAJW5O7NMq+5HafShn0auumxjLoXXZcPDU9wr4mOMB1hD8KLCJ8EIj0hsZgHrhZQxJDUVdUpe5LcTee5ViIQLCZqNcTojRLNHMaqoax75Do8neqWBS8AvxT19madhnQkCgYBubSs5ZKCl0DfrGoPIZkzjz5FswIBO9YnZPkyiIMDeMWR/iCu02bypE5OJNPDx3d4bhYh5sXVXP+vIOrihV+Z/ZzlI5F8dKnQaukIUiD0oOiMDD9sz0r8YGgOlxf72jVcfzCutYH6B26Qb1prEzqM+8OC31UcTcIYFB2xEmHsrmQ==-----END RSA PRIVATE KEY-----"
    
    var rsaEncryptionService: RSAEncryptionService!
    var rsaDecryptionService: RSADecryptionService!
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        do {
            self.rsaEncryptionService = try RSAEncryptionService(publicKey: publicKey)
            self.rsaDecryptionService = try RSADecryptionService(privateKey: privateKey)
        } catch {
            XCTFail("Failed to initialize rsa CryptoService: \(error)")
        }
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        self.rsaDecryptionService = nil
        self.rsaEncryptionService = nil
    }

    /// Test encryption and decryption of a Codable object.
    func testEncryptionDecryption() {
        struct TestObject: Codable {
            let property: String
        }
        let originalObject = TestObject(property: "test")
        
        do {
            let encryptedString = try rsaEncryptionService.encrypt(plainText: originalObject)
            let decryptedObject: TestObject = try rsaDecryptionService.decrypt(cypherText: encryptedString)
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
            let encryptedString = try rsaEncryptionService.encrypt(plainText: originalObject)
            XCTAssertNotNil(encryptedString)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    } 
    
    func testEncryptionForPrimitiveTypeString() {
        let originalText = "Hello Gamers!!!"
        
        do {
            let encryptedString = try rsaEncryptionService.encrypt(plainText: originalText)
            let decryptedString: String = try rsaDecryptionService.decrypt(cypherText: encryptedString)
            XCTAssertEqual(decryptedString, originalText)
        } catch {
            XCTFail("Encryption failed: \(error)")
        }
    }

}
