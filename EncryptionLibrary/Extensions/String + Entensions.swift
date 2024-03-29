//
//  String + Entensions.swift
//  EncryptionLibrary
//
//  Created by Ayush Kumar Sinha on 28/03/24.
//

import Foundation

extension String {
    func substring(from startIndex: Int, to endIndex: Int? = nil) -> String? {
        guard startIndex >= 0 && startIndex < self.count else {
            return nil
        }
        
        let endIndex = endIndex ?? self.count
        
        guard endIndex >= 0 && endIndex <= self.count && endIndex >= startIndex else {
            return nil
        }
        
        let start = self.index(self.startIndex, offsetBy: startIndex)
        let end = self.index(self.startIndex, offsetBy: endIndex)
        return String(self[start..<end])
    }
}
