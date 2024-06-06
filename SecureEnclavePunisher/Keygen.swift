import Foundation
import CryptoKit
import Security

class SecureEnclaveKeyManager {
  
  func generateKeyPairs(count: Int) -> (totalTime: TimeInterval, averageTime: TimeInterval) {
    var totalTime: TimeInterval = 0
    var individualTimes: [TimeInterval] = []
    
    for _ in 0..<count {
      let startTime = Date()
      generateKeyPair()
      let endTime = Date()
      let timeInterval = endTime.timeIntervalSince(startTime)
      totalTime += timeInterval
      individualTimes.append(timeInterval)
    }
    
    let averageTime = totalTime / Double(count)
//    print("Total time for generating keys: \(totalTime) seconds")
//    print("Average time per key: \(averageTime) seconds")
//    for (index, time) in individualTimes.enumerated() {
//      print("Time for key \(index + 1): \(time) seconds")
//    }
    
    return (totalTime, averageTime)
  }
  
  private func generateKeyPair() {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: "com.example.keys.mykey".data(using: .utf8)!
      ]
    ]
    
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      let error = error!.takeRetainedValue() as Error
      print("Error generating key pair: \(error.localizedDescription)")
      return
    }
    
    let publicKey = SecKeyCopyPublicKey(privateKey)
    print("Generated key pair with public key: \(publicKey!)")
  }
  
  func signDataWithAllKeys(data: Data) -> (totalTime: TimeInterval, averageTime: TimeInterval) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrApplicationTag as String: "com.example.keys.mykey".data(using: .utf8)!,
      kSecReturnRef as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var items: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &items)
    
    guard status == errSecSuccess, let keys = items as? [SecKey] else {
      print("Error retrieving keys: \(status)")
      return (0, 0)
    }
    
    var totalTime: TimeInterval = 0
    var individualTimes: [TimeInterval] = []
    
    for (index, key) in keys.enumerated() {
      let startTime = Date()
      let signature = signData(data: data, with: key)
      let endTime = Date()
      let timeInterval = endTime.timeIntervalSince(startTime)
      totalTime += timeInterval
      individualTimes.append(timeInterval)
      print("Signed data with key \(index + 1): \(signature?.base64EncodedString() ?? "N/A")")
    }
    
    let averageTime = totalTime / Double(keys.count)
//    print("Total time for signing data: \(totalTime) seconds")
//    print("Average time per signature: \(averageTime) seconds")
//    for (index, time) in individualTimes.enumerated() {
//      print("Time for signature \(index + 1): \(time) seconds")
//    }
    
    return (totalTime, averageTime)
  }
  
  private func signData(data: Data, with key: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key,
                                                .ecdsaSignatureMessageX962SHA256,
                                                data as CFData,
                                                &error) else {
      let error = error!.takeRetainedValue() as Error
      print("Error signing data: \(error.localizedDescription)")
      return nil
    }
    
    return signature as Data
  }
  
  func generateKeysAndSignData(keyCount: Int, data: Data) {
    let (keyGenTotalTime, keyGenAverageTime) = generateKeyPairs(count: keyCount)
    let (signTotalTime, signAverageTime) = signDataWithAllKeys(data: data)
    
    let totalTime = keyGenTotalTime + signTotalTime
    let averageTime = (keyGenAverageTime + signAverageTime) / 2
    
    print("Total time for key generation and signing: \(totalTime) seconds")
    print("Average time for key generation and signing: \(averageTime) seconds")
  }
}
