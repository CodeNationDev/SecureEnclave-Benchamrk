//
//  ViewController.swift
//  SecureEnclavePunisher
//
//  Created by david.martin.saiz on 6/6/24.
//

import UIKit

class ViewController: UIViewController {

  
  @IBAction func generate100tapped(_ sender: Any) {
    generateKeypairs(amount: 100)
  }
  
  @IBAction func generate1000tapped(_ sender: Any) {
    generateKeypairs(amount: 1000)
  }
  
  @IBAction func wipeKeychainTapped(_ sender: Any) {
    debugAllKeychainItems(log: true, delete: true)
  }
  
  override func viewDidLoad() {
    super.viewDidLoad()
    
  }

  func generateKeypairs(amount: Int) {
    // Uso de la clase
    let manager = SecureEnclaveKeyManager()
    let generateTime = manager.generateKeyPairs(count: amount)
    let dataToSign = "Hello, Secure Enclave!".data(using: .utf8)!
    let signTime = manager.signDataWithAllKeys(data: dataToSign)
    
    print("GENERACIÓN DE CLAVES EC P256")
    print("============================")
    print("Tiempo promedio: \(generateTime.averageTime)")
    print("Tiempo total: \(generateTime.totalTime)")
    print("\n ----------------------- \n")
    print("FIRMA PKCS1")
    print("============================")
    print("Tiempo promedio: \(signTime.averageTime)")
    print("Tiempo total: \(signTime.totalTime)")
    
    
  }
  
  func debugAllKeychainItems(log: Bool = true, delete: Bool = true) {
    
    let secItemClasses = [
      kSecClassGenericPassword,
      kSecClassInternetPassword,
      kSecClassCertificate,
      kSecClassKey,
      kSecClassIdentity
    ]
    
    if log {
      
      for secItemClass in secItemClasses {
        
        let query = [
          kSecReturnAttributes: true,
          kSecMatchLimit: kSecMatchLimitAll,
          kSecClass: secItemClass
        ] as CFDictionary
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query, &result)
        
        if status == errSecSuccess {
          print(result as Any)
        }
      }
    }
    
    if delete {
      for secItemClass in secItemClasses {
        let query = [
          kSecClass: secItemClass
        ] as CFDictionary
        SecItemDelete(query)
      }
    }
  }
}

