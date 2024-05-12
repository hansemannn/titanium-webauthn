//
//  TiWebauthnModule.swift
//  titanium-webauthn
//
//  Created by Hans Knöchel
//  Copyright (c) 2024-present Hans Knöchel. All rights reserved.
//

import TitaniumKit
import WebAuthn

@objc(TiWebauthnModule)
class TiWebauthnModule: TiModule {
  
  private var webauthnManager: WebAuthnManager!
  
  func moduleGUID() -> String {
    return "db8ef0e6-e9e9-4795-9cf5-fea1dec9c463"
  }
  
  override func moduleId() -> String! {
    return "ti.webauthn"
  }

  @objc(initialize:)
  func initialize(arguments: [Any]) {
    guard let params = arguments.first as? [String: Any] else { fatalError("Missing parameters") }
    
    guard let relyingPartyID = params["relyingPartyID"] as? String else { fatalError("Missing parameter relyingPartyID") }
    guard let relyingPartyName = params["relyingPartyName"] as? String else { fatalError("Missing parameter relyingPartyName") }
    guard let relyingPartyOrigin = params["relyingPartyOrigin"] as? String else { fatalError("Missing parameter relyingPartyOrigin") }
        
    webauthnManager = WebAuthnManager(config: WebAuthnManager.Config(
      relyingPartyID: relyingPartyID,
      relyingPartyName: relyingPartyName,
      relyingPartyOrigin: relyingPartyOrigin)
    )
  }
  
  @objc(beginAuthentication:)
  func beginAuthentication(arguments: [Any]) {
    guard let webauthnManager else { fatalError("Missing webauthnManager property" )}
    
    guard let params = arguments.first as? [String: Any] else { fatalError("Missing parameters") }
    guard let callback = params["callback"] as? KrollCallback else { fatalError("Missing parameter callback") }

    guard let result = try? webauthnManager.beginAuthentication() else {
      callback.call([["success": false, "error": "Challenge is not available" ]], thisObject: self)
      return
    }
        
    callback.call([[ "challenge": result.challenge.base64URLEncodedString().asString() ]], thisObject: self)
  }
  
  @objc(finishAuthentication:)
  func finishAuthentication(arguments: [Any]) {
    guard let webauthnManager else { fatalError("Missing webauthnManager property" )}
    
    guard let params = arguments.first as? [String: Any] else { fatalError("Missing parameters") }

    guard let credential = params["credential"] as? String else { fatalError("Missing parameter credential") }
    guard let expectedChallenge = params["expectedChallenge"] as? String else { fatalError("Missing parameter expectedChallenge") }
    guard let credentialPublicKey = params["credentialPublicKey"] as? String else { fatalError("Missing parameter credentialPublicKey") }
    guard let credentialCurrentSignCount = params["credentialCurrentSignCount"] as? String else { fatalError("Missing parameter credentialCurrentSignCount") }
    guard let callback = params["callback"] as? KrollCallback else { fatalError("Missing parameter callback") }

    let decoder = JSONDecoder()
    
    if let jsonData = credential.data(using: .utf8) {
        do {
          let authChallenge = try decoder.decode(AuthenticationCredential.self, from: jsonData)
          guard let result = try? webauthnManager.finishAuthentication(credential: authChallenge, expectedChallenge: expectedChallenge.encode(), credentialPublicKey: credentialPublicKey.encode(), credentialCurrentSignCount: 0) else {
            callback.call([["success": false, "error": "Credential is not available" ]], thisObject: self)
            return
          }
          
          callback.call([["success": true, "credentialID": result.credentialID.asString()]], thisObject: self)
        } catch {
          callback.call([["success": false, "error": error.localizedDescription]], thisObject: self)
        }
    }
  }
}
