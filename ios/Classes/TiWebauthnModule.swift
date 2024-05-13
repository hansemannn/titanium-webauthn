//
//  TiWebauthnModule.swift
//  titanium-webauthn
//
//  Created by Hans Knöchel
//  Copyright (c) 2024-present Hans Knöchel. All rights reserved.
//

import AuthenticationServices
import TitaniumKit

@objc(TiWebauthnModule)
class TiWebauthnModule: TiModule {
    
  func moduleGUID() -> String {
    return "db8ef0e6-e9e9-4795-9cf5-fea1dec9c463"
  }
  
  override func moduleId() -> String! {
    return "ti.webauthn"
  }
  
  @available(iOS 15.0, *)
  @objc(login:)
  func login(arguments: [Any]) {
    guard let params = arguments.first as? [String: Any] else { fatalError("Missing parameters") }

    guard let challengeString = params["challenge"] as? String else { fatalError("Missing parametwer \"challenge\"")}
    guard let relyingParty = params["relyingParty"] as? String else { fatalError("Missing parametwer \"relyingParty\"")}

    let challenge = challengeString.data(using: .utf8)!
    let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingParty)
    let platformKeyRequest = platformProvider.createCredentialAssertionRequest(challenge: challenge)
    let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest])
    
    authController.delegate = self
    
    if #available(iOS 16.0, *) {
      authController.performRequests(options: .preferImmediatelyAvailableCredentials)
    } else {
      authController.performRequests()
    }
  }
  
  @available(iOS 15.0, *)
  @objc(register:)
  func register(arguments: [Any]) {
    guard let params = arguments.first as? [String: Any] else { fatalError("Missing parameters") }
    
    guard let challengeString = params["challenge"] as? String else { fatalError("Missing parametwer \"challenge\"")}
    guard let userIDString = params["userId"] as? String else { fatalError("Missing parametwer \"userIDString\"")}
    guard let userName = params["userName"] as? String else { fatalError("Missing parametwer \"userName\"")}
    guard let relyingParty = params["relyingParty"] as? String else { fatalError("Missing parametwer \"relyingParty\"")}

    let challenge = challengeString.data(using: .utf8)!
    let userID = userIDString.data(using: .utf8)!
    let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingParty)
    let platformKeyRequest = platformProvider.createCredentialRegistrationRequest(challenge: challenge, name: userName, userID: userID)
    let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest])
    
    authController.delegate = self
    authController.performRequests()
  }
  
  private func base64ToBase64url(base64: String) -> String {
    let base64url = base64
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return base64url
}
}

// MARK: ASAuthorizationControllerDelegate

extension TiWebauthnModule: ASAuthorizationControllerDelegate {
  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    if #available(iOS 15.0, *) {
      if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
        var event: [String: Any] = [
          "type": "registration",
          "rawClientDataJSON": credential.rawClientDataJSON.jsonRepresentation ?? "",
          "credential": credential.credentialID.base64EncodedString(),
          "rawAttestationObject": base64ToBase64url(base64: credential.rawAttestationObject?.base64EncodedString() ?? ""),
        ]
        
        if #available(iOS 17.0, *) {
          event["authenticatorAttachment"] = credential.attachment.rawValue
        }
        
        fireEvent("verification", with: event)
      } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
        var event: [String: Any] = [
          "type": "assertion",
          "rawClientDataJSON": credential.rawClientDataJSON.jsonRepresentation ?? "",
          "credential": credential.credentialID.base64EncodedString(),
          "authenticatorData": credential.rawAuthenticatorData.base64EncodedString(),
          "userID": credential.userID.base64EncodedString(),
          "signature": credential.signature.base64EncodedString()
        ]
        
        if #available(iOS 17.0, *) {
          event["authenticatorAttachment"] = credential.attachment.rawValue
        }
        
        fireEvent("verification", with: event)
      } else {
        fireEvent("error", with: ["error": "Unhandled authentication case"])
      }
    }
  }
  
  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
    fireEvent("error", with: ["error": error.localizedDescription])
  }
}

extension Data {
    var jsonRepresentation: NSString? {
        guard let jsonObject = try? JSONSerialization.jsonObject(with: self, options: []),
              let data = try? JSONSerialization.data(withJSONObject: jsonObject,
                                                     options: [.fragmentsAllowed]),
              let json = NSString(data: data, encoding: String.Encoding.utf8.rawValue) else {
                return nil
             }

        return json
    }
}
