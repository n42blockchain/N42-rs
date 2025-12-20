import Foundation
import React

@objc(MobileSdkModule)
class MobileSdkModule: NSObject {

    @objc
    static func requiresMainQueueSetup() -> Bool { false }

    @objc
    func runClient(_ wsUrl: String, validatorKey: String, resolver: @escaping
RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
        MobileSdk.runClient(wsUrl: wsUrl, validatorPrivateKey: validatorKey) {
result in
            switch result {
            case .success:
                resolver(nil)
            case .failure(let error):
                rejecter("RUST_ERROR", "\(error)", nil)
            }
        }
    }

    @objc
    func generateBls12381Keypair(_ resolver: @escaping RCTPromiseResolveBlock,
                              rejecter: @escaping RCTPromiseRejectBlock) {
        let result = MobileSdk.generateBls12381Keypair()
        switch result {
        case .success(let json):
            resolver(json)
        case .failure(let error):
            rejecter("RUST_ERROR", "\(error)", nil)
        }
    }

    @objc
    func createDepositUnsignedTx(_ depositContractAddress: String,
                                 validatorPrivateKey: String,
                                 withdrawalAddress: String,
                                 depositValueInWei: String,
                                 resolver: @escaping RCTPromiseResolveBlock,
                                 rejecter: @escaping RCTPromiseRejectBlock) {
        let result = MobileSdk.createDepositUnsignedTx(
            depositContractAddress: depositContractAddress,
            validatorPrivateKey: validatorPrivateKey,
            withdrawalAddress: withdrawalAddress,
            depositValueInWei: depositValueInWei
        )
        switch result {
        case .success(let json):
            resolver(json)
        case .failure(let error):
            rejecter("RUST_ERROR", "\(error)", nil)
        }
    }

    @objc
    func createGetExitFeeUnsignedTx(_ resolver: @escaping RCTPromiseResolveBlock,
                              rejecter: @escaping RCTPromiseRejectBlock) {
        let result = MobileSdk.createGetExitFeeUnsignedTx()
        switch result {
        case .success(let json):
            resolver(json)
        case .failure(let error):
            rejecter("RUST_ERROR", "\(error)", nil)
        }
    }

    @objc
    func createExitUnsignedTx(_ validatorPublicKey: String,
                              feeInWeiOrEmpty: String?,
                              resolver: @escaping RCTPromiseResolveBlock,
                              rejecter: @escaping RCTPromiseRejectBlock) {
        let result = MobileSdk.createExitUnsignedTx(
            validatorPublicKey: validatorPublicKey,
            feeInWeiOrEmpty: feeInWeiOrEmpty
        )
        switch result {
        case .success(let json):
            resolver(json)
        case .failure(let error):
            rejecter("RUST_ERROR", "\(error)", nil)
        }
    }
}
