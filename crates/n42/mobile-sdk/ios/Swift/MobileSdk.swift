import Foundation

public enum MobileSdkError: Error {
    case rustError(String)
}

public class MobileSdk {

    public static func runClient(wsUrl: String, validatorPrivateKey: String,
completion: @escaping (Result<Void, MobileSdkError>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            var errorPtr: UnsafeMutablePointer<CChar>? = nil
            let code = run_client_c(wsUrl, validatorPrivateKey, &errorPtr)
            defer { if let err = errorPtr { rust_free_string(err) } }

            if code == 0 {
                DispatchQueue.main.async { completion(.success(())) }
            } else {
                let msg = errorPtr.flatMap { String(cString: $0) } ?? "Unknown Rust error"
                DispatchQueue.main.async {
completion(.failure(.rustError(msg))) }
            }
        }
    }

    public static func createDepositUnsignedTx(
        depositContractAddress: String,
        validatorPrivateKey: String,
        withdrawalAddress: String,
        depositValueInWei: String
    ) -> Result<String, MobileSdkError> {
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        guard let jsonPtr = create_deposit_unsigned_tx_c(
            depositContractAddress,
            validatorPrivateKey,
            withdrawalAddress,
            depositValueInWei,
            &errorPtr
        ) else {
            defer { if let err = errorPtr { rust_free_string(err) } }
            let msg = errorPtr.flatMap { String(cString: $0) } ?? "Unknown Rust error"
            return .failure(.rustError(msg))
        }
        defer { rust_free_string(jsonPtr) }
        return .success(String(cString: jsonPtr))
    }

    public static func createExitUnsignedTx(
        validatorPublicKey: String,
        feeInWeiOrEmpty: String?
    ) -> Result<String, MobileSdkError> {
        var errorPtr: UnsafeMutablePointer<CChar>? = nil
        guard let jsonPtr = create_exit_unsigned_tx_c(
            validatorPublicKey,
            feeInWeiOrEmpty ?? "",
            &errorPtr
        ) else {
            defer { if let err = errorPtr { rust_free_string(err) } }
            let msg = errorPtr.flatMap { String(cString: $0) } ?? "Unknown Rust error"
            return .failure(.rustError(msg))
        }
        defer { rust_free_string(jsonPtr) }
        return .success(String(cString: jsonPtr))
    }
}
