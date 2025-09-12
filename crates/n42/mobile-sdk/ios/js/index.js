import { NativeModules } from 'react-native';
const { MobileSdkModule } = NativeModules;

export const runClient = (wsUrl, validatorKey) =>
    MobileSdkModule.runClient(wsUrl, validatorKey);

export const createDepositUnsignedTx = (contractAddr, privKey, withdrawal, value) =>
    MobileSdkModule.createDepositUnsignedTx(contractAddr, privKey, withdrawal, value);

export const createExitUnsignedTx = (pubKey, fee) =>
    MobileSdkModule.createExitUnsignedTx(pubKey, fee);

