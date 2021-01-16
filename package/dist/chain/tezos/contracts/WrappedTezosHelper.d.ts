import { KeyStore, Signer } from '../../../types/ExternalInterfaces';
import { ConseilServerInfo } from '../../../types/conseil/QueryTypes';
export declare type OpenOvenResult = {
    operationHash: string;
    ovenAddress: string;
};
export interface WrappedTezosStorage {
    balanceMap: number;
    approvalsMap: number;
    supply: number;
    administrator: string;
    paused: boolean;
    pauseGuardian: string;
    outcomeMap: number;
    swapMap: number;
}
export interface WrappedTezosBalanceRecord {
}
export interface WrappedTezosApprovalRecord {
}
export interface WrappedTezosOutcomeRecord {
}
export interface WrappedTezosSwapRecord {
}
export declare type OvenMapSchema = {
    key: string;
    value: string;
};
export declare namespace WrappedTezosHelper {
    function verifyDestination(nodeUrl: string, tokenContractAddress: string, ovenContractAddress: string, coreContractAddress: string): Promise<boolean>;
    function verifyScript(tokenScript: string, ovenScript: string, coreScript: string): boolean;
    function getSimpleStorage(server: string, address: string): Promise<WrappedTezosStorage>;
    function getAccountBalance(server: string, mapid: number, account: string): Promise<number>;
    function transferBalance(nodeUrl: string, signer: Signer, keystore: KeyStore, tokenContractAddress: string, fee: number, sourceAddress: string, destinationAddress: string, amount: number, gasLimit?: number, storageLimit?: number): Promise<string>;
    function depositToOven(nodeUrl: string, signer: Signer, keystore: KeyStore, ovenAddress: string, fee: number, amountMutez: number, gasLimit?: number, storageLimit?: number): Promise<string>;
    function withdrawFromOven(nodeUrl: string, signer: Signer, keystore: KeyStore, ovenAddress: string, fee: number, amountMutez: number, gasLimit?: number, storageLimit?: number): Promise<string>;
    function listOvens(serverInfo: ConseilServerInfo, coreContractAddress: string, ovenOwner: string, ovenListBigMapId: number): Promise<Array<string>>;
    function deployOven(nodeUrl: string, signer: Signer, keystore: KeyStore, fee: number, coreAddress: string, baker?: string | undefined, gasLimit?: number, storageLimit?: number): Promise<OpenOvenResult>;
    function setOvenBaker(nodeUrl: string, signer: Signer, keystore: KeyStore, fee: number, ovenAddress: string, bakerAddress: string, gasLimit?: number, storageLimit?: number): Promise<string>;
    function clearOvenBaker(nodeUrl: string, signer: Signer, keystore: KeyStore, fee: number, ovenAddress: string, gasLimit?: number, storageLimit?: number): Promise<string>;
    function getStatistics(tezosNode: string, conseilServer: ConseilServerInfo, address: string): Promise<any>;
}