import { KeyStore, Signer } from '../../types/ExternalInterfaces';
import * as TezosTypes from '../../types/tezos/TezosChainTypes';
import * as TezosP2PMessageTypes from '../../types/tezos/TezosP2PMessageTypes';
export declare namespace TezosNodeWriter {
    function forgeOperations(branch: string, operations: TezosP2PMessageTypes.Operation[]): string;
    function forgeOperationsRemotely(server: string, branch: string, operations: TezosP2PMessageTypes.Operation[], chainid?: string): Promise<string>;
    function preapplyOperation(server: string, branch: string, protocol: string, operations: TezosP2PMessageTypes.Operation[], signedOpGroup: TezosTypes.SignedOperationGroup, chainid?: string): Promise<TezosTypes.AlphaOperationsWithMetadata[]>;
    function injectOperation(server: string, signedOpGroup: TezosTypes.SignedOperationGroup, chainid?: string): Promise<string>;
    function sendOperation(server: string, operations: TezosP2PMessageTypes.Operation[], signer: Signer, offset?: number): Promise<TezosTypes.OperationResult>;
    function queueOperation(server: string, operations: TezosP2PMessageTypes.Operation[], signer: Signer, keyStore: KeyStore, batchDelay?: number): void;
    function getQueueStatus(server: string, keyStore: KeyStore): any;
    function appendRevealOperation(server: string, publicKey: string, accountHash: string, accountOperationIndex: number, operations: TezosP2PMessageTypes.StackableOperation[]): Promise<(TezosP2PMessageTypes.Transaction | TezosP2PMessageTypes.Delegation | TezosP2PMessageTypes.Reveal)[]>;
    function sendTransactionOperation(server: string, signer: Signer, keyStore: KeyStore, to: string, amount: number, fee: number, offset?: number): Promise<TezosTypes.OperationResult>;
    function sendDelegationOperation(server: string, signer: Signer, keyStore: KeyStore, delegate: string | undefined, fee?: number, offset?: number, optimizeFee?: boolean): Promise<TezosTypes.OperationResult>;
    function sendUndelegationOperation(server: string, signer: Signer, keyStore: KeyStore, fee?: number, offset?: number): Promise<TezosTypes.OperationResult>;
    function sendContractOriginationOperation(server: string, signer: Signer, keyStore: KeyStore, amount: number, delegate: string | undefined, fee: number, storageLimit: number, gasLimit: number, code: string, storage: string, codeFormat?: TezosTypes.TezosParameterFormat, offset?: number, optimizeFee?: boolean): Promise<TezosTypes.OperationResult>;
    function constructContractOriginationOperation(keyStore: KeyStore, amount: number, delegate: string | undefined, fee: number, storageLimit: number, gasLimit: number, code: string, storage: string, codeFormat: TezosTypes.TezosParameterFormat, counter: number): TezosP2PMessageTypes.Origination;
    function sendContractInvocationOperation(server: string, signer: Signer, keyStore: KeyStore, contract: string, amount: number, fee: number, storageLimit: number, gasLimit: number, entrypoint: string | undefined, parameters: string | undefined, parameterFormat?: TezosTypes.TezosParameterFormat, offset?: number, optimizeFee?: boolean): Promise<TezosTypes.OperationResult>;
    function constructContractInvocationOperation(publicKeyHash: string, counter: number, to: string, amount: number, fee: number, storageLimit: number, gasLimit: number, entrypoint: string | undefined, parameters: string | undefined, parameterFormat?: TezosTypes.TezosParameterFormat): TezosP2PMessageTypes.Transaction;
    function sendContractPing(server: string, signer: Signer, keyStore: KeyStore, to: string, fee: number, storageLimit: number, gasLimit: number, entrypoint: string | undefined): Promise<TezosTypes.OperationResult>;
    function sendKeyRevealOperation(server: string, signer: Signer, keyStore: KeyStore, fee?: number, offset?: number): Promise<TezosTypes.OperationResult>;
    function sendIdentityActivationOperation(server: string, signer: Signer, keyStore: KeyStore, activationCode: string): Promise<TezosTypes.OperationResult>;
    function testContractInvocationOperation(server: string, chainid: string, keyStore: KeyStore, contract: string, amount: number, fee: number, storageLimit: number, gasLimit: number, entrypoint: string | undefined, parameters: string | undefined, parameterFormat?: TezosTypes.TezosParameterFormat): Promise<{
        gas: number;
        storageCost: number;
    }>;
    function testContractDeployOperation(server: string, chainid: string, keyStore: KeyStore, amount: number, delegate: string | undefined, fee: number, storageLimit: number, gasLimit: number, code: string, storage: string, codeFormat?: TezosTypes.TezosParameterFormat): Promise<{
        gas: number;
        storageCost: number;
    }>;
    function estimateOperation(server: string, chainid: string, ...operations: TezosP2PMessageTypes.Operation[]): Promise<{
        gas: number;
        storageCost: number;
        estimatedFee: number;
        estimatedStorageBurn: number;
    }>;
    function dryRunOperation(server: string, chainid: string, ...operations: TezosP2PMessageTypes.Operation[]): Promise<Response>;
    function parseRPCError(response: string): void;
}