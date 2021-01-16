"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const QueryTypes_1 = require("../../types/conseil/QueryTypes");
const LoggerSelector_1 = __importDefault(require("../../utils/LoggerSelector"));
const ConseilDataClient_1 = require("../ConseilDataClient");
const ConseilQueryBuilder_1 = require("../ConseilQueryBuilder");
const log = LoggerSelector_1.default.log;
var TezosConseilClient;
(function (TezosConseilClient) {
    const BLOCKS = 'blocks';
    const ACCOUNTS = 'accounts';
    const OPERATION_GROUPS = 'operation_groups';
    const OPERATIONS = 'operations';
    const FEES = 'fees';
    const PROPOSALS = 'proposals';
    const BAKERS = 'bakers';
    const BALLOTS = 'ballots';
    function getTezosEntityData(serverInfo, network, entity, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return ConseilDataClient_1.ConseilDataClient.executeEntityQuery(serverInfo, 'tezos', network, entity, query);
        });
    }
    TezosConseilClient.getTezosEntityData = getTezosEntityData;
    function getBlockHead(serverInfo, network) {
        return __awaiter(this, void 0, void 0, function* () {
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addOrdering(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'level', QueryTypes_1.ConseilSortDirection.DESC), 1);
            const r = yield getTezosEntityData(serverInfo, network, BLOCKS, query);
            return r[0];
        });
    }
    TezosConseilClient.getBlockHead = getBlockHead;
    function getBlock(serverInfo, network, hash) {
        return __awaiter(this, void 0, void 0, function* () {
            if (hash === 'head') {
                return getBlockHead(serverInfo, network);
            }
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'hash', QueryTypes_1.ConseilOperator.EQ, [hash], false), 1);
            const r = yield getTezosEntityData(serverInfo, network, BLOCKS, query);
            return r[0];
        });
    }
    TezosConseilClient.getBlock = getBlock;
    function getBlockByLevel(serverInfo, network, level) {
        return __awaiter(this, void 0, void 0, function* () {
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'level', QueryTypes_1.ConseilOperator.EQ, [level], false), 1);
            const r = yield getTezosEntityData(serverInfo, network, BLOCKS, query);
            return r[0];
        });
    }
    TezosConseilClient.getBlockByLevel = getBlockByLevel;
    function getAccount(serverInfo, network, accountID) {
        return __awaiter(this, void 0, void 0, function* () {
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'account_id', QueryTypes_1.ConseilOperator.EQ, [accountID], false), 1);
            const r = yield getTezosEntityData(serverInfo, network, ACCOUNTS, query);
            return r[0];
        });
    }
    TezosConseilClient.getAccount = getAccount;
    function getOperationGroup(serverInfo, network, operationGroupID) {
        return __awaiter(this, void 0, void 0, function* () {
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'hash', QueryTypes_1.ConseilOperator.EQ, [operationGroupID], false), 1);
            const r = yield getTezosEntityData(serverInfo, network, OPERATION_GROUPS, query);
            return r[0];
        });
    }
    TezosConseilClient.getOperationGroup = getOperationGroup;
    function getOperation(serverInfo, network, operationGroupID) {
        return __awaiter(this, void 0, void 0, function* () {
            const query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'operation_group_hash', QueryTypes_1.ConseilOperator.EQ, [operationGroupID], false), 1);
            const r = yield getTezosEntityData(serverInfo, network, OPERATIONS, query);
            return r[0];
        });
    }
    TezosConseilClient.getOperation = getOperation;
    function getBlocks(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, BLOCKS, query);
        });
    }
    TezosConseilClient.getBlocks = getBlocks;
    function getAccounts(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, ACCOUNTS, query);
        });
    }
    TezosConseilClient.getAccounts = getAccounts;
    function getOperationGroups(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, OPERATION_GROUPS, query);
        });
    }
    TezosConseilClient.getOperationGroups = getOperationGroups;
    function getOperations(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, OPERATIONS, query);
        });
    }
    TezosConseilClient.getOperations = getOperations;
    function getFeeStatistics(serverInfo, network, operationType) {
        return __awaiter(this, void 0, void 0, function* () {
            let query = ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery();
            query = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(query, 'kind', QueryTypes_1.ConseilOperator.EQ, [operationType]);
            query = ConseilQueryBuilder_1.ConseilQueryBuilder.addOrdering(query, 'timestamp', QueryTypes_1.ConseilSortDirection.DESC);
            query = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(query, 1);
            return getTezosEntityData(serverInfo, network, FEES, query);
        });
    }
    TezosConseilClient.getFeeStatistics = getFeeStatistics;
    function getProposals(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, PROPOSALS, query);
        });
    }
    TezosConseilClient.getProposals = getProposals;
    function getBakers(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, BAKERS, query);
        });
    }
    TezosConseilClient.getBakers = getBakers;
    function getBallots(serverInfo, network, query) {
        return __awaiter(this, void 0, void 0, function* () {
            return getTezosEntityData(serverInfo, network, BALLOTS, query);
        });
    }
    TezosConseilClient.getBallots = getBallots;
    function awaitOperationConfirmation(serverInfo, network, hash, duration, blocktime = 60) {
        return __awaiter(this, void 0, void 0, function* () {
            if (duration <= 0) {
                throw new Error('Invalid duration');
            }
            const initialLevel = (yield getBlockHead(serverInfo, network))['level'];
            const timeOffset = 180000;
            const startTime = (new Date).getTime() - timeOffset;
            const estimatedEndTime = startTime + timeOffset + duration * blocktime * 1000;
            log.debug(`TezosConseilClient.awaitOperationConfirmation looking for ${hash} since ${initialLevel} at ${(new Date(startTime).toUTCString())}, +${duration}`);
            let currentLevel = initialLevel;
            let operationQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery();
            operationQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(operationQuery, 'operation_group_hash', QueryTypes_1.ConseilOperator.EQ, [hash], false);
            operationQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(operationQuery, 'timestamp', QueryTypes_1.ConseilOperator.AFTER, [startTime], false);
            operationQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(operationQuery, 1);
            while (initialLevel + duration > currentLevel) {
                const group = yield getOperations(serverInfo, network, operationQuery);
                if (group.length > 0) {
                    return group[0];
                }
                currentLevel = (yield getBlockHead(serverInfo, network))['level'];
                if (initialLevel + duration < currentLevel) {
                    break;
                }
                if ((new Date).getTime() > estimatedEndTime) {
                    break;
                }
                yield new Promise(resolve => setTimeout(resolve, blocktime * 1000));
            }
            throw new Error(`Did not observe ${hash} on ${network} in ${duration} block${duration > 1 ? 's' : ''} since ${initialLevel}`);
        });
    }
    TezosConseilClient.awaitOperationConfirmation = awaitOperationConfirmation;
    function awaitOperationForkConfirmation(serverInfo, network, hash, duration, depth) {
        return __awaiter(this, void 0, void 0, function* () {
            const op = yield awaitOperationConfirmation(serverInfo, network, hash, duration);
            const initialLevel = op['block_level'];
            const initialHash = op['block_hash'];
            let currentLevel = initialLevel;
            yield new Promise(resolve => setTimeout(resolve, depth * 50 * 1000));
            while (currentLevel < initialLevel + depth) {
                const currentBlock = yield getBlockHead(serverInfo, network);
                currentLevel = currentBlock['level'];
                if (currentLevel >= initialLevel + depth) {
                    break;
                }
                yield new Promise(resolve => setTimeout(resolve, 60 * 1000));
            }
            let blockSequenceQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery();
            blockSequenceQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(blockSequenceQuery, 'level', 'hash', 'predecessor');
            blockSequenceQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(blockSequenceQuery, 'level', QueryTypes_1.ConseilOperator.BETWEEN, [initialLevel - 1, initialLevel + depth]);
            blockSequenceQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(blockSequenceQuery, depth * 2);
            const blockSequenceResult = yield getBlocks(serverInfo, network, blockSequenceQuery);
            if (blockSequenceResult.length === depth + 2) {
                return fastBlockContinuity(blockSequenceResult, initialLevel, initialHash);
            }
            else {
                return slowBlockContinuity(blockSequenceResult, initialLevel, initialHash, depth);
            }
        });
    }
    TezosConseilClient.awaitOperationForkConfirmation = awaitOperationForkConfirmation;
    function getBigMapData(serverInfo, contract) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!contract.startsWith('KT1')) {
                throw new Error('Invalid address');
            }
            const ownerQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'account_id', QueryTypes_1.ConseilOperator.EQ, [contract], false), 'big_map_id'), 100);
            const ownerResult = yield getTezosEntityData(serverInfo, serverInfo.network, 'originated_account_maps', ownerQuery);
            if (ownerResult.length < 1) {
                return undefined;
            }
            const definitionQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'big_map_id', (ownerResult.length > 1 ? QueryTypes_1.ConseilOperator.IN : QueryTypes_1.ConseilOperator.EQ), ownerResult.map(r => r.big_map_id), false), 100);
            const definitionResult = yield getTezosEntityData(serverInfo, serverInfo.network, 'big_maps', definitionQuery);
            const contentQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 'big_map_id', (ownerResult.length > 1 ? QueryTypes_1.ConseilOperator.IN : QueryTypes_1.ConseilOperator.EQ), ownerResult.map(r => r.big_map_id), false), 'big_map_id', 'key', 'value'), 1000);
            const contentResult = yield getTezosEntityData(serverInfo, serverInfo.network, 'big_map_contents', contentQuery);
            let maps = [];
            for (const d of definitionResult) {
                const definition = { index: Number(d['big_map_id']), key: d['key_type'], value: d['value_type'] };
                let content = [];
                for (const c of contentResult.filter(r => r['big_map_id'] === definition.index)) {
                    content.push({ key: JSON.stringify(c['key']), value: JSON.stringify(c['value']) });
                }
                maps.push({ definition, content });
            }
            return { contract, maps };
        });
    }
    TezosConseilClient.getBigMapData = getBigMapData;
    function getBigMapValueForKey(serverInfo, key, contract = '', mapIndex = -1) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!contract.startsWith('KT1')) {
                throw new Error('Invalid address');
            }
            if (key.length < 1) {
                throw new Error('Invalid key');
            }
            if (mapIndex < 0 && contract.length === 0) {
                throw new Error('One of contract or mapIndex must be specified');
            }
            if (mapIndex < 0 && contract.length > 0) {
                let ownerQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 1);
                ownerQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(ownerQuery, 'big_map_id');
                ownerQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(ownerQuery, 'account_id', QueryTypes_1.ConseilOperator.EQ, [contract], false);
                ownerQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addOrdering(ownerQuery, 'big_map_id', QueryTypes_1.ConseilSortDirection.DESC);
                const ownerResult = yield getTezosEntityData(serverInfo, serverInfo.network, 'originated_account_maps', ownerQuery);
                if (ownerResult.length < 1) {
                    throw new Error(`Could not find any maps for ${contract}`);
                }
                mapIndex = ownerResult[0];
            }
            let contentQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 1);
            contentQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(contentQuery, 'value');
            contentQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(contentQuery, 'key', QueryTypes_1.ConseilOperator.EQ, [key], false);
            contentQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(contentQuery, 'big_map_id', QueryTypes_1.ConseilOperator.EQ, [mapIndex], false);
            const contentResult = yield getTezosEntityData(serverInfo, serverInfo.network, 'big_map_contents', contentQuery);
            if (contentResult.length < 1) {
                throw new Error(`Could not a value for key ${key} in map ${mapIndex}`);
            }
            return contentResult[0];
        });
    }
    TezosConseilClient.getBigMapValueForKey = getBigMapValueForKey;
    function fastBlockContinuity(blocks, initialLevel, initialHash) {
        try {
            return blocks.sort((a, b) => parseInt(a['level']) - parseInt(b['level'])).reduce((a, c, i) => {
                if (!a) {
                    throw new Error('Block sequence mismatch');
                }
                if (i > 1) {
                    return c['predecessor'] === blocks[i - 1]['hash'];
                }
                if (i === 1) {
                    return a && c['level'] === initialLevel
                        && c['hash'] === initialHash
                        && c['predecessor'] === blocks[i - 1]['hash'];
                }
                if (i === 0) {
                    return true;
                }
            }, true);
        }
        catch (_a) {
            return false;
        }
    }
    function slowBlockContinuity(blocks, initialLevel, initialHash, depth) {
        throw new Error('Not implemented');
    }
    function getEntityQueryForId(id) {
        let q = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery(), 1);
        if (typeof id === 'number') {
            const n = Number(id);
            if (n < 0) {
                throw new Error('Invalid numeric id parameter');
            }
            return { entity: BLOCKS, query: ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(q, 'level', QueryTypes_1.ConseilOperator.EQ, [id], false) };
        }
        else if (typeof id === 'string') {
            const s = String(id);
            if (s.startsWith('tz1') || s.startsWith('tz2') || s.startsWith('tz3') || s.startsWith('KT1')) {
                return { entity: ACCOUNTS, query: ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(q, 'account_id', QueryTypes_1.ConseilOperator.EQ, [id], false) };
            }
            else if (s.startsWith('B')) {
                return { entity: BLOCKS, query: ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(q, 'hash', QueryTypes_1.ConseilOperator.EQ, [id], false) };
            }
            else if (s.startsWith('o')) {
                q = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(q, 1000);
                return { entity: OPERATIONS, query: ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(q, 'operation_group_hash', QueryTypes_1.ConseilOperator.EQ, [id], false) };
            }
        }
        throw new Error('Invalid id parameter');
    }
    TezosConseilClient.getEntityQueryForId = getEntityQueryForId;
    function countKeysInMap(serverInfo, mapIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            let countQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.blankQuery();
            countQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addFields(countQuery, 'key');
            countQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addPredicate(countQuery, 'big_map_id', QueryTypes_1.ConseilOperator.EQ, [mapIndex]);
            countQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.addAggregationFunction(countQuery, 'key', QueryTypes_1.ConseilFunction.count);
            countQuery = ConseilQueryBuilder_1.ConseilQueryBuilder.setLimit(countQuery, 1);
            const result = yield ConseilDataClient_1.ConseilDataClient.executeEntityQuery(serverInfo, 'tezos', serverInfo.network, 'operations', countQuery);
            console.log("RESULT", result);
            return -1;
        });
    }
    TezosConseilClient.countKeysInMap = countKeysInMap;
})(TezosConseilClient = exports.TezosConseilClient || (exports.TezosConseilClient = {}));
//# sourceMappingURL=TezosConseilClient.js.map