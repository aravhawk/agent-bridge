import { CONFIG } from './config.ts';

export const VERSION = '1.0.0';
export const SERVICE_NAME = CONFIG.serviceName;
export const SERVER_NAME = CONFIG.serverName;
export const PUBLIC_ORIGIN = CONFIG.origin;
export const RECEIVER_ID = CONFIG.receiverId;
export const QUEUE_TOPIC = CONFIG.queueTopic;
export const QUEUE_REGION = CONFIG.queueRegion;
export const STATE_TABLE = 'bridge_runtime_v1';
