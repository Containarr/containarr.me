import debug from 'debug';
import mongoose from 'mongoose';

import DNSRecord from './MongoDB/DNSRecord.mjs';

import {
  PORT_HTTP,
} from '../config.mjs';

export default class MongoDB {

  debug = debug('MongoDB');
  #models = {};

  constructor() {
    this.connection = mongoose.createConnection(process.env.MONGO_URI)
    this.connection.asPromise()
      .then(() => {
        this.debug('Connected to MongoDB');
      }).catch(err => {
        this.debug(err);
        process.exit(1);
      });
  }

  async getModel(modelName, modelSchema) {
    const connection = await this.connection;

    if (!this.#models[modelName]) {
      this.#models[modelName] = connection.model(modelName, modelSchema);
    }

    return this.#models[modelName];
  }

  async getModelDNSRecord() {
    return this.getModel('DNSRecord', DNSRecord);
  }

}