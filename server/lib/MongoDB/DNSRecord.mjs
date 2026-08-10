import mongoose from 'mongoose';

export default new mongoose.Schema({
  hostname: {
    type: String,
    required: true,
    index: true,
    unique: true,
  },
  ipv4: {
    type: String,
    default: null,
  },
  ipv6: {
    type: String,
    default: null,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  collection: 'DNSRecord',
  versionKey: false,
});