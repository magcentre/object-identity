const DEFAULT_CONFIG_VERSION = 'v1.0.0';

module.exports = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 5004,
  database: {
    url: process.env.URL || 'mongodb://localhost:27017/magcentre',
  },
  jwt: {
    secret: process.env.JWT_SECRET || '5avo57Ive6RawrejEspow0prO6risl',
    accessExpirationMinutes: process.env.JWT_ACCESS_EXPIRATION_MINUTES || 30,
    refreshExpirationDays: process.env.JWT_REFRESH_EXPIRATION_DAYS || 30,
    otpExpiryTimeInMinutes: process.env.OTP_EXPIRY_TIME_MINUTES || 1,
  },
  minio: {
    accessKeyId: process.env.minio_accesskey,
    secretAccessKey: process.env.minio_secretkey,
    endpoint: process.env.minio_endpoint,
    bucket: process.env.minio_bucket,
    encryptionKey: process.env.minio_encryptionKey,
  },
};
