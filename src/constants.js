module.exports = {
  createBucket: '/container/bucket/create',
  sendOTP: '/notification/send-sms',
  bucketExists: '/container/bucket/exists',
  otpTemplate: (otp, expiry) => `Your One Time Password(OTP) is ${otp}. It is valid for ${expiry} mins. Don't share this with anyone.`,
};
