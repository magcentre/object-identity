module.exports = {
  createBucket: '/container/bucket/create',
  sendOTP: '/notification/send-sms',
  otpTemplate: (otp) => `Your One Time Password(OTP) is ${otp}. Don't share this with anyone.`,
};
