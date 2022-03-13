# node configuration
export NODE_ENV='development'
export PORT=5004

# mongo connection string
export URL='mongodb://localhost:27017/magcentre'

# JWT
# JWT secret key
export JWT_SECRET='5avo57Ive6RawrejEspow0prO6risl'
# Number of minutes after which an access token expires
export JWT_ACCESS_EXPIRATION_MINUTES=120
# Number of days after which a refresh token expires
export JWT_REFRESH_EXPIRATION_DAYS=30
# Number of minutes after which a reset password token expires
export JWT_RESET_PASSWORD_EXPIRATION_MINUTES=10
# Number of minutes after which a verify email token expires
export JWT_VERIFY_EMAIL_EXPIRATION_MINUTES=10
# OTP expiry time for otp registration
export OTP_EXPIRY_TIME_MINUTES=1

export API_GATEWAY='http://localhost:4999'

/usr/local/bin/node src/index.js