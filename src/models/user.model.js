const { mongoose } = require('@magcentre/mongoose-helper');

const bcrypt = require('bcryptjs');

const userTypes = {
    USER: 'access',
    ADMIN: 'refresh'
};

const userSchema = mongoose.Schema(
    {
        firstName: {
            type: String,
            required: true,
            trim: true,
        },
        lastName: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            validate(value) {
                var e = String(value)
                    .toLowerCase()
                    .match(
                        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
                    );

                if (!e) {
                    throw { statuCode: 400, message: 'Invalid email' };
                }
            },
        },
        password: {
            type: String,
            required: true,
            trim: true,
            minlength: 8,
            validate(value) {
                if (!value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
                    throw { statuCode: 400, message: 'Password must contain at least one letter and one number' };
                }
            },
        },
        role: {
            type: String,
            enum: [userTypes.ADMIN, userTypes.USER],
            default: userTypes.USER,
        },
    },
    {
        timestamps: true,
        versionKey: false
    }
);


/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isEmailTaken = function (email, excludeUserId) {
    return this.findOne({ email, _id: { $ne: excludeUserId } });
};

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<Object>}
 */
userSchema.methods.isPasswordMatch = function (password) {
    const user = this;
    return new Promise((resolve, reject) => {
        bcrypt.compare(password, user.password, (err, isValid) => {
            if (err) return reject(err);
            return resolve({ match: isValid, ...user.toObject() });
        });
    });
};

userSchema.pre('save', async function (next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
});

/**
 * @typedef User
 */
const User = mongoose.model('Users', userSchema);

module.exports = {
    model: User,
    types: userTypes
};