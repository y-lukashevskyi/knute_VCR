const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { Schema } = mongoose;


const userSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: [true],
        unique: [true]
    },
});

userSchema.pre('save', async function save(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        return next();
    }
    catch (err) {
        return next(err);
    }
});

userSchema.methods.comparePassword = function (candidatePassword, callback) {

    return bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {

        if (err) return callback(err);

        return callback(null, isMatch);

    });

};

const user = mongoose.model('User', userSchema);

module.exports = user;
