const bcrypt = require('bcrypt');
const jwt = require('../lib/jwt.js');
const User = require('../models/User');

const { SECRET } = require('../config/config.js');



exports.login = async (username, password) => {
    // find user by username
    const user = await User.findOne({ username });

    if (!user) {
        throw new Error('Invalid user or password!');
    }

    // check password

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
        throw new Error('Invalid user or password!');
    }

    const token = await generateToken(user);

    return token;

};

//exports.register = (userData) => User.create(userData);

exports.register = async (userData) => {

    const user = await User.findOne({ username: userData.username });

    if (user) {
        throw new Error('Username already exists!');
    }

    //return User.create(userData);

    const createdUser = await User.create(userData);

    const token = await generateToken(createdUser);

    return token;

};

async function generateToken(user) {

    const payload = {

        _id: user._id,
        username: user.username,
        email: user.email,

    }

    const token = await jwt.sign(payload, SECRET, { expiresIn: '2d' });

    return token;
}