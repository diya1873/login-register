const User = require('../models/userModel');
const generateToken = require('../config/jwt');
const bcrypt = require('bcryptjs');


exports.register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
     
        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

       
        const hashedPassword = await bcrypt.hash(password, 10);

       
        const user = await User.create({ username, email, password: hashedPassword });

        res.status(201).json({
            _id: user.id,
            username: user.username,
            email: user.email,
            token: generateToken(user.id)
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        res.json({
            _id: user.id,
            username: user.username,
            email: user.email,
            token: generateToken(user.id)
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};
