const AppError = require('../utility/appError');
const User = require('../model/user.schema');
const bcrypt = require('bcrypt');
const cloudinary = require('cloudinary');
const fs = require('fs');
const sendEmail = require('../utility/sendEmail');
const crypto = require('crypto');
const cookieOptions = {
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: true,
};

exports.home = (req, res) => {
  res.send('This is a Home Page');
};

//register
//----------------------
exports.register = async (req, res, next) => {
  const { fullName, email, password } = req.body;

  console.log(req.body);
  console.log(req.body.fullName);
  if (!fullName || !password || !email) {
    return next(new AppError('All Fields are required', 400));
  }

  const userExists = await User.findOne({ email });
  if (userExists) {
    return next(new AppError('Email already exists', 400));
  }
  const user = await User.create({
    fullName,
    email,
    password,
    avatar: {
      public_id: email,
      secure_url: 'https://res.cloudinary.com',
    },
  });
  if (!user) {
    return next(
      new AppError('User registration failed,please try again later', 400)
    );
  }

  //Todo: File Upload
  //--------------------------
  if (req.file) {
    console.log(`File is -> ${JSON.stringify(req.file)}`);
    try {
      const result = await cloudinary.v2.uploader.upload(req.file.path, {
        folder: 'lms',
        width: 250,
        height: 250,
        gravity: 'faces',
        crop: 'fill',
      });

      if (result) {
        console.log(result);
        user.avatar.public_id = result.public_id;
        user.avatar.secure_url = result.secure_url;
        console.log(user.avatar);
        //Remove file from local System/server
        // fs.rm(`../uploads/${req.file.filename}`);
        fs.rm(`uploads/${req.file.filename}`, (error) => {
          if (error) {
            console.log(error);
          }
        });
      }
    } catch (e) {
      return next(new AppError('File not uploaded', 500));
    }
  }

  await user.save();
  console.log('saved in database');
  user.password = undefined;

  //generating token
  const token = await user.generateJWTToken();
  res.cookie('token', cookieOptions);
  res.status(201).json({
    success: true,
    message: 'user registerd Successfully',
    user,
  });
};
exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new AppError('All fields are required', 400));
  }
  try {
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return next(new AppError('Email or password does not match !', 400));
    }
    const token = await user.generateJWTToken();
    user.password = undefined;
    res.cookie('token', token, cookieOptions);

    res.status(200).json({
      success: true,
      message: 'User logged in sucessfully',
      user,
    });
  } catch (err) {
    return next(new AppError(err.message, 500));
  }
};
exports.getProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    res.status(400).json({
      success: true,
      message: 'User Details',
      user,
    });
  } catch (err) {
    return next(new AppError(err, 400));
  }
};
exports.logout = (req, res) => {
  res.cookie('token', null, {
    secure: true,
    maxAge: 0,
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    message: 'User logged out successfully',
  });
};

//forgot Password
//----------------------

exports.forgotPassword = async (req, res, next) => {
  const { email } = req.body; //to validate
  if (!email) {
    return next(new AppError('Email is required', 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError('Email is not valid', 400));
  }

  const resetToken = await user.generePasswordRestToken();
  await user.save();
  const resetPasswordURL = `http://localhost:7000/api/v1/user/reset-password/${resetToken}`;
  const subject = 'Reset Password';
  const message = `${resetPasswordURL}`;
  try {
    await sendEmail(email, subject, message);
    res.status(200).json({
      success: true,
      message: `Reset Password Token has been sent to ur ${email}`,
    });
  } catch (err) {
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    return next(new AppError(err, 400));
  }
};

exports.resetPassword = async (req, res, next) => {
  console.log('I am called');
  const { resetToken } = req.params;
  const { password } = req.body;
  console.log(resetToken, password);
  const forgotPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  const user = await User.findOne({
    forgotPasswordToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) {
    return next(new AppError('Token is expired', 400));
  }

  user.password = password;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();

  res.status(200).json({
    success: true,
    message: 'Password Changed successfully',
  });
};

exports.changePassword = async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;
  const { id } = req.user;
  console.log(req.user);
  if (!oldPassword || !newPassword) {
    return next(new AppError('All Fields are required', 400));
  }
  const user = await User.findById(id).select('+password');
  if (!user) {
    return next(new AppError('User does not exists', 400));
  }
  const isPasswordExists = await user.comparePassword(oldPassword);
  if (!isPasswordExists) {
    return next(new AppError('Password does not match', 400));
  }
  user.password = newPassword;
  await user.save();
  res.status(200).json({
    success: true,
    message: 'password updated successfully',
  });
};

exports.updateUser = async (req, res, next) => {
  const { fullName } = req.body;
  const { id } = req.user.id;
  const user = await User.findById(id);
  if (!user) {
    return next(new AppError('User does not exists', 400));
  }
  if (req.fullName) {
    user.fullName = fullName;
  }
  if (req.file) {
    await cloudinary.v2.uploader.destroy(user.avatar.public_id);
    try {
      const result = await cloudinary.v2.uploader.upload(req.file.path, {
        folder: 'lms',
        width: 250,
        height: 250,
        gravity: 'faces',
        crop: 'fill',
      });

      if (result) {
        console.log(result);
        user.avatar.public_id = result.public_id;
        user.avatar.secure_url = result.secure_url;
        console.log(user.avatar);
        //Remove file from local System/server
      }
    } catch (e) {
      return next(new AppError('File not uploaded', 500));
    }
  }
  await user.save();
  res.status(200).json({
    success: true,
    message: 'user DEtails updated successfully',
  });
};
