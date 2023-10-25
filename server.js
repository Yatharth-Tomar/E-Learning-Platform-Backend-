require('dotenv').config();
const connectdb = require('./config/connectdb');
const cloudinary = require('cloudinary');
connectdb();
const razorpay = require('razorpay');
const app = require('./app');
const Razorpay = require('razorpay');
const PORT = process.env.PORT || 5000;

//clodinary configuration
cloudinary.v2.config({
  cloud_name: 'dedllx1um',
  api_key: '331841568775566',
  api_secret: '3oY2Qm0AJfzxdcen86ciWcr-S3Y',
});
console.log();
exports.razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});
app.listen(PORT, () => {
  console.log(`Server running at port ${PORT}`);
});
