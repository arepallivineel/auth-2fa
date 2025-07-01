import express from 'express';
import { register, login, enable2FA, resetPassword } from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/enable-2fa', authenticate, enable2FA);
router.post('/reset-password', resetPassword);
router.get('/profile', authenticate, (req, res) => {
  res.json({ user: req.user });
});

export default router;